# SPDX-License-Identifier: MIT
"""Frame sources (real V4L2 camera, scripted fake) and the exclusive broker."""
from __future__ import annotations

import logging
import shlex
import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Callable, Iterator, Protocol

import numpy as np

log = logging.getLogger(__name__)


class CameraError(Exception):
    pass


class CameraBusy(CameraError):
    pass


class FrameSource(Protocol):
    camera_class: str
    name: str

    def open(self) -> None: ...
    def read(self) -> np.ndarray | None: ...
    def close(self) -> None: ...


def run_hook(command: str, what: str) -> None:
    """Run the optional IR-emitter command from the (root-owned) config."""
    if not command.strip():
        return
    try:
        res = subprocess.run(shlex.split(command), timeout=5, check=False, shell=False,
                             stdin=subprocess.DEVNULL, capture_output=True)
        if res.returncode:
            log.warning("%s command exited with %s", what, res.returncode)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        log.warning("%s command failed: %s", what, exc)


def to_bgr(frame: np.ndarray) -> np.ndarray:
    """Frames are exchanged as BGR uint8 (H, W, 3); IR/grey frames are replicated."""
    import cv2
    if frame.dtype != np.uint8:
        frame = cv2.normalize(frame, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    if frame.ndim == 2:
        return cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR)
    if frame.shape[2] == 1:
        return cv2.cvtColor(frame[:, :, 0], cv2.COLOR_GRAY2BGR)
    if frame.shape[2] == 4:
        return cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
    return frame


class OpenCVCamera:
    """A /dev/videoN node read through OpenCV's V4L2 backend."""

    def __init__(self, path: str, name: str, camera_class: str, width: int = 640,
                 height: int = 480, warmup: int = 3, emitter_start: str = "",
                 emitter_stop: str = "") -> None:
        self.path, self.name, self.camera_class = path, name, camera_class
        self.width, self.height, self.warmup = width, height, warmup
        self.emitter_start, self.emitter_stop = emitter_start, emitter_stop
        self._cap = None
        self._emitter_on = False

    def open(self) -> None:
        import cv2
        if self.camera_class == "ir":
            run_hook(self.emitter_start, "IR emitter start")
            self._emitter_on = True
        cap = cv2.VideoCapture(self.path, cv2.CAP_V4L2)
        if not cap.isOpened():
            cap.release()
            self._stop_emitter()
            raise CameraError(f"cannot open {self.path}")
        if self.camera_class == "rgb":
            cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, self.width)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        self._cap = cap
        for _ in range(self.warmup):   # auto-exposure needs a few frames
            cap.read()

    def read(self) -> np.ndarray | None:
        if self._cap is None:
            return None
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return None
        return to_bgr(frame)

    def close(self) -> None:
        if self._cap is not None:
            self._cap.release()
            self._cap = None
        self._stop_emitter()

    def _stop_emitter(self) -> None:
        if self._emitter_on:
            run_hook(self.emitter_stop, "IR emitter stop")
            self._emitter_on = False


class FakeCamera:
    """Plays a list of frames in a loop (tests, demos without hardware).

    Only reachable through ``facial-authd --dev``: a scripted camera in
    production would defeat the whole point of the check.
    """

    def __init__(self, frames: list[np.ndarray] | Callable[[int], np.ndarray | None],
                 camera_class: str = "rgb", fps: float = 30.0, name: str = "fake camera") -> None:
        self._frames, self.camera_class, self.name = frames, camera_class, name
        self._period = 1.0 / fps
        self._i = 0
        self.opened = False
        self.closed = False

    def open(self) -> None:
        self.opened = True

    def read(self) -> np.ndarray | None:
        time.sleep(self._period)
        i, self._i = self._i, self._i + 1
        if callable(self._frames):
            return self._frames(i)
        return self._frames[i % len(self._frames)] if self._frames else None

    def close(self) -> None:
        self.closed = True


class CameraBroker:
    """One consumer of the camera at a time (scan, preview, test)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner = ""

    @property
    def owner(self) -> str:
        return self._owner if self._lock.locked() else ""

    def hold(self, factory: Callable[[], FrameSource], who: str, wait: float = 1.5) -> FrameSource:
        """Open the camera and keep it until ``release`` (preview sessions)."""
        if not self._lock.acquire(timeout=wait):
            raise CameraBusy(f"camera in use by {self._owner}")
        self._owner = who
        try:
            cam = factory()
            cam.open()
            return cam
        except BaseException:
            self._owner = ""
            self._lock.release()
            raise

    def release(self, cam: FrameSource) -> None:
        try:
            cam.close()
        except Exception:  # noqa: BLE001
            log.exception("closing the camera failed")
        finally:
            self._owner = ""
            self._lock.release()

    @contextmanager
    def use(self, factory: Callable[[], FrameSource], who: str,
            wait: float = 1.5) -> Iterator[FrameSource]:
        # A cancelled scan may still be releasing the device: wait a moment.
        if not self._lock.acquire(timeout=wait):
            raise CameraBusy(f"camera in use by {self._owner}")
        self._owner = who
        cam = None
        try:
            cam = factory()
            cam.open()
            yield cam
        finally:
            if cam is not None:
                try:
                    cam.close()
                except Exception:  # noqa: BLE001
                    log.exception("closing the camera failed")
            self._owner = ""
            self._lock.release()
