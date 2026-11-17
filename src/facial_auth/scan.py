# SPDX-License-Identifier: MIT
"""Verification loop (authentication) and enrollment helpers."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable

import numpy as np

from . import liveness
from .camera import FrameSource
from .config import Config
from .engine import Face, FaceEngine
from .store import normalise

log = logging.getLogger(__name__)

MIN_ENROLL_IMAGES = 3
MAX_ENROLL_IMAGES = 12
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_SIDE = 1280
# A face this much smaller than the main one is a bystander, otherwise the
# frame is ambiguous (two people at the camera) and is not used.
AMBIGUITY_RATIO = 0.5
# Enrollment photos must look like the same person.
CONSISTENCY_MIN_SIMILARITY = 0.35


@dataclass
class ScanResult:
    ok: bool
    reason: str = ""            # protocol FAIL reason when not ok
    score: float = 0.0
    frames: int = 0
    seen_face: bool = False
    duration: float = 0.0


class Scanner:
    def __init__(self, engine: FaceEngine, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.engine, self._clock, self._sleep = engine, clock, sleep

    def verify(self, cfg: Config, camera: FrameSource, templates: np.ndarray,
               others: np.ndarray | None, timeout: float, no_face_timeout: float | None = None,
               cancelled: Callable[[], bool] = lambda: False,
               progress: Callable[[str], None] | None = None) -> ScanResult:
        """Look for the face described by ``templates`` until ``timeout``.

        ``others`` holds the templates of every *other* enrolled account: the
        probe must beat them by ``impostor_margin`` so that look-alikes
        (siblings) do not unlock each other's session.
        """
        threshold = cfg["recognition", "threshold"]
        required = cfg["recognition", "required_matches"]
        margin = cfg["recognition", "impostor_margin"]
        min_px = cfg["recognition", "min_face_px"]
        period = 1.0 / cfg["recognition", "max_fps"]
        dark = cfg["camera", "dark_threshold"]
        live_mode = cfg["liveness", "mode"]

        start = self._clock()
        deadline = start + timeout
        res = ScanResult(ok=False)
        streak: list[float] = []
        hashes: list[bytes] = []
        read_failures = 0
        told_face = False

        def finish(ok: bool, reason: str = "", score: float = 0.0) -> ScanResult:
            res.ok, res.reason, res.score = ok, reason, score
            res.duration = self._clock() - start
            return res

        while True:
            t0 = self._clock()
            if cancelled():
                return finish(False, "cancelled")
            if t0 >= deadline:
                break
            if no_face_timeout is not None and not res.seen_face and t0 - start >= no_face_timeout:
                return finish(False, "no-face")
            frame = camera.read()
            if frame is None:
                read_failures += 1
                if read_failures > 30:
                    return finish(False, "camera-error")
                self._sleep(0.03)
                continue
            read_failures = 0
            res.frames += 1
            if float(frame.mean()) < dark:        # lens covered / emitter still off
                streak.clear()
                hashes.clear()
                self._pace(t0, period)
                continue

            faces = self.engine.detect(frame)
            face = self._main_face(faces)
            if face is None:
                streak.clear()
                hashes.clear()
                self._pace(t0, period)
                continue
            res.seen_face = True
            if progress and not told_face:
                progress("face")
                told_face = True
            if face.size < min_px:                # too far away for a reliable match
                streak.clear()
                hashes.clear()
                self._pace(t0, period)
                continue

            vec = self.engine.embed(frame, face)
            score = float((templates @ vec).max())
            rival = float((others @ vec).max()) if others is not None and len(others) else -1.0
            if score >= threshold and score >= rival + margin:
                streak.append(score)
                hashes.append(liveness.frame_hash(frame))
            else:
                streak.clear()
                hashes.clear()
            if len(streak) >= required:
                live, why = liveness.check(hashes, live_mode)
                if not live:
                    log.warning("presentation attack suspected (%s)", why)
                    return finish(False, "spoof")
                return finish(True, "", float(np.mean(streak)))
            self._pace(t0, period)

        return finish(False, "mismatch" if res.seen_face else "no-face")

    @staticmethod
    def _main_face(faces: list[Face]) -> Face | None:
        if not faces:
            return None
        if len(faces) > 1 and faces[1].area > AMBIGUITY_RATIO * faces[0].area:
            return None
        return faces[0]

    def _pace(self, t0: float, period: float) -> None:
        left = period - (self._clock() - t0)
        if left > 0:
            self._sleep(left)


# ---------------------------------------------------------------- enrollment
class EnrollError(Exception):
    """``code`` is machine readable, ``details`` maps image index -> problem."""

    def __init__(self, code: str, message: str, details: dict[int, str] | None = None) -> None:
        super().__init__(message)
        self.code, self.details = code, details or {}


def decode_image(data: bytes, max_side: int = MAX_IMAGE_SIDE) -> np.ndarray:
    import cv2
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise ValueError("image missing or larger than 8 MiB")
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("not a readable image")
    h, w = img.shape[:2]
    if max(h, w) > max_side:
        scale = max_side / max(h, w)
        img = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    return img


def encode_jpeg(frame: np.ndarray, quality: int = 80, max_side: int | None = None) -> bytes:
    import cv2
    if max_side and max(frame.shape[:2]) > max_side:
        scale = max_side / max(frame.shape[:2])
        frame = cv2.resize(frame, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    ok, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        raise ValueError("cannot encode image")
    return buf.tobytes()


@dataclass
class Analysis:
    ok: bool = False
    faces: int = 0
    hints: list[str] = field(default_factory=list)
    box: tuple[int, int, int, int] | None = None
    size: int = 0
    brightness: float = 0.0
    sharpness: float = 0.0
    landmarks: list[tuple[int, int]] = field(default_factory=list)

    def public(self) -> dict:
        return {"ok": self.ok, "faces": self.faces, "hints": list(self.hints),
                "box": list(self.box) if self.box else [], "size": self.size,
                "brightness": round(self.brightness, 1), "sharpness": round(self.sharpness, 1),
                "landmarks": [list(p) for p in self.landmarks]}


def analyze(engine: FaceEngine, frame: np.ndarray, min_face_px: int) -> Analysis:
    """Quality feedback for the capture UI (live preview and imported photos)."""
    import cv2
    out = Analysis()
    faces = engine.detect(frame)
    out.faces = len(faces)
    if not faces:
        out.hints = ["no-face"]
        return out
    face = faces[0]
    x, y, w, h = (int(round(v)) for v in face.box)
    out.box, out.size = (x, y, w, h), min(w, h)
    out.landmarks = [(int(px), int(py)) for px, py in face.landmarks]
    if len(faces) > 1 and faces[1].area > AMBIGUITY_RATIO * face.area:
        out.hints.append("multiple-faces")
    if out.size < min_face_px:
        out.hints.append("too-small")
    crop = frame[max(y, 0):y + h, max(x, 0):x + w]
    if crop.size:
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
        out.brightness = float(gray.mean())
        out.sharpness = float(cv2.Laplacian(cv2.resize(gray, (112, 112)), cv2.CV_64F).var())
        if out.brightness < 40:
            out.hints.append("too-dark")
        elif out.brightness > 225:
            out.hints.append("too-bright")
        if out.sharpness < 15:
            out.hints.append("blurry")
    out.ok = not ({"multiple-faces", "too-small"} & set(out.hints))
    return out


def embed_images(engine: FaceEngine, frames: list[np.ndarray], min_face_px: int) -> list[np.ndarray]:
    """Embeddings of an enrollment set, or EnrollError explaining what is wrong."""
    if len(frames) > MAX_ENROLL_IMAGES:
        raise EnrollError("too-many-images", f"at most {MAX_ENROLL_IMAGES} images")
    vectors: list[np.ndarray] = []
    kept_idx: list[int] = []
    problems: dict[int, str] = {}
    for i, frame in enumerate(frames):
        faces = engine.detect(frame)
        if not faces:
            problems[i] = "no-face"
        elif len(faces) > 1 and faces[1].area > AMBIGUITY_RATIO * faces[0].area:
            problems[i] = "multiple-faces"
        elif faces[0].size < min_face_px:
            problems[i] = "too-small"
        else:
            vectors.append(engine.embed(frame, faces[0]))
            kept_idx.append(i)
    if len(vectors) < MIN_ENROLL_IMAGES:
        raise EnrollError("not-enough-faces",
                          f"{len(vectors)} usable photo(s), at least {MIN_ENROLL_IMAGES} needed",
                          problems)
    # A sample belongs to the set if it resembles most of the *other* samples
    # (median of the pairwise cosine similarities): this also catches a
    # 2 + 2 + 1 mix of different people, which a distance to the mean would not.
    mat = np.stack(vectors)
    sims = mat @ mat.T
    kept: list[np.ndarray] = []
    for pos, (idx, v) in enumerate(zip(kept_idx, vectors)):
        if float(np.median(np.delete(sims[pos], pos))) >= CONSISTENCY_MIN_SIMILARITY:
            kept.append(v)
        else:
            problems[idx] = "different-person"
    if len(kept) < MIN_ENROLL_IMAGES:
        raise EnrollError("inconsistent", "the photos do not all show the same person", problems)
    return kept
