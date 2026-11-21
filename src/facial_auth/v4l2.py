# SPDX-License-Identifier: MIT
"""Camera discovery and IR/RGB classification through plain V4L2 ioctls.

Laptops with "Windows Hello" hardware expose the infrared sensor as a second
video node (usually GREY/Y8I), next to the colour webcam.  Many UVC cameras
also expose metadata-only nodes that must be ignored.  The ioctl function is
injectable so the parsing can be tested without any hardware.
"""
from __future__ import annotations

import errno
import fcntl
import logging
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .const import Paths

log = logging.getLogger(__name__)

VIDIOC_QUERYCAP = 0x80685600     # _IOR('V', 0, struct v4l2_capability)  (104 bytes)
VIDIOC_ENUM_FMT = 0xC0405602     # _IOWR('V', 2, struct v4l2_fmtdesc)    (64 bytes)
V4L2_BUF_TYPE_VIDEO_CAPTURE = 1
V4L2_CAP_VIDEO_CAPTURE = 0x00000001
V4L2_CAP_STREAMING = 0x04000000
V4L2_CAP_DEVICE_CAPS = 0x80000000

_CAP = struct.Struct("<16s32s32sIII3I")
_FMT = struct.Struct("<III32sII3I")
assert _CAP.size == 104 and _FMT.size == 64

MONO_FORMATS = {"GREY", "Y8I", "Y10", "Y12", "Y16", "Y10B", "Y12I", "Y14", "Y8"}
COLOR_FORMATS = {"YUYV", "MJPG", "JPEG", "NV12", "NV21", "UYVY", "YVYU", "VYUY", "YU12",
                 "YV12", "RGB3", "BGR3", "RGBP", "RGB4", "BGR4", "H264", "Y41P", "M420"}
VIRTUAL_DRIVERS = ("v4l2 loopback", "v4l2loopback", "vivid", "vimc", "vim2m", "vicodec")
IR_NAME = re.compile(r"(\bir\b|infra\s*red|infrared|\bnir\b)", re.IGNORECASE)


@dataclass
class CameraInfo:
    path: str
    name: str = ""
    driver: str = ""
    bus: str = ""
    formats: list[str] = field(default_factory=list)
    camera_class: str = "unknown"      # rgb | ir | unknown
    usable: bool = False               # can capture video frames
    virtual: bool = False              # loopback / test pattern generator

    def key(self) -> str:
        """Stable identity of this video node (the /dev/videoN number is not): the colour and
        infrared nodes of one laptop camera share a name and a bus, not their formats."""
        return f"{self.name}|{self.bus}|{self.camera_class}|{','.join(sorted(self.formats))}"

    def public(self) -> dict:
        return {"path": self.path, "name": self.name, "driver": self.driver,
                "class": self.camera_class, "formats": ",".join(self.formats),
                "usable": self.usable, "virtual": self.virtual}


def _fourcc(raw: int) -> str:
    return struct.pack("<I", raw).decode("ascii", errors="replace").strip()


def _text(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()


def classify(name: str, formats: list[str]) -> str:
    fmts = set(formats)
    if IR_NAME.search(name):
        return "ir"
    if fmts & COLOR_FORMATS:
        return "rgb"
    if fmts & MONO_FORMATS:
        return "ir"
    return "unknown"


def probe(path: str, ioctl: Callable = fcntl.ioctl) -> CameraInfo:
    """Query one /dev/videoN node; never raises."""
    info = CameraInfo(path=path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        log.debug("cannot open %s: %s", path, exc)
        return info
    try:
        buf = bytearray(_CAP.size)
        ioctl(fd, VIDIOC_QUERYCAP, buf, True)
        driver, card, bus, _ver, caps, dev_caps, *_ = _CAP.unpack(bytes(buf))
        caps = dev_caps if caps & V4L2_CAP_DEVICE_CAPS else caps
        info.driver, info.name, info.bus = _text(driver), _text(card), _text(bus)
        info.virtual = any(v in info.driver.lower() for v in VIRTUAL_DRIVERS)
        capture = bool(caps & V4L2_CAP_VIDEO_CAPTURE) and bool(caps & V4L2_CAP_STREAMING)
        index = 0
        while capture and index < 64:
            fmt = bytearray(_FMT.size)
            _FMT.pack_into(fmt, 0, index, V4L2_BUF_TYPE_VIDEO_CAPTURE, 0, b"", 0, 0, 0, 0, 0)
            try:
                ioctl(fd, VIDIOC_ENUM_FMT, fmt, True)
            except OSError as exc:
                if exc.errno == errno.EINVAL:   # end of the list
                    break
                raise
            _idx, _type, _flags, _desc, pixfmt, *_ = _FMT.unpack(bytes(fmt))
            info.formats.append(_fourcc(pixfmt))
            index += 1
        info.usable = capture and bool(info.formats)
        info.camera_class = classify(info.name, info.formats) if info.usable else "unknown"
    except OSError as exc:
        log.debug("V4L2 query of %s failed: %s", path, exc)
    finally:
        os.close(fd)
    return info


def discover(paths: Paths | None = None, ioctl: Callable = fcntl.ioctl) -> list[CameraInfo]:
    paths = paths or Paths()
    nodes = sorted(Path(paths.dev).glob("video[0-9]*"),
                   key=lambda p: int(re.sub(r"\D", "", p.name) or 0))
    return [probe(str(n), ioctl) for n in nodes]


def select(cameras: list[CameraInfo], device: str = "auto", preference: str = "ir-first",
           force_class: str = "auto", need_class: str | None = None,
           allow_virtual: bool = False) -> CameraInfo | None:
    """Pick the camera to use.

    ``need_class`` ("ir"/"rgb"/None) comes from the service policy and from the
    kind of face the user enrolled.
    """
    def eff(c: CameraInfo) -> str:
        return force_class if force_class != "auto" else c.camera_class

    usable = [c for c in cameras if c.usable and (allow_virtual or not c.virtual)]
    if device != "auto":
        want = os.path.realpath(device)
        for c in usable:
            if os.path.realpath(c.path) == want:
                if need_class and eff(c) != need_class:
                    return None
                return c
        return None
    if preference == "ir-only":
        usable = [c for c in usable if eff(c) == "ir"]
    elif preference == "rgb-only":
        usable = [c for c in usable if eff(c) == "rgb"]
    if need_class:
        usable = [c for c in usable if eff(c) == need_class]
    order = {"ir-first": ("ir", "rgb"), "rgb-first": ("rgb", "ir")}.get(preference, ("ir", "rgb"))
    usable.sort(key=lambda c: order.index(eff(c)) if eff(c) in order else len(order))
    return usable[0] if usable else None


def effective_class(cam: CameraInfo, force_class: str = "auto") -> str:
    return force_class if force_class != "auto" else cam.camera_class
