# SPDX-License-Identifier: MIT
"""Face detection / recognition models (OpenCV Zoo, ONNX).

* YuNet  (MIT)         - face detector with 5 landmarks
* SFace  (Apache-2.0)  - 128-d face embedding, 99.4 % accuracy on LFW

The detector depends on the OpenCV that Ubuntu ships: ``FaceDetectorYN``
decodes the *old* YuNet layout (``loc``/``conf``/``iou`` outputs) up to
OpenCV 4.7 and only the *new* one (``cls_8`` ... ``kps_32``) from 4.8.  Ubuntu
24.04 ships OpenCV 4.6, hence ``yunet-2022mar`` there.

Files are never trusted blindly: SHA-256 and size are pinned (they come from
the Git LFS pointers of the pinned opencv_zoo commits) and checked both after
a download and before a model is loaded.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .const import Paths

log = logging.getLogger(__name__)

_ZOO = "opencv/opencv_zoo"
_OLD = "7e062e54cf5410c09b795ff71b4a255e58498c79"   # YuNet 2022mar + SFace
_NEW = "48b10fa505aeb51fbd127fc60a5c660040e823b7"   # YuNet 2023mar


def _urls(commit: str, subdir: str, name: str) -> tuple[str, ...]:
    return (
        f"https://github.com/{_ZOO}/raw/{commit}/models/{subdir}/{name}",
        f"https://media.githubusercontent.com/media/{_ZOO}/{commit}/models/{subdir}/{name}",
    )


@dataclass(frozen=True)
class ModelSpec:
    key: str
    filename: str
    sha256: str
    size: int
    urls: tuple[str, ...]
    license: str
    role: str                      # detector | recognizer


YUNET_2022 = ModelSpec(
    "yunet-2022mar", "face_detection_yunet_2022mar.onnx",
    "50ef07f702a31741ca46a4c0d947773b64143b9362780237bf0d427d6c79bab7", 345478,
    _urls(_OLD, "face_detection_yunet", "face_detection_yunet_2022mar.onnx"), "MIT", "detector")
YUNET_2023 = ModelSpec(
    "yunet-2023mar", "face_detection_yunet_2023mar.onnx",
    "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4", 232589,
    _urls(_NEW, "face_detection_yunet", "face_detection_yunet_2023mar.onnx"), "MIT", "detector")
SFACE = ModelSpec(
    "sface-2021dec", "face_recognition_sface_2021dec.onnx",
    "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79", 38696353,
    _urls(_OLD, "face_recognition_sface", "face_recognition_sface_2021dec.onnx"),
    "Apache-2.0", "recognizer")

ALL = (YUNET_2022, YUNET_2023, SFACE)


def opencv_version(cv_version: str | None = None) -> tuple[int, int]:
    if cv_version is None:
        import cv2
        cv_version = cv2.__version__
    parts = cv_version.split(".")
    return int(parts[0]), int(parts[1])


def required(cv_version: str | None = None) -> tuple[ModelSpec, ModelSpec]:
    """(detector, recognizer) matching the installed OpenCV."""
    detector = YUNET_2023 if opencv_version(cv_version) >= (4, 8) else YUNET_2022
    return detector, SFACE


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_verified: dict[tuple[str, int, int], bool] = {}


def verify(spec: ModelSpec, path: Path) -> bool:
    """Size + SHA-256 check (memoised on path/size/mtime)."""
    try:
        st = path.stat()
    except OSError:
        return False
    if st.st_size != spec.size:
        return False
    key = (str(path), st.st_size, int(st.st_mtime_ns))
    if key not in _verified:
        _verified[key] = sha256_of(path) == spec.sha256
    return _verified[key]


def locate(spec: ModelSpec, paths: Paths | None = None) -> Path | None:
    """Return the verified file for ``spec`` or None."""
    paths = paths or Paths()
    candidate = paths.models / spec.filename
    return candidate if verify(spec, candidate) else None


def status(paths: Paths | None = None, cv_version: str | None = None) -> dict:
    paths = paths or Paths()
    det, rec = required(cv_version)
    missing = [s.filename for s in (det, rec) if locate(s, paths) is None]
    return {"detector": det.key, "recognizer": rec.key, "directory": str(paths.models),
            "missing": missing, "ok": not missing}


def fetch(spec: ModelSpec, dest_dir: Path, opener=urllib.request.urlopen,
          progress=None) -> Path:
    """Download ``spec`` into ``dest_dir`` (needs network, run as root).

    The download is verified before it is moved into place, so a truncated or
    tampered file can never be picked up by the daemon.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    final = dest_dir / spec.filename
    if verify(spec, final):
        return final
    last_error: Exception | None = None
    for url in spec.urls:
        fd, tmp_name = tempfile.mkstemp(prefix=spec.filename + ".", dir=dest_dir)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out, opener(url, timeout=60) as resp:  # noqa: S310
                done = 0
                for chunk in iter(lambda: resp.read(1 << 18), b""):
                    out.write(chunk)
                    done += len(chunk)
                    if done > spec.size + (1 << 20):
                        raise ValueError("download larger than expected")
                    if progress:
                        progress(spec, done)
            if tmp.stat().st_size != spec.size or sha256_of(tmp) != spec.sha256:
                raise ValueError("checksum mismatch (corrupted or tampered download)")
            tmp.chmod(0o644)
            tmp.replace(final)
            return final
        except Exception as exc:  # noqa: BLE001 - try the next mirror
            last_error = exc
            log.warning("download from %s failed: %s", url, exc)
            tmp.unlink(missing_ok=True)
    raise RuntimeError(f"could not download {spec.filename}: {last_error}")


def fetch_required(paths: Paths | None = None, cv_version: str | None = None,
                   progress=None, opener=urllib.request.urlopen) -> list[Path]:
    paths = paths or Paths()
    return [fetch(s, paths.models, opener=opener, progress=progress)
            for s in required(cv_version)]


def fetch_all(dest_dir: Path, progress=None, opener=urllib.request.urlopen,
              specs: tuple[ModelSpec, ...] = ALL) -> list[Path]:
    """Download *every* known model, whatever the OpenCV version.

    Used when building a package: it then works on any release of Ubuntu and
    needs no network at install time.
    """
    return [fetch(s, dest_dir, opener=opener, progress=progress) for s in specs]


def check_dir(directory: Path, specs: tuple[ModelSpec, ...] = ALL) -> list[str]:
    """Problems found in a directory of models; an empty list means all good."""
    problems = []
    for spec in specs:
        path = directory / spec.filename
        if not path.exists():
            problems.append(f"{spec.filename}: missing")
        elif not verify(spec, path):
            problems.append(f"{spec.filename}: size or SHA-256 mismatch")
    return problems


def install_from(directory: Path, paths: Paths | None = None, cv_version: str | None = None) -> list[Path]:
    """Install already-downloaded files (offline machines): verifies them."""
    paths = paths or Paths()
    paths.models.mkdir(parents=True, exist_ok=True)
    out = []
    for spec in required(cv_version):
        src = directory / spec.filename
        if not verify(spec, src):
            raise RuntimeError(f"{src}: missing or does not match the expected SHA-256")
        dst = paths.models / spec.filename
        shutil.copyfile(src, dst)
        dst.chmod(0o644)
        out.append(dst)
    return out
