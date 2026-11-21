# SPDX-License-Identifier: MIT
"""Which "infrared" cameras were shown not to see a phone screen.

The camera class comes from the pixel formats (monochrome = "infrared").  That guess is wrong for a
monochrome sensor *without* an infrared filter: it sees a phone screen, and a photograph on a phone
then unlocks a service that was meant to need infrared.  `facial-auth check-camera` therefore shows
the camera a bright screen (irtest.py) and records the outcome here; services that require an
infrared camera accept only a camera that passed (``camera.require_ir_check``).
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path

from .const import Paths
from .v4l2 import CameraInfo

log = logging.getLogger(__name__)


class CameraTrust:
    def __init__(self, paths: Paths | None = None, owner: tuple[int, int] | None = None) -> None:
        self.paths = paths or Paths()
        self._owner = owner

    @property
    def path(self) -> Path:
        return self.paths.state / "cameras.json"

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def is_verified(self, info: CameraInfo) -> bool:
        entry = self._load().get(info.key())
        return bool(isinstance(entry, dict) and entry.get("verified") is True)

    def status(self, info: CameraInfo) -> str:
        """verified | failed | unknown"""
        entry = self._load().get(info.key())
        if not isinstance(entry, dict):
            return "unknown"
        return "verified" if entry.get("verified") is True else "failed"

    def record(self, info: CameraInfo, verified: bool, details: dict | None = None) -> None:
        data = self._load()
        data[info.key()] = {"name": info.name, "verified": bool(verified),
                            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "details": {k: v for k, v in (details or {}).items()
                                        if isinstance(v, (int, float, str, bool))}}
        self.paths.state.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".cameras.", dir=self.paths.state)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
            os.chmod(tmp, 0o644)
            if self._owner and os.geteuid() == 0:
                os.chown(tmp, *self._owner)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        log.info("camera %s (%s): infrared check %s", info.name, info.path, "passed" if verified else "failed")
