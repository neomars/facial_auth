# SPDX-License-Identifier: MIT
"""Names, paths and defaults shared by the daemon, the CLI and the GUI.

Paths can be redirected with ``FACIAL_AUTH_ROOT`` (tests, development).  The daemon
removes that variable (and ``FACIAL_AUTH_LOCALEDIR``, ``FACIAL_AUTH_BUS``) from its
environment unless it is started with ``--dev``; the command line tools honour them.
"""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "facial-auth"
VERSION = "0.1.0"

# D-Bus ------------------------------------------------------------------
BUS_NAME = "io.github.neomars.FacialAuth1"
OBJECT_PATH = "/io/github/neomars/FacialAuth1"
IFACE = "io.github.neomars.FacialAuth1.Manager"
ERROR_PREFIX = "io.github.neomars.FacialAuth1.Error"

# polkit actions (see data/polkit/*.policy)
ACTION_MANAGE = "io.github.neomars.FacialAuth1.manage-faces"
ACTION_CONFIGURE = "io.github.neomars.FacialAuth1.configure"
ACTION_CAMERA = "io.github.neomars.FacialAuth1.use-camera"

SERVICE_USER = "facial-auth"

# Largest picture (width x height, as written in its header) the daemon agrees to decode.
# 24 Mi pixels: a 24-megapixel camera passes, nothing bigger.  OpenCV is given the same bound.
MAX_IMAGE_PIXELS = 24 * 1024 * 1024


def _root() -> Path:
    return Path(os.environ.get("FACIAL_AUTH_ROOT", "/"))


class Paths:
    """Filesystem layout; evaluated lazily so tests can change the root."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root is not None else _root()

    def _p(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    @property
    def config(self) -> Path:          # admin-edited
        return self._p("/etc/facial-auth/facial-auth.conf")

    @property
    def config_dropins(self) -> Path:
        return self._p("/etc/facial-auth/facial-auth.conf.d")

    @property
    def defaults(self) -> Path:        # shipped with the package
        return self._p("/usr/share/facial-auth/defaults.conf")

    @property
    def state(self) -> Path:
        return self._p("/var/lib/facial-auth")

    @property
    def settings(self) -> Path:        # written by the daemon (GUI changes)
        return self.state / "settings.conf"

    @property
    def templates(self) -> Path:
        return self.state / "templates"

    @property
    def markers(self) -> Path:         # one empty file per enrolled user name
        return self.state / "enrolled"

    @property
    def models(self) -> Path:
        return self._p("/usr/share/facial-auth/models")

    @property
    def socket(self) -> Path:
        return self._p("/run/facial-auth/pam.sock")

    @property
    def lid_glob(self) -> str:
        return str(self._p("/proc/acpi/button/lid/*/state"))

    @property
    def sysfs_v4l(self) -> Path:
        return self._p("/sys/class/video4linux")

    @property
    def dev(self) -> Path:
        return self._p("/dev")
