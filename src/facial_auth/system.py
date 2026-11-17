# SPDX-License-Identifier: MIT
"""Facts about the machine that decide whether looking at a camera makes sense."""
from __future__ import annotations

import glob
import logging
from pathlib import Path
from typing import Protocol

from .const import Paths

log = logging.getLogger(__name__)

LOGIN1 = "org.freedesktop.login1"


def lid_closed(paths: Paths | None = None) -> bool:
    """True when ACPI reports a closed lid (the built-in camera sees nothing)."""
    paths = paths or Paths()
    for f in glob.glob(paths.lid_glob):
        try:
            if "closed" in Path(f).read_text().lower():
                return True
        except OSError:
            continue
    return False


class SessionProbe(Protocol):
    def is_remote(self, pid: int) -> bool | None:
        """True: ssh/remote session, False: local, None: unknown."""


class LogindProbe:
    """Asks systemd-logind whether the caller's session is remote."""

    def __init__(self) -> None:
        self._bus = None

    def _connection(self):
        if self._bus is None:
            from gi.repository import Gio
            self._bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        return self._bus

    def is_remote(self, pid: int) -> bool | None:
        try:
            from gi.repository import Gio, GLib
            bus = self._connection()
            res = bus.call_sync(LOGIN1, "/org/freedesktop/login1", f"{LOGIN1}.Manager",
                                "GetSessionByPID", GLib.Variant("(u)", (pid,)),
                                GLib.VariantType("(o)"), Gio.DBusCallFlags.NONE, 2000, None)
            session_path = res.unpack()[0]
            prop = bus.call_sync(LOGIN1, session_path, "org.freedesktop.DBus.Properties", "Get",
                                 GLib.Variant("(ss)", (f"{LOGIN1}.Session", "Remote")),
                                 GLib.VariantType("(v)"), Gio.DBusCallFlags.NONE, 2000, None)
            return bool(prop.unpack()[0])
        except Exception as exc:  # noqa: BLE001
            # "No session for PID" is normal for system services (display manager).
            log.debug("logind session lookup for pid %s: %s", pid, exc)
            return None


class NullProbe:
    def is_remote(self, pid: int) -> bool | None:
        return None
