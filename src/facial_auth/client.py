# SPDX-License-Identifier: MIT
"""D-Bus client used by the CLI and the settings app."""
from __future__ import annotations

import json
import os
from typing import Any

from gi.repository import Gio, GLib

from .const import BUS_NAME, ERROR_PREFIX, IFACE, OBJECT_PATH


class ClientError(Exception):
    """``code`` is the stable error code ('access-denied', 'not-enough-faces'...)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _code_of(remote: str | None) -> str:
    if not remote:
        return "internal"
    if remote.startswith(ERROR_PREFIX + "."):
        tail = remote[len(ERROR_PREFIX) + 1:]
        return "".join("-" + c.lower() if c.isupper() and i else c.lower() for i, c in enumerate(tail))
    if remote.endswith("AccessDenied"):
        return "access-denied"
    if remote.endswith(("ServiceUnknown", "NameHasNoOwner")):
        return "daemon-unavailable"
    return "internal"


def _convert(exc: GLib.Error) -> ClientError:
    """GLib.Error -> ClientError (strip_remote_error edits the error in place)."""
    remote = Gio.DBusError.get_remote_error(exc)
    Gio.DBusError.strip_remote_error(exc)
    return ClientError(_code_of(remote), exc.message)


class Client:
    def __init__(self, bus: str | None = None) -> None:
        bus = bus or os.environ.get("FACIAL_AUTH_BUS", "system")
        try:
            self.conn = Gio.bus_get_sync(Gio.BusType.SESSION if bus == "session" else Gio.BusType.SYSTEM, None)
        except GLib.Error as exc:
            raise ClientError("daemon-unavailable", exc.message) from exc

    # -- low level ----------------------------------------------------------
    def call(self, method: str, sig: str = "", args: tuple = (), timeout_ms: int = 30000) -> tuple:
        params = GLib.Variant(f"({sig})", args) if sig else None
        try:
            res = self.conn.call_sync(BUS_NAME, OBJECT_PATH, IFACE, method, params, None,
                                      Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION,
                                      timeout_ms, None)
        except GLib.Error as exc:
            raise _convert(exc) from exc
        return res.unpack()

    def call_async(self, method: str, sig: str, args: tuple, callback, timeout_ms: int = 600000) -> None:
        """callback(result_tuple, error) runs in the GLib main loop."""
        params = GLib.Variant(f"({sig})", args) if sig else None

        def done(conn, res, _data):
            try:
                out = conn.call_finish(res).unpack()
                callback(out, None)
            except GLib.Error as exc:
                callback(None, _convert(exc))

        self.conn.call(BUS_NAME, OBJECT_PATH, IFACE, method, params, None,
                       Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, timeout_ms, None, done, None)

    def subscribe(self, signal: str, callback) -> int:
        return self.conn.signal_subscribe(BUS_NAME, IFACE, signal, OBJECT_PATH, None,
                                          Gio.DBusSignalFlags.NONE,
                                          lambda *a: callback(*a[5].unpack()), None)

    # -- API ------------------------------------------------------------------
    def status(self) -> dict:
        return self.call("GetStatus")[0]

    def cameras(self) -> list[dict]:
        return self.call("ListCameras")[0]

    def users(self) -> list[dict]:
        return self.call("ListUsers")[0]

    def faces(self, user: str) -> list[dict]:
        return self.call("ListFaces", "s", (user,))[0]

    def config(self) -> dict[str, Any]:
        return json.loads(self.call("GetConfig")[0])

    def set_config(self, changes: dict[str, Any]) -> None:
        def v(x):
            if isinstance(x, bool):
                return GLib.Variant("b", x)
            if isinstance(x, int):
                return GLib.Variant("x", x)
            if isinstance(x, float):
                return GLib.Variant("d", x)
            return GLib.Variant("s", str(x))
        self.call("SetConfig", "a{sv}", ({k: v(x) for k, x in changes.items()},), 600000)

    def analyze(self, image: bytes) -> dict:
        return self.call("AnalyzeImage", "ay", (image,))[0]

    def start_preview(self, camera_class: str = "") -> str:
        return self.call("StartPreview", "s", (camera_class,))[0]

    def grab(self) -> tuple[bytes, dict]:
        jpeg, analysis = self.call("GrabFrame")
        return bytes(jpeg), analysis

    def stop_preview(self) -> None:
        self.call("StopPreview")

    def add_face(self, user: str, label: str, images: list[bytes], camera_class: str,
                 source: str) -> dict:
        return self.call("AddFace", "ssaayss", (user, label, images, camera_class, source), 600000)[0]

    def remove_face(self, user: str, face_id: str) -> None:
        self.call("RemoveFace", "ss", (user, face_id), 600000)

    def clear(self, user: str) -> int:
        return self.call("ClearFaces", "s", (user,), 600000)[0]

    def set_enabled(self, user: str, enabled: bool) -> None:
        self.call("SetUserEnabled", "sb", (user, enabled), 600000)

    def test(self, user: str, camera_class: str = "") -> dict:
        return self.call("TestRecognition", "ss", (user, camera_class), 120000)[0]

    def verify_infrared(self) -> dict:
        return self.call("VerifyInfrared", "", (), 120000)[0]
