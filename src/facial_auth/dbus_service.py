# SPDX-License-Identifier: MIT
"""System D-Bus API (management: enroll, list, remove, configure, test).

Authorization is done with polkit:

* ``manage-faces``  - link/unlink a face to *another* account (administrator)
* ``configure``     - change daemon settings (administrator)
* ``use-camera``    - camera preview / analysis (active local session)

A user may always look at, test, disable or remove *their own* faces, but only
an administrator can link a new face to an account: that is the step that
grants a way to log in.  Preview frames are returned to the caller only; they
are never broadcast as signals, so another bus client cannot eavesdrop.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Protocol

from gi.repository import Gio, GLib

from . import config as config_mod
from . import scan
from .camera import CameraBusy, CameraError, FrameSource
from .const import (ACTION_CAMERA, ACTION_CONFIGURE, ACTION_MANAGE, BUS_NAME, ERROR_PREFIX,
                    IFACE, OBJECT_PATH)
from .core import ApiError, Core

log = logging.getLogger(__name__)

PREVIEW_IDLE_SECONDS = 15.0

INTROSPECTION = f"""
<node>
  <interface name="{IFACE}">
    <method name="GetStatus"><arg type="a{{sv}}" name="status" direction="out"/></method>
    <method name="ListCameras"><arg type="aa{{sv}}" name="cameras" direction="out"/></method>
    <method name="ListUsers"><arg type="aa{{sv}}" name="users" direction="out"/></method>
    <method name="ListFaces">
      <arg type="s" name="user" direction="in"/>
      <arg type="aa{{sv}}" name="faces" direction="out"/>
    </method>
    <method name="GetConfig"><arg type="s" name="json" direction="out"/></method>
    <method name="SetConfig"><arg type="a{{sv}}" name="changes" direction="in"/></method>
    <method name="AnalyzeImage">
      <arg type="ay" name="image" direction="in"/>
      <arg type="a{{sv}}" name="analysis" direction="out"/>
    </method>
    <method name="StartPreview">
      <arg type="s" name="camera_class" direction="in"/>
      <arg type="s" name="camera_class_used" direction="out"/>
    </method>
    <method name="GrabFrame">
      <arg type="ay" name="jpeg" direction="out"/>
      <arg type="a{{sv}}" name="analysis" direction="out"/>
    </method>
    <method name="StopPreview"/>
    <method name="AddFace">
      <arg type="s" name="user" direction="in"/>
      <arg type="s" name="label" direction="in"/>
      <arg type="aay" name="images" direction="in"/>
      <arg type="s" name="camera_class" direction="in"/>
      <arg type="s" name="source" direction="in"/>
      <arg type="a{{sv}}" name="face" direction="out"/>
    </method>
    <method name="RemoveFace">
      <arg type="s" name="user" direction="in"/>
      <arg type="s" name="face_id" direction="in"/>
    </method>
    <method name="ClearFaces">
      <arg type="s" name="user" direction="in"/>
      <arg type="u" name="removed" direction="out"/>
    </method>
    <method name="SetUserEnabled">
      <arg type="s" name="user" direction="in"/>
      <arg type="b" name="enabled" direction="in"/>
    </method>
    <method name="TestRecognition">
      <arg type="s" name="user" direction="in"/>
      <arg type="s" name="camera_class" direction="in"/>
      <arg type="a{{sv}}" name="result" direction="out"/>
    </method>
    <signal name="FacesChanged"><arg type="s" name="user"/></signal>
    <signal name="ConfigChanged"/>
  </interface>
</node>
"""


# ---------------------------------------------------------------- polkit
class Authorizer(Protocol):
    def check(self, sender: str, action: str) -> bool: ...


class PolkitUnavailable(Exception):
    """polkit could not be asked (not running, refused the daemon's question...).

    That is not a "no": reporting it as "not authorized, an administrator must approve" sends
    people to type a password that nobody is going to ask for.
    """


class PolkitAuthorizer:
    """Asks polkit; blocks while the administrator types their password.

    Returns False when polkit *decided* that the caller may not; raises PolkitUnavailable when
    polkit could not be asked at all.
    """

    def __init__(self, conn: Gio.DBusConnection) -> None:
        self.conn = conn

    def check(self, sender: str, action: str) -> bool:
        try:
            subject = ("system-bus-name", {"name": GLib.Variant("s", sender)})
            args = GLib.Variant("((sa{sv})sa{ss}us)", (subject, action, {}, 1, ""))
            res = self.conn.call_sync(
                "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization", args,
                GLib.VariantType("((bba{ss}))"), Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION,
                10 * 60 * 1000, None)
            return bool(res.unpack()[0][0])
        except GLib.Error as exc:
            log.error("polkit check for %s failed: %s", action, exc.message)
            raise PolkitUnavailable(exc.message) from exc


# ------------------------------------------------------------- conversions
def variant_of(value: Any) -> GLib.Variant:
    if isinstance(value, bool):
        return GLib.Variant("b", value)
    if isinstance(value, int):
        return GLib.Variant("x", value)
    if isinstance(value, float):
        return GLib.Variant("d", value)
    if isinstance(value, (list, tuple)):
        if all(isinstance(v, int) and not isinstance(v, bool) for v in value):
            return GLib.Variant("ax", list(value))
        return GLib.Variant("as", [str(v) for v in value])
    return GLib.Variant("s", str(value))


def vardict(d: dict) -> dict[str, GLib.Variant]:
    return {str(k): variant_of(v) for k, v in d.items()}


def error_name(code: str) -> str:
    return f"{ERROR_PREFIX}.{''.join(p.capitalize() for p in code.split('-'))}"


class Preview:
    def __init__(self, owner: str, cam: FrameSource, camera_class: str) -> None:
        self.owner, self.cam, self.camera_class = owner, cam, camera_class
        self.last = time.monotonic()
        self.watch = 0


class DBusService:
    def __init__(self, core: Core, bus: Gio.BusType, authorizer: Authorizer | None = None,
                 on_ready: Callable[[], None] | None = None,
                 on_lost: Callable[[], None] | None = None) -> None:
        self.core, self.bus_type = core, bus
        self._authorizer = authorizer
        self._on_ready, self._on_lost = on_ready, on_lost
        self.conn: Gio.DBusConnection | None = None
        self.pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="dbus")
        self._preview: Preview | None = None
        self._preview_lock = threading.Lock()
        self._owner_id = 0
        self.table: dict[str, Callable[..., Any]] = {
            "GetStatus": self.m_status, "ListCameras": self.m_cameras, "ListUsers": self.m_users,
            "ListFaces": self.m_list_faces, "GetConfig": self.m_get_config,
            "SetConfig": self.m_set_config, "AnalyzeImage": self.m_analyze,
            "StartPreview": self.m_start_preview, "GrabFrame": self.m_grab,
            "StopPreview": self.m_stop_preview, "AddFace": self.m_add_face,
            "RemoveFace": self.m_remove_face, "ClearFaces": self.m_clear,
            "SetUserEnabled": self.m_set_enabled, "TestRecognition": self.m_test,
        }
        node = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION)
        self._iface = node.interfaces[0]
        self._out_sigs = {m.name: "(" + "".join(a.signature for a in m.out_args) + ")"
                          for m in self._iface.methods}

    # -------------------------------------------------------------- bus
    def start(self) -> None:
        self._owner_id = Gio.bus_own_name(
            self.bus_type, BUS_NAME, Gio.BusNameOwnerFlags.NONE,
            self._on_bus_acquired, self._on_name_acquired, self._on_name_lost)

    def _on_bus_acquired(self, conn: Gio.DBusConnection, _name: str) -> None:
        self.conn = conn
        if self._authorizer is None:
            self._authorizer = PolkitAuthorizer(conn)
        conn.register_object(OBJECT_PATH, self._iface, self._on_call, None, None)

    def _on_name_acquired(self, _conn, name: str) -> None:
        log.info("D-Bus name %s acquired", name)
        if self._on_ready:
            self._on_ready()

    def _on_name_lost(self, _conn, name: str) -> None:
        log.error("lost D-Bus name %s", name)
        if self._on_lost:
            self._on_lost()

    def emit(self, signal: str, params: GLib.Variant | None = None) -> None:
        if self.conn:
            self.conn.emit_signal(None, OBJECT_PATH, IFACE, signal, params)

    # ---------------------------------------------------------- dispatch
    def _on_call(self, conn, sender, _path, _iface, method, params, invocation) -> None:
        handler = self.table.get(method)
        self.core.touch()
        if handler is None:
            invocation.return_dbus_error("org.freedesktop.DBus.Error.UnknownMethod", method)
            return
        args = params.unpack()

        def work() -> None:
            try:
                result = handler(sender, *args)
                out = self._out_sigs[method]
                value = GLib.Variant(out, result if out != "()" else ())
                GLib.idle_add(invocation.return_value, value)
            except ApiError as exc:
                GLib.idle_add(invocation.return_dbus_error, error_name(exc.code), str(exc))
            except PermissionError as exc:
                GLib.idle_add(invocation.return_dbus_error,
                              "org.freedesktop.DBus.Error.AccessDenied", str(exc))
            except Exception as exc:  # noqa: BLE001
                log.exception("unexpected error in %s", method)
                GLib.idle_add(invocation.return_dbus_error, error_name("internal"), str(exc))
            finally:
                self.core.touch()

        self.pool.submit(work)

    # ------------------------------------------------------- authorization
    def caller_uid(self, sender: str) -> int:
        assert self.conn is not None
        res = self.conn.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                  "org.freedesktop.DBus", "GetConnectionUnixUser",
                                  GLib.Variant("(s)", (sender,)), GLib.VariantType("(u)"),
                                  Gio.DBusCallFlags.NONE, 2000, None)
        return res.unpack()[0]

    def require(self, sender: str, action: str) -> None:
        try:
            allowed = self._authorizer.check(sender, action)
        except PolkitUnavailable as exc:
            raise ApiError("polkit-unavailable", f"{action}: {exc}") from exc
        if not allowed:
            raise PermissionError(f"not authorized ({action})")

    def require_self_or_admin(self, sender: str, username: str) -> int:
        """Own account: free. Somebody else's: administrator only."""
        uid = self.core.uid_of(username)
        if self.caller_uid(sender) != uid:
            self.require(sender, ACTION_MANAGE)
        return uid

    # ----------------------------------------------------------- methods
    def m_status(self, sender):
        return (vardict(self.core.status()),)

    def m_cameras(self, sender):
        return ([vardict(c.public()) for c in self.core.cameras(refresh=True)],)

    def m_users(self, sender):
        return ([vardict(self.core.user_summary(p)) for p in self.core.human_users()],)

    def m_list_faces(self, sender, username):
        uid = self.require_self_or_admin(sender, username)
        return ([vardict(f.public()) for f in self.core.store.load(uid).faces],)

    def m_get_config(self, sender):
        return (json.dumps(self.core.cfg.as_dict()),)

    def m_set_config(self, sender, changes):
        self.require(sender, ACTION_CONFIGURE)
        try:
            validated = config_mod.validate_update({k: v for k, v in changes.items()})
            config_mod.write_settings(self.core.paths.settings, validated)
        except ValueError as exc:
            raise ApiError("bad-argument", str(exc)) from exc
        except OSError as exc:
            raise ApiError("store-error", str(exc)) from exc
        self.core.reload()
        GLib.idle_add(self.emit, "ConfigChanged")
        return ()

    def m_analyze(self, sender, image):
        self.require(sender, ACTION_CAMERA)
        return (vardict(self.core.analyze(bytes(image))),)

    # -- preview ---------------------------------------------------------
    def m_start_preview(self, sender, camera_class):
        self.require(sender, ACTION_CAMERA)
        with self._preview_lock:
            if self._preview is not None:
                if self._preview.owner != sender:
                    raise ApiError("camera-busy", "the camera is in use")
                return (self._preview.camera_class,)
            wanted = {camera_class} if camera_class else {"ir", "rgb"}
            if not wanted <= {"ir", "rgb"}:
                raise ApiError("bad-argument", "camera_class must be '', 'ir' or 'rgb'")
            picked = self.core.pick_camera(wanted)
            if picked is None:
                raise ApiError("no-camera", "no suitable camera found")
            info, cls = picked
            try:
                cam = self.core.broker.hold(lambda: self.core._camera_factory(info, cls),
                                            who="preview")
            except CameraBusy as exc:
                raise ApiError("camera-busy", str(exc)) from exc
            except CameraError as exc:
                raise ApiError("camera-error", str(exc)) from exc
            prev = Preview(sender, cam, cls)
            self._preview = prev
            with self.core._lock:
                self.core.active += 1
        prev.watch = Gio.bus_watch_name_on_connection(
            self.conn, sender, Gio.BusNameWatcherFlags.NONE, None,
            lambda *_: self.stop_preview(sender))
        return (cls,)

    def m_grab(self, sender):
        with self._preview_lock:
            prev = self._preview
            if prev is None or prev.owner != sender:
                raise ApiError("no-preview", "no preview session is running for you")
            prev.last = time.monotonic()
            frame = prev.cam.read()
        if frame is None:
            raise ApiError("camera-error", "no frame")
        analysis = scan.analyze(self.core.engine(), frame, self.core.cfg["recognition", "min_face_px"])
        return (scan.encode_jpeg(frame, 85), vardict(analysis.public() | {"camera_class": prev.camera_class}))

    def m_stop_preview(self, sender):
        self.stop_preview(sender)
        return ()

    def stop_preview(self, sender: str | None = None, force: bool = False) -> None:
        with self._preview_lock:
            prev = self._preview
            if prev is None or (not force and sender is not None and prev.owner != sender):
                return
            self._preview = None
        if prev.watch:
            Gio.bus_unwatch_name(prev.watch)
        self.core.broker.release(prev.cam)
        with self.core._lock:
            self.core.active -= 1

    def reap_previews(self) -> bool:
        """Timer: a preview nobody asks frames from is released."""
        prev = self._preview
        if prev and time.monotonic() - prev.last > PREVIEW_IDLE_SECONDS:
            log.info("preview session abandoned: camera released")
            self.stop_preview(force=True)
        return True

    # -- faces -----------------------------------------------------------
    def m_add_face(self, sender, username, label, images, camera_class, source):
        self.require(sender, ACTION_MANAGE)
        self.stop_preview(sender)            # frees the camera for the next scan
        face = self.core.add_face(username, label, [bytes(i) for i in images], camera_class,
                                  source if source in ("camera", "import") else "import")
        GLib.idle_add(self.emit, "FacesChanged", GLib.Variant("(s)", (username,)))
        return (vardict(face),)

    def m_remove_face(self, sender, username, face_id):
        uid = self.require_self_or_admin(sender, username)
        if not self.core.store.remove_face(uid, face_id):
            raise ApiError("not-found", "no such face")
        GLib.idle_add(self.emit, "FacesChanged", GLib.Variant("(s)", (username,)))
        return ()

    def m_clear(self, sender, username):
        uid = self.require_self_or_admin(sender, username)
        n = self.core.store.clear(uid)
        GLib.idle_add(self.emit, "FacesChanged", GLib.Variant("(s)", (username,)))
        return (n,)

    def m_set_enabled(self, sender, username, enabled):
        uid = self.require_self_or_admin(sender, username)
        from .store import StoreError
        try:
            self.core.store.set_enabled(uid, bool(enabled))
        except StoreError as exc:
            raise ApiError("not-enrolled", str(exc)) from exc
        GLib.idle_add(self.emit, "FacesChanged", GLib.Variant("(s)", (username,)))
        return ()

    def m_test(self, sender, username, camera_class):
        self.require_self_or_admin(sender, username)
        self.stop_preview(sender)
        return (vardict(self.core.test_user(username, camera_class or None, lambda: False)),)
