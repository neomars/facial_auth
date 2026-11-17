# SPDX-License-Identifier: MIT
"""The D-Bus management API on a private bus, with a recording polkit stand-in."""
import json
import os
import subprocess
import threading
import time

import pytest

gi = pytest.importorskip("gi")
from gi.repository import Gio, GLib  # noqa: E402

from facial_auth import v4l2  # noqa: E402
from facial_auth.config import Config  # noqa: E402
from facial_auth.const import ACTION_CAMERA, ACTION_CONFIGURE, ACTION_MANAGE, BUS_NAME, IFACE, OBJECT_PATH  # noqa: E402
from facial_auth.core import Core  # noqa: E402
from facial_auth.const import Paths  # noqa: E402
from facial_auth.dbus_service import DBusService  # noqa: E402
from facial_auth.scan import encode_jpeg  # noqa: E402
from facial_auth.store import FaceStore  # noqa: E402

from .fakes import FakeEngine, ScriptedCamera, face_frame  # noqa: E402

from .conftest import USER  # noqa: E402

pytestmark = pytest.mark.skipif(not os.path.exists("/usr/bin/dbus-daemon"), reason="needs dbus-daemon")


def call(env, method, args=None, sig="", conn=None, timeout=20000):
    params = GLib.Variant(f"({sig})", args) if sig else None
    res = (conn or env.conn).call_sync(BUS_NAME, OBJECT_PATH, IFACE, method, params, None,
                                       Gio.DBusCallFlags.NONE, timeout, None)
    return res.unpack()


def fails(env, method, args=None, sig="", conn=None):
    with pytest.raises(GLib.Error) as exc:
        call(env, method, args, sig, conn)
    return Gio.DBusError.get_remote_error(exc.value)


@pytest.fixture(autouse=True)
def reset(env):
    env.polkit.grants, env.polkit.asked = set(), []
    env.scene["identity"] = 1
    env.service.stop_preview(force=True)
    env.service.caller_uid = lambda sender: 0       # an administrator-less caller by default
    env.core.store.clear(env.uid)
    env.core.limiter.reset()
    yield


def photos(identity=1, n=4):
    return [encode_jpeg(face_frame(identity)) for _ in range(n)]


def test_status_and_cameras_are_public(env):
    (st,) = call(env, "GetStatus")
    assert st["enabled"] is True and st["camera_class"] == "rgb" and st["models_ok"] is True
    (cams,) = call(env, "ListCameras")
    assert cams[0]["class"] == "rgb" and cams[0]["usable"] is True
    (users,) = call(env, "ListUsers")
    assert USER in [u["name"] for u in users]
    assert env.polkit.asked == []


def test_only_an_administrator_can_link_a_face_to_an_account(env):
    args = (USER, "Me", photos(), "rgb", "camera")
    assert "AccessDenied" in fails(env, "AddFace", args, "ssaayss")
    assert env.polkit.asked == [ACTION_MANAGE]
    env.polkit.grants = {ACTION_MANAGE}
    (face,) = call(env, "AddFace", args, "ssaayss")
    assert face["samples"] == 4 and face["camera_class"] == "rgb" and face["label"] == "Me"
    assert "vectors" not in face, "no biometric data crosses the bus"
    time.sleep(0.2)
    assert env.signals[-1] == USER, "FacesChanged is emitted"
    assert env.core.store.classes_for(env.uid) == {"rgb"}
    assert os.path.exists(env.core.paths.markers / USER), "PAM fast-path marker created"


def test_a_user_can_never_link_a_face_without_admin_even_to_herself(env):
    env.service.caller_uid = lambda sender: env.uid       # alice asks for alice
    assert "AccessDenied" in fails(env, "AddFace", (USER, "x", photos(), "rgb", "camera"), "ssaayss")


def test_enrollment_errors_are_explained(env):
    env.polkit.grants = {ACTION_MANAGE}
    err = fails(env, "AddFace", (USER, "x", photos(n=2), "rgb", "camera"), "ssaayss")
    assert err.endswith("NotEnoughFaces")
    mixed = photos(3, 2) + photos(4, 2) + photos(5, 1)
    assert fails(env, "AddFace", (USER, "x", mixed, "rgb", "camera"), "ssaayss").endswith("Inconsistent")
    assert fails(env, "AddFace", (USER, "x", [b"junk"] * 3, "rgb", "camera"), "ssaayss").endswith("BadImage")
    assert fails(env, "AddFace", ("nobody-here", "x", photos(), "rgb", "camera"), "ssaayss").endswith("UnknownUser")
    assert fails(env, "AddFace", ("root", "x", photos(), "rgb", "camera"), "ssaayss").endswith("NotAllowed")
    assert fails(env, "AddFace", (USER, "x", photos(), "thermal", "camera"), "ssaayss").endswith("BadArgument")


def test_own_faces_can_be_listed_disabled_and_removed_without_admin(env):
    env.polkit.grants = {ACTION_MANAGE}
    (face,) = call(env, "AddFace", (USER, "Mine", photos(), "rgb", "camera"), "ssaayss")
    env.polkit.grants, env.polkit.asked = set(), []
    # somebody else (uid 0 here) cannot look at it without admin rights
    assert "AccessDenied" in fails(env, "ListFaces", (USER,), "s")
    env.service.caller_uid = lambda sender: env.uid                   # now it is the owner
    env.polkit.asked = []
    (faces,) = call(env, "ListFaces", (USER,), "s")
    assert [f["id"] for f in faces] == [face["id"]] and env.polkit.asked == []
    call(env, "SetUserEnabled", (USER, False), "sb")
    assert not os.path.exists(env.core.paths.markers / USER), "disabled: PAM skips the daemon"
    call(env, "SetUserEnabled", (USER, True), "sb")
    call(env, "RemoveFace", (USER, face["id"]), "ss")
    assert call(env, "ListFaces", (USER,), "s")[0] == []
    assert fails(env, "RemoveFace", (USER, "deadbeef"), "ss").endswith("NotFound")
    assert env.polkit.asked == []


def test_admin_can_clear_another_account(env):
    env.polkit.grants = {ACTION_MANAGE}
    call(env, "AddFace", (USER, "a", photos(), "rgb", "camera"), "ssaayss")
    call(env, "AddFace", (USER, "b", photos(), "rgb", "camera"), "ssaayss")
    assert call(env, "ClearFaces", (USER,), "s") == (2,)


def test_image_analysis_gives_hints(env):
    env.polkit.grants = {ACTION_CAMERA}
    (a,) = call(env, "AnalyzeImage", (encode_jpeg(face_frame(1)),), "ay")
    assert a["ok"] is True and a["faces"] == 1 and len(a["box"]) == 4
    (a,) = call(env, "AnalyzeImage", (encode_jpeg(face_frame(None)),), "ay")
    assert a["ok"] is False and "no-face" in a["hints"]
    env.polkit.grants = set()
    assert "AccessDenied" in fails(env, "AnalyzeImage", (b"x",), "ay")


def test_preview_session_is_private_and_released(env):
    env.polkit.grants = {ACTION_CAMERA}
    assert call(env, "StartPreview", ("",), "s") == ("rgb",)
    jpeg, analysis = call(env, "GrabFrame")
    assert bytes(jpeg)[:2] == b"\xff\xd8" and analysis["faces"] == 1 and analysis["camera_class"] == "rgb"
    # a second bus client sees neither the frames nor can take the camera
    other = Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SESSION_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
    assert fails(env, "GrabFrame", conn=other).endswith("NoPreview")
    assert fails(env, "StartPreview", ("",), "s", conn=other).endswith("CameraBusy")
    call(env, "StopPreview")
    assert fails(env, "GrabFrame").endswith("NoPreview")
    assert env.core.broker.owner == "", "camera released"
    # an owner that disappears releases the camera by itself
    call(env, "StartPreview", ("",), "s", conn=other)
    assert env.core.broker.owner == "preview"
    other.close_sync(None)
    for _ in range(50):
        if env.core.broker.owner == "":
            break
        time.sleep(0.1)
    assert env.core.broker.owner == "", "owner vanished: camera must be released"


def test_forgotten_preview_is_reaped(env, monkeypatch):
    env.polkit.grants = {ACTION_CAMERA}
    call(env, "StartPreview", ("",), "s")
    monkeypatch.setattr("facial_auth.dbus_service.PREVIEW_IDLE_SECONDS", -1)
    env.service.reap_previews()
    assert env.core.broker.owner == ""


def test_configuration_needs_admin_and_is_validated(env):
    assert "AccessDenied" in fails(env, "SetConfig", ({"recognition.threshold": GLib.Variant("d", 0.6)},), "a{sv}")
    env.polkit.grants = {ACTION_CONFIGURE}
    call(env, "SetConfig", ({"recognition.threshold": GLib.Variant("d", 0.6),
                             "services.sudo": GLib.Variant("s", "any")},), "a{sv}")
    cfg = json.loads(call(env, "GetConfig")[0])
    assert cfg["recognition"]["threshold"] == 0.6 and cfg["services"]["sudo"] == "any"
    assert fails(env, "SetConfig", ({"recognition.threshold": GLib.Variant("d", 0.01)},), "a{sv}").endswith("BadArgument")
    assert fails(env, "SetConfig", ({"camera.emitter_command": GLib.Variant("s", "id")},), "a{sv}").endswith("BadArgument")
    env.core.paths.settings.unlink()
    env.core.reload()


def test_recognition_test_for_the_owner(env):
    env.polkit.grants = {ACTION_MANAGE}
    call(env, "AddFace", (USER, "me", photos(1), "rgb", "camera"), "ssaayss")
    env.service.caller_uid = lambda sender: env.uid
    env.polkit.grants, env.polkit.asked = set(), []
    (res,) = call(env, "TestRecognition", (USER, ""), "ss")
    assert res["ok"] is True and res["camera_class"] == "rgb"
    env.scene["identity"] = 5
    (res,) = call(env, "TestRecognition", (USER, ""), "ss", timeout=60000)
    assert res["ok"] is False and res["reason"] in ("mismatch", "no-face")
    assert env.polkit.asked == [], "testing one's own account needs no admin"
    env.service.caller_uid = lambda sender: 0
    env.polkit.grants = {ACTION_MANAGE}
    call(env, "ClearFaces", (USER,), "s")
    assert fails(env, "TestRecognition", (USER, ""), "ss").endswith("NotEnrolled")
