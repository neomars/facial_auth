# SPDX-License-Identifier: MIT
"""The `facial-auth` command against the real D-Bus service (fake camera/engine)."""
import os
import subprocess
import sys

import pytest

from facial_auth.const import ACTION_CAMERA, ACTION_CONFIGURE, ACTION_MANAGE
from facial_auth.scan import encode_jpeg

from .fakes import face_frame
from .conftest import USER
from .test_dbus import reset  # noqa: F401  (autouse isolation fixture)


def cli(env, *args, timeout=60):
    e = {**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "..", "src"),
         "FACIAL_AUTH_BUS": "session", "LANGUAGE": "C", "LC_ALL": "C"}
    p = subprocess.run(["/usr/bin/python3.12", "-m", "facial_auth.cli", *args], capture_output=True,
                       text=True, env=e, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def test_add_from_camera_then_list_test_and_remove(env):
    env.polkit.grants = {ACTION_CAMERA, ACTION_MANAGE}
    rc, out = cli(env, "add", "--user", USER, "--label", "Desk", "-n", "3")
    assert rc == 0, out
    assert "photo 3/3 taken" in out and "now linked to " + USER in out
    rc, out = cli(env, "list", "--user", USER)
    assert rc == 0 and "Desk" in out and "RGB" in out and "3 samples" not in out.split("RGB")[0]
    env.service.caller_uid = lambda sender: env.uid
    rc, out = cli(env, "test", "--user", USER)
    assert rc == 0 and "Recognised" in out
    face_id = env.core.store.load(env.uid).faces[0].id
    rc, out = cli(env, "remove", "--user", USER, face_id)
    assert rc == 0 and "removed" in out
    assert env.core.store.load(env.uid).faces == []


def test_import_photos_taken_with_the_camera_app(env, tmp_path):
    for i in range(4):
        (tmp_path / f"IMG_{i}.jpg").write_bytes(encode_jpeg(face_frame(2)))
    env.polkit.grants = {ACTION_MANAGE}
    rc, out = cli(env, "import", "--user", USER, "--label", "Camera app", *map(str, sorted(tmp_path.glob("*.jpg"))))
    assert rc == 0, out
    assert env.core.store.load(env.uid).faces[0].source == "import"
    rc, out = cli(env, "import", "--user", USER, str(tmp_path / "missing.jpg"))
    assert rc == 1 and "missing.jpg" in out


def test_non_admin_gets_a_clear_message(env):
    env.polkit.grants = {ACTION_CAMERA}
    rc, out = cli(env, "add", "--user", USER, "-n", "3")
    assert rc == 1 and "Not authorized" in out


def test_an_unreachable_polkit_is_not_presented_as_an_administrator_refusal(env):
    env.polkit.grants = {ACTION_CAMERA, ACTION_MANAGE}
    env.polkit.unavailable = "polkitd is not running"
    rc, out = cli(env, "add", "--user", USER, "-n", "3")
    assert rc == 1 and "Cannot ask polkit" in out and "polkitd is not running" in out
    assert "administrator must approve" not in out
    env.polkit.unavailable = None


def test_status_cameras_service_config_and_toggle(env):
    rc, out = cli(env, "status")
    assert rc == 0 and "Face authentication: enabled" in out and USER in out
    rc, out = cli(env, "cameras")
    assert rc == 0 and "rgb" in out
    rc, out = cli(env, "service")
    assert "sudo" in out and "camera=ir" in out
    env.polkit.grants = {ACTION_CONFIGURE}
    rc, out = cli(env, "service", "sudo", "any")
    assert rc == 0 and env.core.cfg.service("sudo").camera_class == "any"
    rc, out = cli(env, "config", "recognition.threshold", "0.6")
    assert rc == 0 and env.core.cfg["recognition", "threshold"] == 0.6
    rc, out = cli(env, "config", "recognition.threshold", "0.1")
    assert rc == 1 and "out of range" in out
    env.core.paths.settings.unlink()
    env.core.reload()
    env.service.caller_uid = lambda sender: env.uid       # the account owner toggles their own face
    rc, out = cli(env, "disable", "--user", USER)
    assert rc == 1 and "No face is linked" in out


def test_without_a_daemon_the_error_is_actionable(env):
    e = {**os.environ, "PYTHONPATH": "src", "FACIAL_AUTH_BUS": "session", "LANGUAGE": "C",
         "DBUS_SESSION_BUS_ADDRESS": "unix:path=/nonexistent/bus"}
    p = subprocess.run(["/usr/bin/python3.12", "-m", "facial_auth.cli", "status"], capture_output=True,
                       text=True, env=e, timeout=30)
    assert p.returncode != 0
