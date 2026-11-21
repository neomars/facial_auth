# SPDX-License-Identifier: MIT
"""End to end: real pam_facial_auth.so + real pam_unix + the Python daemon.

Only the camera and the face engine are synthetic (tests/python/fakes.py);
everything between "pam_authenticate()" and "OK/FAIL" is the production code:
C module, wire protocol, socket server, policy, scan loop, rate limiter.
"""
import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import numpy as np
import pytest

from facial_auth import v4l2
from facial_auth.config import Config
from facial_auth.const import Paths
from facial_auth.core import Core
from facial_auth.server import PamServer
from facial_auth.store import FaceStore

from .fakes import FakeEngine, ScriptedCamera, face_frame, template

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="needs root (PAM service, users)")

USER, OTHER, PASSWORD = "faE2e", "faE2eOther", "pw-e2e"
SERVICES = {"fa-e2e": "sequential", "fa-e2e-par": "parallel-tty", "fa-e2e-ir": "sequential"}


class Env:
    pass


@pytest.fixture(scope="module")
def env(build_dir, tmp_path_factory):
    e = Env()
    tmp = tmp_path_factory.mktemp("e2e")
    os.chmod(tmp, 0o755)
    for name in (USER, OTHER):
        if subprocess.run(["id", name], capture_output=True).returncode != 0:
            subprocess.run(["useradd", "-m", "-s", "/bin/bash", name], check=True)
    subprocess.run(["chpasswd"], input=f"{USER}:{PASSWORD}\n{OTHER}:{PASSWORD}\n", text=True, check=True)
    import pwd
    e.uid, e.other_uid = pwd.getpwnam(USER).pw_uid, pwd.getpwnam(OTHER).pw_uid

    paths = Paths(tmp / "root")
    classes = {s: "any" for s in SERVICES} | {"fa-e2e-ir": "ir"}
    conf = ["[services]"] + [f"{s} = {c}" for s, c in classes.items()] + ["[interaction]"] \
        + [f"{s} = {m}" for s, m in SERVICES.items()]
    paths.config.parent.mkdir(parents=True)
    paths.config.write_text("\n".join(conf) + "\n[liveness]\nmode = basic\n"
                            "[recognition]\nsequential_timeout = 2\ntimeout = 3\n"
                            "no_face_timeout = 0.8\nparallel_start_delay = 0.1\nrequired_matches = 3\n"
                            "[security]\nmax_failures = 3\nlockout = 30\n")
    e.paths = paths
    e.store = FaceStore(paths)
    e.store.add_face(e.uid, "me", template(1, 4), "rgb", "fake")
    e.store.add_face(e.other_uid, "other", template(3, 4), "rgb", "fake")

    e.scene = {"identity": 1}            # what the fake camera is looking at
    e.cameras = []

    def make_camera(info, cls):
        cam = ScriptedCamera(lambda i: face_frame(e.scene["identity"]), camera_class=cls)
        e.cameras.append(cam)
        return cam

    rgb = v4l2.CameraInfo("/dev/video0", "Fake RGB", "uvcvideo", "", ["MJPG"], "rgb", True)
    e.core = Core(paths=paths, store=e.store, engine_loader=lambda: FakeEngine(),
                  camera_factory=make_camera, camera_lister=lambda: [rgb],
                  lid_probe=lambda: False, models_probe=lambda: {"ok": True, "missing": []})

    sock_path = tmp / "pam.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    os.chmod(sock_path, 0o666)
    srv.listen(8)
    e.server = PamServer(e.core, srv)
    threading.Thread(target=e.server.serve_forever, daemon=True).start()

    module = build_dir / "pam" / "pam_facial_auth.so"
    for svc in SERVICES:
        Path(f"/etc/pam.d/{svc}").write_text(
            f"auth [success=2 conv_err=die default=ignore] {module} socket={sock_path} marker_dir=- debug\n"
            "auth [success=1 default=ignore] pam_unix.so nullok try_first_pass\n"
            "auth requisite pam_deny.so\nauth required pam_permit.so\n")
    e.pamtest = build_dir / "tests/pam/pamtest"
    yield e
    e.server.stop()
    for svc in SERVICES:
        Path(f"/etc/pam.d/{svc}").unlink(missing_ok=True)
    subprocess.run(["userdel", "-r", USER], capture_output=True)
    subprocess.run(["userdel", "-r", OTHER], capture_output=True)


def pam(env, service="fa-e2e", user=USER, *args, timeout=30):
    proc = subprocess.run([str(env.pamtest), *args, service, user], capture_output=True, text=True,
                          timeout=timeout, env={"PATH": os.environ["PATH"], "LANGUAGE": "C"})
    ev = [(m.group(1), int(m.group(2)), m.group(3)) for m in
          (re.match(r"^(\S+) (-?\d+) ?(.*)$", ln) for ln in proc.stdout.splitlines()) if m]
    return proc.returncode, ev


def tags(ev, name):
    return [e for e in ev if e[0] == name]


@pytest.fixture(autouse=True)
def fresh(env):
    env.scene["identity"] = 1
    env.cameras.clear()
    env.core.limiter.reset()
    env.core.reload()
    yield


def test_owner_logs_in_with_the_face_without_any_password(env):
    rc, ev = pam(env)
    assert rc == 0 and not tags(ev, "PROMPT"), ev
    assert ("Looking for your face...") in [e[2] for e in tags(ev, "INFO")]
    assert env.cameras and env.cameras[0].closed, "camera must be released after the scan"


def test_a_stranger_gets_the_password_prompt_instead(env):
    env.scene["identity"] = 4
    rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
    assert rc == 0 and len(tags(ev, "PROMPT")) == 1
    assert "Face not recognized." in [e[2] for e in tags(ev, "INFO")]


def test_a_stranger_with_the_wrong_password_is_refused(env):
    env.scene["identity"] = 4
    rc, ev = pam(env, "fa-e2e", USER, "--answer", "0:wrong")
    assert rc != 0


def test_one_account_cannot_be_opened_with_the_face_of_another(env):
    env.scene["identity"] = 3                      # OTHER's face in front of the camera
    rc, ev = pam(env, "fa-e2e", USER, "--answer", "0:wrong")
    assert rc != 0
    env.scene["identity"] = 3
    rc, ev = pam(env, "fa-e2e", OTHER)
    assert rc == 0, "...but it does open its own account"


def test_nobody_in_front_of_the_camera_falls_back_quickly(env):
    env.scene["identity"] = None
    t0 = time.monotonic()
    rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
    assert rc == 0 and time.monotonic() - t0 < 2.5, "no_face_timeout must unblock the password"


def test_parallel_mode_face_wins_over_the_pending_prompt(env):
    rc, ev = pam(env, "fa-e2e-par", USER, "--post-sleep", "200")
    assert rc == 0
    assert len(tags(ev, "PROMPT")) == 1, "the password prompt is displayed while scanning"
    assert tags(ev, "CONV-CANCELLED"), "and cancelled when the face is recognised"


def test_parallel_mode_password_typed_first_cancels_the_camera(env):
    env.scene["identity"] = 4                      # the face never matches
    rc, ev = pam(env, "fa-e2e-par", USER, "--answer", f"300:{PASSWORD}")
    assert rc == 0
    time.sleep(0.5)
    assert env.cameras and env.cameras[0].closed, "typing a password must stop the camera"


def test_parallel_mode_does_not_power_the_camera_for_instant_answers(env):
    """`sudo -S` style: the password is available immediately."""
    env.scene["identity"] = 4
    rc, ev = pam(env, "fa-e2e-par", USER, "--answer", f"0:{PASSWORD}")
    time.sleep(0.3)
    assert rc == 0 and not env.cameras, "start_delay must prevent a useless camera flash"


def test_infrared_only_service_refuses_an_rgb_camera(env):
    rc, ev = pam(env, "fa-e2e-ir", USER, "--answer", f"0:{PASSWORD}")
    assert rc == 0 and tags(ev, "PROMPT"), "RGB webcam + service requiring IR => password"
    assert not env.cameras


def test_unknown_service_never_uses_the_camera(env):
    Path("/etc/pam.d/fa-e2e-unlisted").write_text(Path("/etc/pam.d/fa-e2e").read_text())
    try:
        rc, ev = pam(env, "fa-e2e-unlisted", USER, "--answer", f"0:{PASSWORD}")
        assert rc == 0 and not env.cameras
    finally:
        Path("/etc/pam.d/fa-e2e-unlisted").unlink()


def test_disabling_the_user_removes_the_face_path(env):
    env.store.set_enabled(env.uid, False)
    try:
        rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
        assert rc == 0 and not env.cameras and tags(ev, "PROMPT")
    finally:
        env.store.set_enabled(env.uid, True)


def test_repeated_wrong_faces_lock_the_face_path_but_never_the_password(env):
    env.scene["identity"] = 4
    for _ in range(3):
        pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
    assert env.core.limiter.remaining(env.uid) > 0
    env.cameras.clear()
    env.scene["identity"] = 1                       # even the owner is refused while locked...
    t0 = time.monotonic()
    rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
    assert rc == 0 and not env.cameras and tags(ev, "PROMPT"), "...and still logs in by password"
    assert time.monotonic() - t0 < 2


def test_missing_models_degrade_to_the_password(env):
    env.core._models = lambda: {"ok": False, "missing": ["x.onnx"]}
    try:
        rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
        assert rc == 0 and not env.cameras
    finally:
        env.core._models = lambda: {"ok": True, "missing": []}


def test_closed_lid_skips_the_face(env):
    env.core._lid = lambda: True
    try:
        rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
        assert rc == 0 and not env.cameras
    finally:
        env.core._lid = lambda: False


def test_remote_sessions_are_refused_by_the_daemon_too(env):
    class Remote:
        def is_remote(self, pid):
            return True
    env.core.sessions = Remote()
    try:
        rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
        assert rc == 0 and not env.cameras
    finally:
        from facial_auth.system import NullProbe
        env.core.sessions = NullProbe()


def test_broken_camera_degrades_to_the_password(env):
    def broken(info, cls):
        raise RuntimeError("device vanished")
    old = env.core._camera_factory
    env.core._camera_factory = broken
    try:
        rc, ev = pam(env, "fa-e2e", USER, "--answer", f"0:{PASSWORD}")
        assert rc == 0
    finally:
        env.core._camera_factory = old
