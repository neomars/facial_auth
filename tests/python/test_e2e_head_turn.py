# SPDX-License-Identifier: MIT
"""End to end, with the head-turn test: real pam_facial_auth.so + real pam_unix + the Python daemon.

Only the camera (a synthetic 3-D scene whose head turns, or a flat photograph moved by hand) and the
face engine are synthetic.  What these tests add to the unit tests is that the C module, the wire
protocol (`STATE phase=challenge seq=... timeout=...`), the socket server, the policy, the scan loop
and the head-turn state machine agree with one another, in both ways of interacting with the user.
"""
import os
import pwd
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from facial_auth import challenge, v4l2
from facial_auth.const import Paths
from facial_auth.core import Core
from facial_auth.server import PamServer
from facial_auth.store import FaceStore

from .fakes import template
from .synth3d import Scene, SceneCamera, SceneEngine, head_turns, tilted_sheet

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="needs root (PAM service, users)")

USER, PASSWORD = "faE2eHT", "pw-e2e-ht"
SERVICES = {"fa-e2e-ht": "sequential", "fa-e2e-ht-par": "parallel-tty"}
LR = "Slowly turn your head to your left, then to your right, then look at the screen."
RL = "Slowly turn your head to your right, then to your left, then look at the screen."


class Env:
    pass


@pytest.fixture(scope="module")
def env(build_dir, tmp_path_factory):
    e = Env()
    tmp = tmp_path_factory.mktemp("e2e-ht")
    os.chmod(tmp, 0o755)
    if subprocess.run(["id", USER], capture_output=True).returncode != 0:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", USER], check=True)
    subprocess.run(["chpasswd"], input=f"{USER}:{PASSWORD}\n", text=True, check=True)
    uid = pwd.getpwnam(USER).pw_uid

    paths = Paths(tmp / "root")
    paths.config.parent.mkdir(parents=True)
    paths.config.write_text(
        "[services]\n" + "".join(f"{s} = ir\n" for s in SERVICES)
        + "[interaction]\n" + "".join(f"{s} = {m}\n" for s, m in SERVICES.items())
        + "[liveness]\nmode = challenge\nchallenge_timeout = 8\n"
        "[recognition]\nsequential_timeout = 4\ntimeout = 4\nno_face_timeout = 2\n"
        "parallel_start_delay = 0.1\nrequired_matches = 3\nmax_fps = 30\n"
        "[security]\nmax_failures = 50\nlockout = 30\n")
    e.paths = paths
    store = FaceStore(paths)
    store.add_face(uid, "me", template(1, 4), "ir", "fake", "camera")

    e.engine = SceneEngine()
    e.show = {"scene": Scene("head", seed=3), "poses": head_turns(+1)}     # what the camera sees, per test
    e.cameras = []

    def make_camera(info, cls):
        cam = SceneCamera(e.show["scene"], e.show["poses"], e.engine)
        e.cameras.append(cam)
        return cam

    ir = v4l2.CameraInfo("/dev/video2", "IR", "uvcvideo", "", ["GREY"], "ir", True)
    e.core = Core(paths=paths, store=store, engine_loader=lambda: e.engine, camera_factory=make_camera,
                  camera_lister=lambda: [ir], lid_probe=lambda: False,
                  models_probe=lambda: {"ok": True, "missing": []})
    e.core.trust.record(ir, True)           # the verification itself is the subject of test_ir_check.py

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


@pytest.fixture(autouse=True)
def fresh(env, monkeypatch):
    env.cameras.clear()
    env.core.reload()                      # configuration (and limiter settings) as written in the file
    env.core.limiter.reset()
    env.sequence = "lr"
    monkeypatch.setattr(challenge, "draw_sequence", lambda: env.sequence)
    yield


def pam(env, service, *args, timeout=60):
    proc = subprocess.run([str(env.pamtest), *args, service, USER], capture_output=True, text=True,
                          timeout=timeout, env={"PATH": os.environ["PATH"], "LANGUAGE": "C"})
    ev = [(m.group(1), int(m.group(2)), m.group(3)) for m in
          (re.match(r"^(\S+) (-?\d+) ?(.*)$", ln) for ln in proc.stdout.splitlines()) if m]
    return proc.returncode, ev


def infos(ev):
    return [e[2] for e in ev if e[0] == "INFO"]


def count(ev, tag):
    return len([e for e in ev if e[0] == tag])


def watch(env, scene, poses, sequence="lr"):
    env.show.update(scene=scene, poses=poses)
    env.sequence = sequence


# ----------------------------------------------------------------- the login screen: sequential
def test_a_head_turning_as_asked_logs_in_without_any_password(env):
    watch(env, Scene("head", seed=3), head_turns(+1))
    rc, ev = pam(env, "fa-e2e-ht")
    assert rc == 0 and count(ev, "PROMPT") == 0, ev
    shown = infos(ev)
    assert shown.index("Looking for your face...") < shown.index(LR), shown
    assert env.cameras and env.cameras[0].i > 20, "the head turn was played"


def test_the_other_order_is_asked_and_accepted_the_same_way(env):
    watch(env, Scene("head", seed=4), head_turns(-1), "rl")
    rc, ev = pam(env, "fa-e2e-ht")
    assert rc == 0 and RL in infos(ev) and LR not in infos(ev), ev


def test_a_photograph_never_logs_in_and_the_password_still_works(env):
    watch(env, Scene("flat", seed=11), tilted_sheet(0))
    rc, ev = pam(env, "fa-e2e-ht", "--answer", f"0:{PASSWORD}")
    assert rc == 0 and count(ev, "PROMPT") == 1, "the face did not open the session: the password did"
    assert LR in infos(ev) and infos(ev)[-1] == "Face not recognized.", ev


def test_a_photograph_with_the_wrong_password_is_refused(env):
    watch(env, Scene("flat", seed=12), tilted_sheet(1))
    rc, _ev = pam(env, "fa-e2e-ht", "--answer", "0:wrong-password")
    assert rc != 0


def test_a_recording_played_in_the_wrong_order_is_refused(env):
    watch(env, Scene("head", seed=5), head_turns(-1), "lr")        # asked: left first; shown: right first
    rc, ev = pam(env, "fa-e2e-ht", "--answer", "0:wrong-password")
    assert rc != 0 and LR in infos(ev)


def test_failed_head_turns_lock_the_face_path_out_but_never_the_password(env):
    env.core.limiter.configure(2, 60.0, 30.0)
    watch(env, Scene("flat", seed=13), tilted_sheet(2))
    for _ in range(2):
        rc, ev = pam(env, "fa-e2e-ht", "--answer", f"0:{PASSWORD}")
        assert rc == 0 and LR in infos(ev)
    t0 = time.monotonic()
    rc, ev = pam(env, "fa-e2e-ht", "--answer", f"0:{PASSWORD}")
    assert rc == 0, "the password is never locked"
    assert "Looking for your face..." not in infos(ev) and time.monotonic() - t0 < 2.5, \
        "the face path is locked out: no scan, the password prompt comes at once"


# ------------------------------------------------------ sudo / su on a terminal: parallel-tty
def test_in_a_terminal_the_pending_prompt_gives_way_to_the_instruction_then_the_face_wins(env):
    watch(env, Scene("head", seed=6), head_turns(+1))
    rc, ev = pam(env, "fa-e2e-ht-par", "--post-sleep", "200")
    assert rc == 0, ev
    assert count(ev, "PROMPT") == 1 and count(ev, "CONV-CANCELLED") == 1
    shown = infos(ev)
    assert LR in shown and "Face recognized." in shown and shown.index(LR) < shown.index("Face recognized.")


def test_in_a_terminal_a_photograph_leaves_a_fresh_password_prompt(env):
    watch(env, Scene("flat", seed=14), tilted_sheet(3))
    rc, ev = pam(env, "fa-e2e-ht-par", "--answer", "30000:never-typed", "--answer", f"0:{PASSWORD}")
    assert rc == 0, ev
    assert count(ev, "CONV-CANCELLED") == 1 and count(ev, "PROMPT") == 2
    assert infos(ev)[-2:] == [LR, "Face not recognized."]
