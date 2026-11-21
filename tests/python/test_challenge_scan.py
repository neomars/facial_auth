# SPDX-License-Identifier: MIT
"""The scan loop and the policy with the head-turn test: Scanner.verify and Core.decide/verify.

The camera plays synthetic 3-D scenes (tests/python/synth3d.py) on a virtual clock, the engine
"detects" the exact landmarks of the scene and "recognises" an identity, so what is exercised is the
real tracking, the real state machine and the real scan loop.
"""
import pwd

import pytest

from facial_auth import core as core_mod
from facial_auth import protocol, v4l2
from facial_auth.config import Config
from facial_auth.const import Paths
from facial_auth.core import Core
from facial_auth.scan import Scanner
from facial_auth.store import FaceStore

from .fakes import template
from .synth3d import Scene, SceneCamera, SceneEngine, head_turns, tilted_sheet


@pytest.fixture
def cfg(tmp_path):
    paths = Paths(tmp_path)
    paths.config.parent.mkdir(parents=True)
    paths.config.write_text("[recognition]\nmax_fps = 60\nrequired_matches = 3\ntimeout = 6\n"
                            "[liveness]\nmode = challenge\nchallenge_timeout = 5\n")
    return Config.load(paths)


def verify(cfg, scene, poses, sequence="lr", who=None, die_after=None, cancelled=lambda: False):
    engine = SceneEngine()
    cam = SceneCamera(scene, poses, engine, who, die_after)
    events = []
    res = Scanner(engine, clock=lambda: cam.t, sleep=lambda s: None).verify(
        cfg, cam, template(1), None, 6.0, None, cancelled,
        lambda phase, **kw: events.append((phase, kw)), sequence)
    return res, events


# ---------------------------------------------------------------------------- the scan
def test_a_real_head_turning_as_asked_unlocks_and_the_user_was_told_what_to_do(cfg):
    res, events = verify(cfg, Scene("head", seed=3), head_turns(+1), "lr")
    assert res.ok, (res.reason, res.challenge)
    assert res.challenge["steps"] == 2 and res.challenge["sequence"] == "lr"
    told = ("challenge", {"seq": "lr", "timeout": "5.0"})
    assert told in events, "the PAM module must be told to show the instruction, and for how long"
    assert events.index(told) > events.index(("face", {}))


def test_a_photograph_never_unlocks_whatever_the_hand_does(cfg):
    for seed in range(3):
        res, _events = verify(cfg, Scene("flat", seed=10 + seed), tilted_sheet(seed), "rl" if seed % 2 else "lr")
        assert not res.ok and res.reason in ("spoof", "challenge"), (seed, res.reason)


def test_a_still_photograph_fails_with_the_challenge_reason_not_as_a_wrong_face(cfg):
    res, _events = verify(cfg, Scene("flat", seed=20), [(0.0, 0.0, 0.0)] * 6, "lr")
    assert not res.ok and res.reason == "challenge"


def test_the_wrong_order_does_not_unlock(cfg):
    res, _events = verify(cfg, Scene("head", seed=4), head_turns(-1), "lr")
    assert not res.ok and res.reason == "challenge"


def test_somebody_else_taking_over_during_the_turn_is_a_spoof(cfg):
    res, _events = verify(cfg, Scene("head", seed=5), head_turns(+1), "lr", who={i: 7 for i in range(20, 60)})
    assert not res.ok and res.reason == "spoof" and res.challenge["reason"] == "identity-changed"


def test_without_a_sequence_the_scan_is_the_plain_recognition(cfg):
    res, events = verify(cfg, Scene("flat", seed=21), [(0.0, 0.0, 0.0)] * 6, "")
    assert res.ok and not [e for e in events if e[0] == "challenge"]


def test_cancelling_during_the_challenge_stops_it(cfg):
    calls = {"n": 0}

    def cancelled():
        calls["n"] += 1
        return calls["n"] > 12

    res, _events = verify(cfg, Scene("head", seed=6), head_turns(+1), "lr", cancelled=cancelled)
    assert not res.ok and res.reason == "cancelled"


def test_an_unexpected_error_while_tracking_ends_the_scan_without_an_exception(cfg, monkeypatch):
    """A frame OpenCV cannot digest must cost the face login (the password remains), not the connection."""
    def boom(self, *args, **kwargs):
        raise RuntimeError("OpenCV could not track this frame")

    monkeypatch.setattr("facial_auth.challenge.HeadTurn.feed", boom)
    res, _events = verify(cfg, Scene("head", seed=8), head_turns(+1), "lr")
    assert not res.ok and res.reason == "error"
    assert res.challenge["reason"] == "error"


def test_a_camera_that_dies_during_the_challenge_is_a_camera_error(cfg):
    res, _events = verify(cfg, Scene("head", seed=7), head_turns(+1), "lr", die_after=14)
    assert not res.ok and res.reason == "camera-error"


# ------------------------------------------------------------------------------ the policy
@pytest.fixture
def core(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    paths.config.parent.mkdir(parents=True)
    paths.config.write_text("[services]\npolkit-1 = ir\nsudo = ir\nlightdm = ir\n"
                            "[recognition]\ntimeout = 6\nsequential_timeout = 4\n")
    store = FaceStore(paths)
    store.add_face(4242, "me", template(1, 4), "ir", "fake", "camera")
    cam = v4l2.CameraInfo("/dev/video2", "IR", "uvcvideo", "", ["GREY"], "ir", True)
    fake_user = pwd.struct_passwd(("alice", "x", 4242, 4242, "Alice", "/home/alice", "/bin/bash"))
    monkeypatch.setattr(core_mod.pwd, "getpwnam", lambda name: fake_user if name == "alice" else (_ for _ in ()).throw(KeyError(name)))
    c = Core(paths=paths, store=store, engine_loader=lambda: SceneEngine(), camera_factory=lambda i, k: None,
             camera_lister=lambda: [cam], lid_probe=lambda: False, models_probe=lambda: {"ok": True, "missing": []})
    c.trust.record(cam, True)   # camera verification is the subject of its own tests (test_ir_check.py)
    return c


def decide(core, service):
    return core.decide(protocol.Request(user="alice", service=service), peer_uid=0, peer_pid=1)


def test_the_module_is_told_to_wait_for_the_scan_and_the_head_turn(core):
    d = decide(core, "lightdm")
    assert d.accept and d.challenge and d.mode == "sequential"
    assert d.accept_timeout == pytest.approx(d.timeout + core.cfg["liveness", "challenge_timeout"])
    assert d.accept_timeout < 60, "the module refuses anything above a minute"


def test_terminals_keep_their_parallel_prompt_and_graphical_dialogs_become_sequential(core):
    assert decide(core, "sudo").mode == "parallel-tty"          # the module cancels the prompt to give instructions
    assert decide(core, "polkit-1").mode == "sequential"        # a dialog keeping its prompt cannot be interrupted


def test_basic_mode_changes_nothing_about_the_modes(core):
    core.cfg._v["liveness", "mode"] = "basic"
    d = decide(core, "polkit-1")
    assert d.mode == "parallel" and not d.challenge and d.accept_timeout == d.timeout


def test_failed_head_turns_count_towards_the_lock_out_and_it_grows(core):
    uid = 4242
    from facial_auth.scan import ScanResult
    decision = decide(core, "lightdm")
    for _ in range(core.cfg["security", "max_failures"]):
        core._record(decision, ScanResult(False, "spoof"))
    first = core.limiter.remaining(uid)
    assert first > 0
    core.limiter.reset(uid)                       # (a success would also clear the memory)
    assert core.limiter.remaining(uid) == 0
