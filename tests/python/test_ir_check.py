# SPDX-License-Identifier: MIT
"""An "infrared" camera is trusted only after it was shown a phone screen and did not see it."""
import json
import pwd

import numpy as np
import pytest

from facial_auth import core as core_mod
from facial_auth import irtest, protocol, v4l2
from facial_auth.const import Paths
from facial_auth.core import ApiError, Core
from facial_auth.store import FaceStore
from facial_auth.trust import CameraTrust

from .fakes import template

RNG = np.random.default_rng(7)


def scene(mean=90, patch=None, size=(120, 160)):
    f = np.clip(RNG.normal(mean, 6, size), 0, 255)
    if patch:
        y0, y1, x0, x1, value = patch
        f[y0:y1, x0:x1] = value
    return np.repeat(f.astype(np.uint8)[:, :, None], 3, axis=2)


def run(base, shown, nb=12, ns=30):
    acc = irtest.Accumulator()
    for _ in range(nb):
        acc.add_baseline(base())
    for _ in range(ns):
        acc.add_shown(shown())
    return acc.verdict()


# ------------------------------------------------------------------------------- judging
def test_a_camera_that_sees_the_white_screen_is_not_infrared():
    r = run(lambda: scene(90), lambda: scene(80, (20, 100, 30, 130, 255)))
    assert r["verdict"] == "sees-visible-light" and r["saturated"] > 0.3


def test_a_real_infrared_camera_sees_a_dark_rectangle_and_a_glint():
    r = run(lambda: scene(90), lambda: scene(35, (50, 54, 70, 76, 255)))      # the screen is black, a tiny reflection
    assert r["verdict"] == "infrared", r


def test_nothing_shown_proves_nothing():
    r = run(lambda: scene(90), lambda: scene(90))
    assert r["verdict"] == "inconclusive" and r["reason"] == "nothing-shown"


def test_a_camera_that_brightens_a_lot_without_saturating_still_sees_the_screen():
    r = run(lambda: scene(60), lambda: scene(130))
    assert r["verdict"] == "sees-visible-light"


def test_too_few_frames_is_inconclusive():
    assert irtest.Accumulator().verdict()["verdict"] == "inconclusive"


def test_a_strobing_emitter_does_not_make_the_dark_frames_count():
    acc = irtest.Accumulator(dark=6.0)
    for i in range(24):
        acc.add_baseline(scene(90) if i % 2 else scene(1))
    for i in range(40):
        acc.add_shown(scene(35, (50, 54, 70, 76, 255)) if i % 2 else scene(1))
    assert acc.verdict()["verdict"] == "infrared"


# ------------------------------------------------------------------------------ the registry
def cam(name="Integrated_Webcam_HD", cls="ir", formats=("GREY",), path="/dev/video2"):
    return v4l2.CameraInfo(path, name, "uvcvideo", "usb-0000:00:14.0-8", list(formats), cls, True)


def test_a_camera_is_recognised_across_reboots_and_its_colour_sibling_is_a_different_camera():
    ir, rgb = cam(), cam(cls="rgb", formats=("MJPG", "YUYV"), path="/dev/video0")
    assert ir.key() != rgb.key()
    assert cam(path="/dev/video5").key() == ir.key(), "the /dev/videoN number must not matter"


def test_the_outcome_is_kept_and_a_corrupt_file_is_just_unverified(tmp_path):
    trust = CameraTrust(Paths(tmp_path))
    assert trust.status(cam()) == "unknown" and not trust.is_verified(cam())
    trust.record(cam(), True, {"saturated": 0.0, "nested": {"dropped": 1}})
    assert trust.is_verified(cam()) and trust.status(cam()) == "verified"
    assert json.loads(trust.path.read_text())[cam().key()]["details"] == {"saturated": 0.0}
    trust.record(cam(), False, {})
    assert trust.status(cam()) == "failed" and not trust.is_verified(cam())
    trust.path.write_text("{ not json")
    assert trust.status(cam()) == "unknown"
    trust.path.write_text('["a list"]')
    assert not trust.is_verified(cam())


# ------------------------------------------------------------------------------- the policy
@pytest.fixture
def core(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    paths.config.parent.mkdir(parents=True)
    paths.config.write_text("[services]\nlightdm = ir\nsddm = any\n[liveness]\nmode = basic\n")
    store = FaceStore(paths)
    store.add_face(4242, "me", template(1, 4), "ir", "fake", "camera")
    fake_user = pwd.struct_passwd(("alice", "x", 4242, 4242, "Alice", "/home/alice", "/bin/bash"))
    monkeypatch.setattr(core_mod.pwd, "getpwnam", lambda name: fake_user if name == "alice" else (_ for _ in ()).throw(KeyError(name)))
    c = Core(paths=paths, store=store, camera_factory=lambda i, k: None, camera_lister=lambda: [cam()],
             lid_probe=lambda: False, models_probe=lambda: {"ok": True, "missing": []})
    return c


def decide(core, service):
    return core.decide(protocol.Request(user="alice", service=service), peer_uid=0, peer_pid=1)


def test_an_unverified_infrared_camera_is_not_accepted_for_a_service_that_needs_infrared(core):
    d = decide(core, "lightdm")
    assert not d.accept and d.reason == "camera-unverified"


def test_once_verified_it_is_accepted(core):
    core.trust.record(cam(), True)
    assert decide(core, "lightdm").accept


def test_a_camera_that_failed_the_check_stays_refused(core):
    core.trust.record(cam(), False)
    assert decide(core, "lightdm").reason == "camera-unverified"


def test_services_that_accept_any_camera_do_not_wait_for_the_check(core):
    assert decide(core, "sddm").accept


def test_the_check_can_be_switched_off_by_an_administrator_who_knows_the_risk(core):
    core.cfg._v["camera", "require_ir_check"] = False
    assert decide(core, "lightdm").accept


def test_status_tells_what_is_missing(core):
    assert core.status()["camera_ir_check"] == "unknown" and core.status()["require_ir_check"] is True
    core.trust.record(cam(), True)
    assert core.status()["camera_ir_check"] == "verified"


# ------------------------------------------------------------------------- the daemon's check
class Clocked:
    """A camera whose pictures depend on a virtual time that advances with every sleep()."""

    camera_class = "ir"
    name = "scripted"

    def __init__(self, picture):
        self.t, self.picture = 0.0, picture

    def open(self):
        pass

    def close(self):
        pass

    def read(self):
        return self.picture(self.t)

    def sleep(self, seconds):
        self.t += seconds


def check(core, picture, **kw):
    camera = Clocked(picture)
    core._camera_factory = lambda info, cls: camera
    return core.verify_infrared(lambda: False, kw.get("progress"), clock=lambda: camera.t, sleep=camera.sleep)


def test_a_camera_that_sees_the_screen_is_recorded_as_not_infrared(core):
    seen = []
    r = check(core, lambda t: scene(90) if t < 2 else scene(80, (20, 100, 30, 130, 255)), progress=lambda p, **kw: seen.append(p))
    assert r["verdict"] == "sees-visible-light" and r["camera"] == "Integrated_Webcam_HD"
    assert seen == ["baseline", "show-screen"]
    assert core.trust.status(cam()) == "failed"


def test_a_real_infrared_camera_is_recorded_as_verified(core):
    r = check(core, lambda t: scene(90) if t < 2 else scene(35, (50, 54, 70, 76, 255)))
    assert r["verdict"] == "infrared" and core.trust.is_verified(cam())


def test_an_inconclusive_check_records_nothing(core):
    r = check(core, lambda t: scene(90))
    assert r["verdict"] == "inconclusive" and core.trust.status(cam()) == "unknown"


def test_a_machine_without_an_infrared_camera_says_so(tmp_path):
    c = Core(paths=Paths(tmp_path), camera_lister=lambda: [cam(cls="rgb", formats=("MJPG",))],
             lid_probe=lambda: False, models_probe=lambda: {"ok": True, "missing": []})
    with pytest.raises(ApiError) as exc:
        c.verify_infrared(lambda: False)
    assert exc.value.code == "no-camera"


def test_the_check_can_be_cancelled(core):
    camera = Clocked(lambda t: scene(90))
    core._camera_factory = lambda info, cls: camera
    with pytest.raises(ApiError) as exc:
        core.verify_infrared(lambda: camera.t > 1, None, clock=lambda: camera.t, sleep=camera.sleep)
    assert exc.value.code == "cancelled"
