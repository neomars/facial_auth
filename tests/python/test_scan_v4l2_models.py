# SPDX-License-Identifier: MIT
import errno
import hashlib
import struct
import threading
import time

import numpy as np
import pytest

from facial_auth import models, v4l2
from facial_auth.config import Config
from facial_auth.const import Paths
from facial_auth.ratelimit import FailureLimiter
from facial_auth.scan import (EnrollError, Scanner, analyze, decode_image, embed_images,
                              encode_jpeg)

from .fakes import FakeEngine, ScriptedCamera, face_frame, template

CFG = Config.defaults()


def scanner():
    return Scanner(FakeEngine())


def run(frames, identity=1, timeout=3.0, others=None, no_face_timeout=None, cancelled=None,
        cfg=CFG, fail_first=0, progress=None):
    cam = ScriptedCamera(frames, fail_first=fail_first)
    res = scanner().verify(cfg, cam, template(identity), others, timeout, no_face_timeout,
                           cancelled or (lambda: False), progress)
    return res, cam


# ------------------------------------------------------------- verification
def test_owner_is_recognised_after_required_consecutive_frames():
    seen = []
    res, cam = run(lambda i: face_frame(1), progress=seen.append)
    assert res.ok and res.score > 0.9
    assert res.frames >= CFG["recognition", "required_matches"]
    assert seen == ["face"], "progress is reported once"


def test_a_stranger_is_rejected_until_timeout():
    res, _ = run(lambda i: face_frame(2), timeout=0.6)
    assert not res.ok and res.reason == "mismatch" and res.seen_face


def test_empty_scene_reports_no_face_and_gives_up_early_when_asked():
    start = time.monotonic()
    res, _ = run(lambda i: face_frame(None), timeout=5.0, no_face_timeout=0.4)
    assert not res.ok and res.reason == "no-face"
    assert time.monotonic() - start < 1.5, "sequential mode must not keep the password hostage"


def test_one_lucky_frame_is_not_enough():
    # owner only every 3rd frame: the streak keeps resetting -> never accepted
    res, _ = run(lambda i: face_frame(1 if i % 3 == 0 else None), timeout=0.8)
    assert not res.ok


def test_look_alike_must_lose_against_the_other_account():
    """Bob's face is almost Alice's: the closer enrolled account wins."""
    alice, bob = template(1), template(1)       # identical embeddings = worst case twin
    res = scanner().verify(CFG, ScriptedCamera(lambda i: face_frame(1)), alice, bob, 0.6)
    assert not res.ok, "a face that matches another account as well as the target is ambiguous"


def test_threshold_from_config_is_honoured():
    strict = Config._build(__import__("configparser").ConfigParser())
    strict._v[("recognition", "threshold")] = 0.999999
    res, _ = run(lambda i: face_frame(1), timeout=0.5, cfg=strict)
    assert not res.ok


def test_frozen_camera_feed_is_flagged_as_spoof():
    frame = face_frame(1, still=True)
    res, _ = run(lambda i: frame.copy(), timeout=2.0)
    assert not res.ok and res.reason == "spoof"


def test_a_face_that_is_too_small_is_ignored():
    res, _ = run(lambda i: face_frame(1, size=40), timeout=0.5)
    assert not res.ok


def test_two_people_at_the_camera_is_ambiguous():
    """Two comparable faces side by side: we cannot tell who is authenticating."""
    def two(i):
        f = face_frame(None)
        f[70:170, 30:130] = 110          # owner...
        f[70:170, 190:290] = 110         # ...and someone of the same size next to them
        return f
    assert len(FakeEngine().detect(two(0))) == 2, "fixture sanity"
    res, _ = run(two, timeout=0.5)
    assert not res.ok, "an ambiguous frame must never authenticate"


def test_a_small_bystander_does_not_prevent_the_owner():
    def with_bystander(i):
        f = face_frame(1)
        f[5:45, 5:45] = 110              # tiny face far in the background
        return f
    res, _ = run(with_bystander, timeout=2.0)
    assert res.ok


def test_dark_frames_do_not_match():
    res, _ = run(lambda i: np.zeros((240, 320, 3), np.uint8), timeout=0.4)
    assert not res.ok and res.reason == "no-face"


def test_cancellation_stops_within_a_frame():
    flag = threading.Event()
    threading.Timer(0.2, flag.set).start()
    start = time.monotonic()
    res, _ = run(lambda i: face_frame(2), timeout=10, cancelled=flag.is_set)
    assert res.reason == "cancelled" and time.monotonic() - start < 1.0


def test_camera_that_never_delivers_is_an_error_not_a_hang():
    res, _ = run(lambda i: face_frame(1), timeout=10, fail_first=10_000)
    assert not res.ok and res.reason == "camera-error"


# -------------------------------------------------------------- enrollment
def test_enrollment_embeds_good_photos_and_explains_bad_ones():
    eng = FakeEngine()
    good = [face_frame(3) for _ in range(4)]
    assert len(embed_images(eng, good, 90)) == 4
    with pytest.raises(EnrollError) as e:
        embed_images(eng, [face_frame(3), face_frame(None), face_frame(3, size=30)], 90)
    assert e.value.code == "not-enough-faces" and e.value.details == {1: "no-face", 2: "too-small"}


def test_enrollment_refuses_a_mix_of_two_people():
    eng = FakeEngine()
    with pytest.raises(EnrollError) as e:
        embed_images(eng, [face_frame(3), face_frame(3), face_frame(4), face_frame(4), face_frame(5)], 90)
    assert e.value.code == "inconsistent"


def test_analysis_gives_actionable_hints():
    eng = FakeEngine()
    assert analyze(eng, face_frame(None), 90).hints == ["no-face"]
    far = analyze(eng, face_frame(1, size=40), 90)
    assert "too-small" in far.hints and not far.ok
    good = analyze(eng, face_frame(1), 90)
    assert good.ok and good.box and good.faces == 1


def test_image_decoding_is_bounded():
    img = face_frame(1)
    assert decode_image(encode_jpeg(img)).shape[:2] == img.shape[:2]
    for bad in (b"", b"not an image", b"\xff\xd8\xff" + b"0" * 100, b"x" * (9 * 1024 * 1024)):
        with pytest.raises(ValueError):
            decode_image(bad)
    big = np.zeros((3000, 4000, 3), np.uint8)
    assert max(decode_image(encode_jpeg(big)).shape[:2]) <= 1280


# ------------------------------------------------------------- rate limiter
def test_failed_faces_lock_the_face_path_then_expire():
    t = [0.0]
    lim = FailureLimiter(3, 60, 30, clock=lambda: t[0])
    assert not lim.record_failure(1000) and not lim.record_failure(1000)
    assert lim.record_failure(1000) and lim.remaining(1000) == 30
    assert lim.remaining(1001) == 0, "other accounts are unaffected"
    t[0] = 31
    assert lim.remaining(1000) == 0
    lim.record_failure(1000); t[0] = 200; lim.record_failure(1000)
    assert lim.remaining(1000) == 0, "old failures leave the window"
    lim.record_success(1000)


# ------------------------------------------------------------------- v4l2
def fake_ioctl_factory(table):
    """table: path -> (driver, card, caps, [fourcc...])"""
    state = {}

    def ioctl(fd, req, buf, mutate=True):
        path = state[fd]
        driver, card, caps, fmts = table[path]
        if req == v4l2.VIDIOC_QUERYCAP:
            # capabilities advertises DEVICE_CAPS, device_caps is the per-node truth
            struct.pack_into("<16s32s32sIII", buf, 0, driver.encode(), card.encode(), b"usb-1",
                             0x060800, 0x80000000 | caps, caps)
            return 0
        if req == v4l2.VIDIOC_ENUM_FMT:
            idx = struct.unpack_from("<I", buf, 0)[0]
            if idx >= len(fmts):
                raise OSError(errno.EINVAL, "end")
            struct.pack_into("<III32sI", buf, 0, idx, 1, 0, b"", struct.unpack("<I", fmts[idx].encode().ljust(4))[0])
            return 0
        raise OSError(errno.ENOTTY, "?")
    return ioctl, state


def test_camera_discovery_classifies_rgb_ir_metadata_and_virtual(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    paths.dev.mkdir(parents=True)
    CAP = v4l2.V4L2_CAP_VIDEO_CAPTURE | v4l2.V4L2_CAP_STREAMING
    table = {
        str(paths.dev / "video0"): ("uvcvideo", "Integrated Camera: Integrated C", CAP, ["MJPG", "YUYV"]),
        str(paths.dev / "video1"): ("uvcvideo", "Integrated Camera: Integrated C", 0x00800000, []),   # metadata node
        str(paths.dev / "video2"): ("uvcvideo", "Integrated Camera: Integrated I", CAP, ["GREY"]),
        str(paths.dev / "video3"): ("v4l2 loopback", "OBS Virtual Camera", CAP, ["YUYV"]),
        str(paths.dev / "video10"): ("uvcvideo", "Chicony IR Camera", CAP, ["YUYV"]),
    }
    for p in table:
        open(p, "w").close()
    ioctl, state = fake_ioctl_factory(table)
    real_open = v4l2.os.open

    def fake_open(path, flags, *a):
        fd = real_open(path, v4l2.os.O_RDONLY)
        state[fd] = str(path)
        return fd
    monkeypatch.setattr(v4l2.os, "open", fake_open)

    cams = v4l2.discover(paths, ioctl)
    by = {c.path.rsplit("/", 1)[1]: c for c in cams}
    assert [c.path.rsplit("/", 1)[1] for c in cams] == ["video0", "video1", "video2", "video3", "video10"], "numeric order"
    assert by["video0"].camera_class == "rgb" and by["video0"].usable
    assert not by["video1"].usable, "metadata nodes are ignored"
    assert by["video2"].camera_class == "ir" and by["video2"].formats == ["GREY"]
    assert by["video3"].virtual and by["video3"].usable
    assert by["video10"].camera_class == "ir", "the name says IR even though it streams YUYV"

    pick = lambda **kw: (v4l2.select(cams, **kw) or v4l2.CameraInfo("none")).path.rsplit("/", 1)[-1]
    assert pick() == "video2", "IR first by default"
    assert pick(preference="rgb-first") == "video0"
    assert pick(need_class="rgb") == "video0"
    assert pick(preference="ir-only", need_class="rgb") == "none"
    assert pick(device=str(paths.dev / "video0")) == "video0"
    assert pick(device=str(paths.dev / "video3")) == "none", "virtual cameras refused by default"
    assert v4l2.select(cams, device=str(paths.dev / "video3"), allow_virtual=True).virtual
    assert pick(force_class="rgb", device=str(paths.dev / "video2"), need_class="ir") == "none"


# ------------------------------------------------------------------ models
def test_required_models_follow_the_opencv_version():
    assert models.required("4.6.0")[0] is models.YUNET_2022, "Ubuntu 24.04"
    assert models.required("4.5.4")[0] is models.YUNET_2022, "Ubuntu 22.04"
    assert models.required("4.8.0")[0] is models.YUNET_2023
    assert models.required("4.10.0")[0] is models.YUNET_2023
    assert models.required("4.6.0")[1] is models.SFACE
    for spec in models.ALL:
        assert len(spec.sha256) == 64 and spec.size > 0 and all(u.startswith("https://") for u in spec.urls)


class FakeResponse:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, n):
        chunk, self.pos = self.data[self.pos:self.pos + n], self.pos + n
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_download_is_verified_and_falls_back_to_the_next_mirror(tmp_path):
    payload = b"onnx-bytes" * 100
    spec = models.ModelSpec("t", "t.onnx", hashlib.sha256(payload).hexdigest(), len(payload),
                            ("https://bad.example/t", "https://good.example/t"), "MIT", "detector")
    served = {"https://bad.example/t": b"corrupted!" * 100, "https://good.example/t": payload}
    opener = lambda url, timeout=0: FakeResponse(served[url])
    out = models.fetch(spec, tmp_path / "m", opener=opener)
    assert out.read_bytes() == payload and models.verify(spec, out)
    assert not [p for p in (tmp_path / "m").iterdir() if p != out], "no temp files left"


def test_tampered_download_is_never_installed(tmp_path):
    spec = models.ModelSpec("t", "t.onnx", "0" * 64, 10, ("https://x.example/t",), "MIT", "detector")
    with pytest.raises(RuntimeError):
        models.fetch(spec, tmp_path / "m", opener=lambda url, timeout=0: FakeResponse(b"0123456789"))
    assert not (tmp_path / "m" / "t.onnx").exists()


def test_oversized_download_is_aborted(tmp_path):
    spec = models.ModelSpec("t", "t.onnx", "0" * 64, 10, ("https://x.example/t",), "MIT", "detector")
    with pytest.raises(RuntimeError):
        models.fetch(spec, tmp_path / "m", opener=lambda url, timeout=0: FakeResponse(b"A" * (3 << 20)))
