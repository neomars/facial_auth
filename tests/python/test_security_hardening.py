# SPDX-License-Identifier: MIT
"""Regression tests for the findings of the security audit of v1.2.0.

Each section names the weakness it closes, what an attacker could do, and what has to stay true.
The scenarios are the ones that were reproduced against the code before the fix.
"""
import os
import random
import struct
import threading
import time

import numpy as np
import pytest

from facial_auth import scan
from facial_auth.scan import decode_image, encode_jpeg

from .fakes import face_frame


# ------------------------------------------------------------------ images
# AnalyzeImage / AddFace hand bytes written by *any* local user to OpenCV, whose Ubuntu build decodes
# a dozen formats (GDAL, GDCM, OpenEXR, JPEG 2000...).  Only JPEG and PNG are accepted, and the size
# is read from the header before anything is allocated.
def png_header(width, height):
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\0\0\0\0"


def jpeg_header(width, height, *, before=b""):
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + before + sof + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"


NOT_JPEG_NOR_PNG = {
    "Windows bitmap": b"BM" + b"\0" * 200,
    "WebP": b"RIFF\x24\0\0\0WEBPVP8 " + b"\0" * 200,
    "TIFF (little endian)": b"II*\0" + b"\0" * 200,
    "TIFF (big endian)": b"MM\0*" + b"\0" * 200,
    "JPEG 2000": b"\0\0\0\x0cjP  \r\n\x87\n" + b"\0" * 200,
    "JPEG 2000 codestream": b"\xff\x4f\xff\x51" + b"\0" * 200,
    "PNM": b"P6\n8 8\n255\n" + b"\0" * 200,
    "PAM": b"P7\nWIDTH 8\nHEIGHT 8\n" + b"\0" * 200,
    "PFM": b"PF\n8 8\n-1.0\n" + b"\0" * 200,
    "Radiance HDR": b"#?RADIANCE\nFORMAT=32-bit_rle_rgbe\n\n-Y 8 +X 8\n" + b"\0" * 200,
    "Sun Raster": b"\x59\xa6\x6a\x95" + b"\0" * 200,
    "OpenEXR": b"v/1\x01\x02\0\0\0" + b"\0" * 200,
    "DICOM (GDCM)": b"\0" * 128 + b"DICM" + b"\0" * 200,
    "NITF (GDAL)": b"NITF02.10" + b"\0" * 200,
    "HDF5": b"\x89HDF\r\n\x1a\n" + b"\0" * 200,
    "GIF": b"GIF89a" + b"\0" * 50,
    "SVG": b"<svg xmlns='http://www.w3.org/2000/svg'/>",
}


@pytest.fixture
def opencv_must_not_decode(monkeypatch):
    """Fails the test if the bytes get as far as OpenCV."""
    import cv2

    def forbidden(*_a, **_k):
        raise AssertionError("cv2.imdecode was reached")
    monkeypatch.setattr(cv2, "imdecode", forbidden)


@pytest.mark.parametrize("name", sorted(NOT_JPEG_NOR_PNG))
def test_only_jpeg_and_png_reach_opencv(name, opencv_must_not_decode):
    with pytest.raises(ValueError, match="JPEG and PNG"):
        decode_image(NOT_JPEG_NOR_PNG[name])


def test_a_gdal_vrt_hidden_behind_the_dted_signature_never_reaches_opencv(opencv_must_not_decode):
    """GDAL's VRT driver reads any local file named in an XML document: OpenCV hands a blob to GDAL
    when "DTED" sits at offset 140, so the blob must be turned away before OpenCV sees it."""
    head = b'<VRTDataset rasterXSize="4" rasterYSize="4"><!--'
    blob = head + b"x" * (140 - len(head)) + b"DTED-->" + b"<VRTRasterBand/></VRTDataset>"
    assert blob[140:144] == b"DTED"
    with pytest.raises(ValueError, match="JPEG and PNG"):
        decode_image(blob)


def test_real_encoders_of_other_formats_are_refused():
    cv2 = pytest.importorskip("cv2")
    img = (np.random.RandomState(1).rand(32, 32, 3) * 255).astype(np.uint8)
    refused = 0
    for ext in (".bmp", ".webp", ".tif", ".jp2", ".ppm", ".pam", ".ras"):
        try:
            ok, buf = cv2.imencode(ext, img)
        except cv2.error:                       # an OpenCV built without this codec
            continue
        if ok:
            refused += 1
            with pytest.raises(ValueError, match="JPEG and PNG"):
                decode_image(buf.tobytes())
    assert refused >= 3, "this OpenCV can encode almost nothing: the test proves nothing"
    ok, png = cv2.imencode(".png", img)
    assert ok and decode_image(png.tobytes()).shape == (32, 32, 3)


def test_the_size_is_read_from_the_header_and_refused_before_decoding(opencv_must_not_decode):
    assert scan.MAX_IMAGE_PIXELS <= 32 * 1024 * 1024
    for blob in (png_header(20000, 20000), jpeg_header(20000, 20000)):
        with pytest.raises(ValueError, match="too large"):
            decode_image(blob)
    for blob in (png_header(1 << 24, 1), jpeg_header(65535, 1)):      # absurdly wide, tiny in pixels
        with pytest.raises(ValueError, match="too large"):
            decode_image(blob)
    for blob in (png_header(0, 10), png_header(10, 0), jpeg_header(0, 10)):
        with pytest.raises(ValueError):
            decode_image(blob)


def test_the_header_reader_finds_the_size_behind_metadata():
    exif = b"\xff\xe1" + struct.pack(">H", 2 + 5000) + b"Exif\0" + b"\0" * 4995
    assert scan.declared_size(jpeg_header(640, 480, before=exif)) == (640, 480)
    assert scan.declared_size(png_header(7, 9)) == (7, 9)
    for broken in (b"", b"\xff\xd8", b"\xff\xd8\xff", b"\xff\xd8\xff\xe1\x00\x01", b"\x89PNG\r\n\x1a\n",
                   b"\xff\xd8" + b"\xff\xe0\x00\x02" * 3,                # no frame header
                   b"\xff\xd8\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"):   # scan before any frame header
        assert scan.declared_size(broken) is None


def test_a_normal_phone_photo_still_goes_through():
    big = np.zeros((3000, 4000, 3), np.uint8)                       # 12 Mpx
    assert max(decode_image(encode_jpeg(big)).shape[:2]) <= scan.MAX_IMAGE_SIDE


def test_a_decoder_that_raises_becomes_a_refusal_not_an_internal_error(monkeypatch):
    """cv2.error used to escape as an "internal error" with OpenCV's text and a traceback."""
    import cv2

    def boom(*_a, **_k):
        raise cv2.error("loadsave.cpp:77: error: (-215:Assertion failed)")
    monkeypatch.setattr(cv2, "imdecode", boom)
    with pytest.raises(ValueError, match="not a readable image"):
        decode_image(encode_jpeg(face_frame(1)))


def test_decoding_is_serialised(monkeypatch):
    """Six simultaneous large decodes were measured at twice the unit's memory limit."""
    import cv2
    real = cv2.imdecode
    state = {"now": 0, "peak": 0}
    lock = threading.Lock()

    def slow(*a, **k):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.05)
        try:
            return real(*a, **k)
        finally:
            with lock:
                state["now"] -= 1
    monkeypatch.setattr(cv2, "imdecode", slow)
    jpeg = encode_jpeg(face_frame(1))
    threads = [threading.Thread(target=decode_image, args=(jpeg,)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert 1 <= state["peak"] <= 2


def fds():
    return len(os.listdir("/proc/self/fd"))


def test_malformed_images_cannot_leak_descriptors():
    """OpenCV 4.6's Radiance HDR decoder leaked a file descriptor on most corrupted inputs: about a
    thousand requests exhausted the daemon's descriptors and silenced the PAM socket."""
    cv2 = pytest.importorskip("cv2")
    ok, hdr = cv2.imencode(".hdr", np.zeros((16, 16, 3), np.float32))
    assert ok
    seed, rng = hdr.tobytes(), random.Random(2)
    before = fds()
    for _ in range(400):
        data = bytearray(seed)
        for _ in range(rng.randint(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        with pytest.raises(ValueError):
            decode_image(bytes(data))
    assert fds() - before <= 3


# --------------------------------------------------------- configuration
# SetConfig is guarded by a whitelist: security.*, camera.emitter_command and camera.allow_virtual cannot
# be changed through D-Bus.  A *service name* used to be written into settings.conf as it came, so a name
# made of several lines added whole sections to the file, which is read last and over every other layer.
from facial_auth import protocol  # noqa: E402
from facial_auth.config import Config, validate_update, write_settings  # noqa: E402
from facial_auth.const import Paths  # noqa: E402

HOSTILE_NAMES = [
    "x = 1\n[security]\nallow_root = true\ny",
    "x\n[camera]\nemitter_command = /bin/true\ny",
    "a=b", "a:b", "a b", "a\tb", "[security]", "", ".hidden", "-dash", "@at", "a" * 65,
    "café", "a\x00b", "a\x1b[2J", "a/b", "../etc",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
@pytest.mark.parametrize("section,value", [("services", "off"), ("interaction", "sequential")])
def test_service_names_are_validated(section, value, name):
    with pytest.raises(ValueError):
        validate_update({f"{section}.{name}": value})
    with pytest.raises(ValueError):                    # and again at the point where the file is written
        write_settings(Paths("/nonexistent-never-written").settings, {(section, name): value})


@pytest.mark.parametrize("name", ["sudo", "sudo-i", "gdm-password", "polkit-1", "cinnamon-screensaver",
                                  "lightdm-greeter", "my_app", "app.v2", "user@host", "Xdm", "a" * 64])
def test_real_service_names_are_still_accepted(name):
    assert validate_update({f"services.{name}": "ir"}) == {("services", name): "ir"}


def test_a_hostile_service_name_writes_nothing(tmp_path):
    p = Paths(tmp_path)
    with pytest.raises(ValueError):
        write_settings(p.settings, {("recognition", "timeout"): "5.0",
                                    ("services", "x = 1\n[security]\nallow_root = true\ny"): "off"})
    assert not p.settings.exists(), "a refused change set is refused as a whole"
    c = Config.load(p)
    assert c["security", "allow_root"] is False


def test_settings_file_cannot_carry_what_the_whitelist_forbids(tmp_path):
    """The file belongs to the unprivileged daemon user and is read last: whatever it holds, the keys
    SetConfig may not change cannot take effect from it.  The root-owned layers can still set them."""
    p = Paths(tmp_path)
    p.state.mkdir(parents=True)
    p.settings.write_text(
        "[security]\nallow_root = true\nabort_if_remote = false\nlockout = 5\nmax_failures = 100\n"
        "[camera]\nemitter_command = /usr/bin/touch /tmp/x\nemitter_stop_command = /bin/true\n"
        "allow_virtual = true\nrequire_ir_check = false\n"
        "[recognition]\nthreshold = 0.5\n[services]\nsudo = any\nbad name = ir\n")
    c = Config.load(p)
    assert c["security", "allow_root"] is False and c["security", "abort_if_remote"] is True
    assert c["security", "lockout"] == 60.0 and c["security", "max_failures"] == 5
    assert c["camera", "emitter_command"] == "" and c["camera", "emitter_stop_command"] == ""
    assert c["camera", "allow_virtual"] is False
    assert c["camera", "require_ir_check"] is False, "this one *is* a GUI setting (camera.require_ir_check)"
    assert c["recognition", "threshold"] == 0.5 and c.service("sudo").camera_class == "any"
    ignored = " ".join(c.warnings)
    for key in ("allow_root", "emitter_command", "allow_virtual", "lockout", "bad name"):
        assert key in ignored, f"{key} was dropped silently"
    # the same keys in the root-owned file are honoured
    p.config.parent.mkdir(parents=True)
    p.config.write_text("[security]\nallow_root = true\n[camera]\nemitter_command = /usr/bin/true\n")
    p.settings.unlink()
    c = Config.load(p)
    assert c["security", "allow_root"] is True and c["camera", "emitter_command"] == "/usr/bin/true"


def test_a_damaged_settings_file_does_not_block_new_changes(tmp_path):
    p = Paths(tmp_path)
    p.state.mkdir(parents=True)
    p.settings.write_text("[recognition]\nthreshold = 0.5\n[recognition]\nthreshold = 0.6\n")   # duplicate section
    write_settings(p.settings, {("recognition", "timeout"): "5.0"})
    assert Config.load(p)["recognition", "timeout"] == 5.0


def test_values_written_to_the_settings_file_are_one_clean_line(tmp_path):
    p = Paths(tmp_path)
    for bad in ("a\nb", "a\x00b", "a" * 300):
        with pytest.raises(ValueError):
            validate_update({"camera.device": bad})
    assert validate_update({"camera.device": "/dev/video2"}) == {("camera", "device"): "/dev/video2"}
    with pytest.raises(ValueError):
        write_settings(p.settings, {("camera", "device"): "x\n[security]\nallow_root = true"})


# -------------------------------------------------------------- protocol
# service, tty, rhost and ruser went into the journal unchecked: any local user can talk to the 0666
# socket and used to be able to write lines that look like the daemon's own.
@pytest.mark.parametrize("field", ["service", "tty", "rhost", "ruser", "user"])
@pytest.mark.parametrize("value", ["x\nINFO facial-authd: verify ok=True", "a\rb", "a\x1b[31m", "a\x00b",
                                   "a\x7fb", "a b", "a\u0085b"])
def test_control_characters_are_refused_in_every_field(field, value):
    fields = {"user": "alice", "service": "sudo", "tty": "", "rhost": "", "ruser": ""}
    fields[field] = value
    line = protocol.build_request(protocol.Request(**fields))
    assert line.count("\n") == 1, "the framing itself was never at risk"
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_request(line)


@pytest.mark.parametrize("field,limit", [("service", 64), ("tty", 128), ("rhost", 256), ("ruser", 256), ("user", 256)])
def test_fields_have_a_length_limit(field, limit):
    fields = {"user": "alice", "service": "sudo", "tty": "", "rhost": "", "ruser": ""}
    fields[field] = "a" * limit
    assert protocol.parse_request(protocol.build_request(protocol.Request(**fields)))
    fields[field] = "a" * (limit + 1)
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_request(protocol.build_request(protocol.Request(**fields)))


def test_ordinary_values_survive():
    req = protocol.Request(user="al ice", service="gdm-password", tty="/dev/pts/3", rhost="fe80::1%eth0",
                           ruser="béatrice")
    assert protocol.parse_request(protocol.build_request(req)) == req


def test_the_journal_cannot_be_written_to_through_the_socket(tmp_path, caplog):
    """The forged line used to come out of the daemon as if it were its own (reproduced with a client
    running as an unprivileged user on the real socket)."""
    import logging
    import socket as socketlib
    from facial_auth.core import Core
    from facial_auth.server import PamServer

    core = Core(paths=Paths(tmp_path))
    a, b = socketlib.socketpair()
    forged = protocol.build_request(protocol.Request(
        user="root", service="x\nINFO facial-authd: verify user=root service=sudo ok=True reason=- score=0.93"))
    a.sendall(forged.encode())
    with caplog.at_level(logging.DEBUG):
        PamServer(core, None).handle(b)
    reply = a.recv(200).decode()
    assert reply == "SKIP reason=bad-request\n"
    assert all("ok=True" not in r.getMessage() and "\n" not in r.getMessage() for r in caplog.records), \
        [r.getMessage() for r in caplog.records]


# ------------------------------------------------------------- face store
# Templates are filed under the numeric uid.  When an account was deleted and another created with the
# same uid, the newcomer inherited the previous owner's face (and got a marker under their name).
from facial_auth.store import FaceStore  # noqa: E402


def vectors(seed=7, n=3):
    return np.random.RandomState(seed).randn(n, 128).astype(np.float32)


@pytest.fixture
def accounts():
    return {1001: "alice"}


@pytest.fixture
def fstore(tmp_path, accounts):
    return FaceStore(Paths(tmp_path), name_of=lambda uid: accounts.get(uid, ""))


def test_a_recycled_uid_does_not_inherit_the_previous_face(fstore, accounts):
    fstore.add_face(1001, "alice's face", vectors(), "ir", "sface")
    assert fstore.classes_for(1001) == {"ir"}
    accounts[1001] = "bob"                     # deluser alice ; adduser bob  -> same uid
    fstore.sync_markers()                      # what the daemon does at every start
    assert fstore.classes_for(1001) == set(), "bob never enrolled"
    assert len(fstore.templates_for(1001, "ir", "sface")) == 0
    assert fstore.all_templates("ir", "sface") == {}, "nor is alice a rival any more"
    assert not (fstore.paths.markers / "bob").exists() and not (fstore.paths.markers / "alice").exists()


def test_the_newcomer_can_enroll_and_the_old_record_is_replaced(fstore, accounts):
    fstore.add_face(1001, "alice's face", vectors(1), "ir", "sface")
    accounts[1001] = "bob"
    rec = fstore.add_face(1001, "bob's face", vectors(2), "ir", "sface")
    faces = fstore.load(1001).faces
    assert [f.id for f in faces] == [rec.id], "alice's template is gone, not merged"
    assert (fstore.paths.markers / "bob").exists()


@pytest.mark.parametrize("now", ["", "carol"])        # account deleted / account renamed
def test_a_deleted_or_renamed_account_loses_its_faces_until_they_are_enrolled_again(fstore, accounts, now):
    fstore.add_face(1001, "face", vectors(), "ir", "sface")
    accounts.pop(1001)
    if now:
        accounts[1001] = now
    assert fstore.classes_for(1001) == set()
    accounts[1001] = "alice"                              # the directory answers again (or the rename is undone)
    assert fstore.classes_for(1001) == {"ir"}, "nothing was deleted behind anybody's back"


def test_a_lookup_failure_never_deletes_anything(fstore, accounts):
    """When the user database cannot be reached the name comes back empty: faces are not used (the
    password works), and nothing is removed - only an administrator's command does that."""
    fstore.add_face(1001, "face", vectors(), "ir", "sface")
    saved = dict(accounts)
    accounts.clear()
    fstore.sync_markers()
    assert fstore.classes_for(1001) == set()
    assert (fstore.paths.templates / "1001" / "faces.json").exists()
    accounts.update(saved)
    fstore.sync_markers()
    assert fstore.classes_for(1001) == {"ir"} and (fstore.paths.markers / "alice").exists()


@pytest.mark.parametrize("content", ["[]", "null", "42", '"text"', '{"version": 1, "faces": 7}', "{"])
def test_a_face_file_that_is_not_what_it_should_be_means_no_faces(fstore, content):
    fstore.add_face(1001, "face", vectors(), "ir", "sface")
    (fstore.paths.templates / "1001" / "faces.json").write_text(content)
    assert fstore.classes_for(1001) == set()
    assert fstore.load(1001).faces == []
    assert [o for o in fstore.orphans() if o.uid == 1001] == []


def test_records_written_before_the_name_was_kept_are_still_read(fstore):
    import json
    fstore.add_face(1001, "face", vectors(), "ir", "sface")
    f = fstore.paths.templates / "1001" / "faces.json"
    data = json.loads(f.read_text())
    del data["username"]
    f.write_text(json.dumps(data))
    assert fstore.classes_for(1001) == {"ir"}


def test_orphans_are_listed_and_purged_without_touching_the_others(fstore, accounts):
    accounts.update({1002: "dave", 1003: "erin"})
    for uid in (1001, 1002, 1003):
        fstore.add_face(uid, "face", vectors(uid), "ir", "sface")
    del accounts[1001]                                    # deleted
    accounts[1003] = "erin2"                              # renamed
    found = {(o.uid, o.recorded, o.current) for o in fstore.orphans()}
    assert found == {(1001, "alice", ""), (1003, "erin", "erin2")}
    assert fstore.classes_for(1002) == {"ir"}
    removed = fstore.purge_orphans()
    assert {o.uid for o in removed} == {1001, 1003}
    assert sorted(p.name for p in fstore.paths.templates.iterdir()) == ["1002"]
    assert sorted(p.name for p in fstore.paths.markers.iterdir()) == ["dave"]
    assert fstore.orphans() == []


def test_purge_keeps_the_marker_of_a_new_account_with_the_old_name(fstore, accounts):
    fstore.add_face(1001, "old alice", vectors(1), "ir", "sface")
    accounts.pop(1001)
    accounts[1005] = "alice"                              # alice came back, with another uid
    fstore.add_face(1005, "new alice", vectors(2), "ir", "sface")
    fstore.purge_orphans()
    assert (fstore.paths.markers / "alice").exists()
    assert fstore.classes_for(1005) == {"ir"}


def test_the_purge_command(tmp_path, monkeypatch, capsys):
    """facial-auth purge-orphans: lists by default when it cannot ask, removes with --yes."""
    from facial_auth import cli
    monkeypatch.setenv("FACIAL_AUTH_ROOT", str(tmp_path))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    paths = Paths(tmp_path)
    names = {0: "root"}
    store = FaceStore(paths, name_of=lambda uid: names.get(uid, ""))
    for uid, stored in ((0, "root"), (61001, "ghost"), (61002, "oldname")):
        names.setdefault(uid, stored)
        store.add_face(uid, "face", vectors(uid), "ir", "sface")
    names[61002] = "oldname"
    # real lookups in the command: uid 0 is root; the two others are not accounts of this machine
    assert cli.main(["purge-orphans", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "ghost" in out and "oldname" in out and "uid 0:" not in out
    assert (paths.templates / "61001").exists(), "--dry-run removes nothing"
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False, raising=False)
    assert cli.main(["purge-orphans"]) == 2, "nothing is removed without a way to confirm"
    assert (paths.templates / "61001").exists()
    assert cli.main(["purge-orphans", "--yes"]) == 0
    assert sorted(p.name for p in paths.templates.iterdir()) == ["0"]
    assert cli.main(["purge-orphans", "--yes"]) == 0
    assert "No orphaned" in capsys.readouterr().out
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.main(["purge-orphans", "--yes"]) == 1, "root only"


# ----------------------------------------------------------- the lock-out
# The progressive lock-out lived in the daemon's memory, and the daemon leaves after 15 minutes of
# silence (or is restarted, or killed): somebody trying a photograph just had to wait for that.
import json  # noqa: E402

from facial_auth.ratelimit import FailureLimiter, MEMORY_SECONDS  # noqa: E402


class Clocks:
    """A monotonic clock and a wall clock moving together; a restart gets a new monotonic origin."""
    def __init__(self):
        self.wall, self.mono = 1_800_000_000.0, 5000.0

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds

    def restart(self):
        self.mono = 12.0                      # time.monotonic() starts again from boot


def make_limiter(state, clocks, **kw):
    return FailureLimiter(3, 60, 60, clock=lambda: clocks.mono, growth=2.0, max_lockout=3600.0,
                          state_file=state, wall_clock=lambda: clocks.wall, **kw)


def trip(lim, uid=1001):
    for _ in range(3):
        lim.record_failure(uid)


def test_a_lock_out_survives_a_restart_of_the_daemon(tmp_path):
    clocks, state = Clocks(), tmp_path / "state" / "lockout.json"
    first = make_limiter(state, clocks)
    trip(first)
    assert first.remaining(1001) == 60
    clocks.advance(20)
    clocks.restart()
    second = make_limiter(state, clocks)
    assert 39 <= second.remaining(1001) <= 41, "the 40 seconds that were left"
    clocks.advance(41)
    assert second.remaining(1001) == 0


def test_the_next_lock_out_after_a_restart_is_longer_not_the_first_one_again(tmp_path):
    clocks, state = Clocks(), tmp_path / "lockout.json"
    lim = make_limiter(state, clocks)
    trip(lim)
    clocks.advance(61)
    clocks.restart()
    lim = make_limiter(state, clocks)
    assert lim.remaining(1001) == 0
    trip(lim)
    assert lim.remaining(1001) == 120, "strikes were remembered: 60 s, then 120 s"


def test_a_success_and_a_reset_clear_what_was_saved(tmp_path):
    clocks, state = Clocks(), tmp_path / "lockout.json"
    lim = make_limiter(state, clocks)
    trip(lim, 1)
    trip(lim, 2)
    lim.record_success(1)
    assert make_limiter(state, clocks).remaining(1) == 0
    assert make_limiter(state, clocks).remaining(2) > 0
    lim.reset(2)
    assert make_limiter(state, clocks).remaining(2) == 0
    trip(lim, 3)
    lim.reset()
    assert make_limiter(state, clocks).remaining(3) == 0


def test_strikes_are_forgotten_after_the_usual_quiet_period(tmp_path):
    clocks, state = Clocks(), tmp_path / "lockout.json"
    lim = make_limiter(state, clocks)
    trip(lim)
    clocks.advance(MEMORY_SECONDS + 1)
    clocks.restart()
    lim = make_limiter(state, clocks)
    trip(lim)
    assert lim.remaining(1001) == 60


def test_a_clock_set_back_cannot_make_a_lock_out_last_for_ever(tmp_path):
    clocks, state = Clocks(), tmp_path / "lockout.json"
    trip(make_limiter(state, clocks))
    clocks.wall -= 10 * 86400                # the system clock was set ten days back
    clocks.restart()
    assert make_limiter(state, clocks).remaining(1001) <= 3600


@pytest.mark.parametrize("junk", [
    "", "not json", "[]", "null", '{"version": 2, "accounts": {}}', '{"version": 1}',
    '{"version": 1, "accounts": []}', '{"version": 1, "accounts": {"x": {}}}',
    '{"version": 1, "accounts": {"1": {"locked_until": "soon", "strikes": "many", "last_strike": null}}}',
    '{"version": 1, "accounts": {"1": {"locked_until": NaN, "strikes": 5, "last_strike": NaN}}}',
    '{"version": 1, "accounts": {"1": {"locked_until": Infinity, "strikes": 1000000, "last_strike": 1}}}',
    '{"version": 1, "accounts": {"1": 7}}',
])
def test_a_damaged_state_file_is_ignored_never_fatal(tmp_path, junk):
    clocks, state = Clocks(), tmp_path / "lockout.json"
    state.write_text(junk)
    lim = make_limiter(state, clocks)
    assert lim.remaining(1) <= 3600
    trip(lim, 7)                                         # and it still works (no overflow from a huge strike count)
    assert lim.remaining(7) > 0


def test_a_state_directory_that_cannot_be_written_never_breaks_authentication(tmp_path):
    clocks = Clocks()
    blocker = tmp_path / "file"
    blocker.write_text("x")
    lim = make_limiter(blocker / "lockout.json", clocks)       # a "directory" that is a regular file
    trip(lim)
    assert lim.remaining(1001) == 60


def test_the_state_file_holds_only_numbers_and_is_private(tmp_path):
    clocks, state = Clocks(), tmp_path / "lockout.json"
    trip(make_limiter(state, clocks))
    data = json.loads(state.read_text())
    assert data["version"] == 1 and set(data["accounts"]) == {"1001"}
    assert oct(state.stat().st_mode & 0o777) == "0o600"


def test_the_daemon_keeps_its_lock_outs_in_its_state_directory(tmp_path):
    from facial_auth.core import Core
    core = Core(paths=Paths(tmp_path))
    for _ in range(core.cfg["security", "max_failures"]):
        core.limiter.record_failure(1001)
    assert (Paths(tmp_path).state / "lockout.json").is_file()
    assert Core(paths=Paths(tmp_path)).limiter.remaining(1001) > 0


# ------------------------------------------------------------- D-Bus / polkit
# Four weaknesses of the management API, none of which touches the PAM path:
#  * polkit was always allowed to pop a password dialog, whatever the caller asked;
#  * a process could keep every worker thread busy for ten minutes with requests waiting for a password,
#    and the read-only calls waited behind them;
#  * TestRecognition switched the camera on for any session of the account, SSH included;
#  * an unexpected error was sent to the caller with its text (paths, library messages).
gi = pytest.importorskip("gi")
from gi.repository import Gio, GLib  # noqa: E402

from facial_auth import dbus_service  # noqa: E402
from facial_auth.const import ACTION_CAMERA, BUS_NAME, IFACE, OBJECT_PATH  # noqa: E402

from .conftest import USER  # noqa: E402


def raw_call(conn, method, args=None, sig="", flags=Gio.DBusCallFlags.NONE, timeout=20000):
    params = GLib.Variant(f"({sig})", args) if sig else None
    return conn.call_sync(BUS_NAME, OBJECT_PATH, IFACE, method, params, None, flags, timeout, None).unpack()


def new_connection():
    return Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SESSION_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)


def error_of(exc):
    return Gio.DBusError.get_remote_error(exc.value)


@pytest.fixture
def quiet_env(env):
    env.polkit.grants, env.polkit.asked, env.polkit.interactive, env.polkit.hold = set(), [], [], None
    env.service.caller_uid = lambda sender: 0
    yield env
    if env.polkit.hold is not None:
        env.polkit.hold.set()
    env.polkit.hold = None
    env.service.caller_uid = lambda sender: 0


def test_polkit_may_ask_for_a_password_only_when_the_caller_said_it_accepts(quiet_env):
    env = quiet_env
    args = ("nobody", "x", [], "rgb", "camera")
    for flags, expected in ((Gio.DBusCallFlags.NONE, False), (Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, True)):
        env.polkit.interactive.clear()
        with pytest.raises(GLib.Error) as exc:
            raw_call(env.conn, "AddFace", args, "ssaayss", flags)
        assert error_of(exc) == "org.freedesktop.DBus.Error.AccessDenied"
        assert env.polkit.interactive == [expected], flags


def test_the_real_authorizer_passes_the_caller_choice_to_polkit():
    seen = []

    class Conn:
        def call_sync(self, bus, path, iface, method, args, *rest):
            seen.append(args.unpack()[3])               # CheckAuthorizationFlags
            return GLib.Variant("((bba{ss}))", ((True, False, {}),))

    auth = dbus_service.PolkitAuthorizer(Conn())
    assert auth.check(":1.7", ACTION_CAMERA) and seen == [1], "outside a request: as before"
    with dbus_service.serving(interactive=False):
        assert auth.check(":1.7", ACTION_CAMERA)
    with dbus_service.serving(interactive=True):
        assert auth.check(":1.7", ACTION_CAMERA)
    assert seen == [1, 0, 1]
    assert dbus_service.call_is_interactive() is True, "the context is left as it was found"


def test_one_caller_cannot_hold_every_worker_waiting_for_a_password(quiet_env):
    env = quiet_env
    env.polkit.hold = threading.Event()
    args = ("nobody", "x", [], "rgb", "camera")
    waiting = []

    def ask(conn):
        with pytest.raises(GLib.Error):
            raw_call(conn, "AddFace", args, "ssaayss", Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, 60000)

    greedy = new_connection()
    for _ in range(dbus_service.MAX_PENDING_AUTHORIZATIONS):
        t = threading.Thread(target=ask, args=(greedy,))
        t.start()
        waiting.append(t)
    for _ in range(100):
        if len(env.polkit.asked) >= dbus_service.MAX_PENDING_AUTHORIZATIONS:
            break
        time.sleep(0.05)
    with pytest.raises(GLib.Error) as exc:                   # one more from the same process: turned away at once
        raw_call(greedy, "AddFace", args, "ssaayss", timeout=5000)
    assert error_of(exc).endswith("TooManyRequests")
    other = new_connection()                                 # somebody else is not affected by it
    t = threading.Thread(target=ask, args=(other,))
    t.start()
    waiting.append(t)
    env.polkit.hold.set()
    for t in waiting:
        t.join(20)
        assert not t.is_alive()
    with pytest.raises(GLib.Error) as exc:                   # slots are given back
        raw_call(greedy, "AddFace", args, "ssaayss", timeout=5000)
    assert error_of(exc) == "org.freedesktop.DBus.Error.AccessDenied"


def test_read_only_calls_are_not_queued_behind_requests_waiting_for_a_password(quiet_env):
    env = quiet_env
    env.polkit.hold = threading.Event()
    args = ("nobody", "x", [], "rgb", "camera")
    conns = [new_connection() for _ in range(3)]            # 3 callers x 2 requests = all 6 workers
    threads = []
    for conn in conns:
        for _ in range(dbus_service.MAX_PENDING_AUTHORIZATIONS):
            t = threading.Thread(target=lambda c=conn: pytest.raises(GLib.Error, raw_call, c, "AddFace", args,
                                                                      "ssaayss", Gio.DBusCallFlags.NONE, 60000))
            t.start()
            threads.append(t)
    for _ in range(100):
        if len(env.polkit.asked) >= 6:
            break
        time.sleep(0.05)
    assert len(env.polkit.asked) >= 6, "the workers are all busy"
    started = time.monotonic()
    (st,) = raw_call(new_connection(), "GetStatus", timeout=5000)
    assert st["enabled"] is True and time.monotonic() - started < 3
    env.polkit.hold.set()
    for t in threads:
        t.join(20)


def test_the_recognition_test_needs_the_camera_action_even_for_the_owner(quiet_env):
    env = quiet_env
    env.service.caller_uid = lambda sender: env.uid          # the account's own session, but not an active local one
    with pytest.raises(GLib.Error) as exc:
        raw_call(env.conn, "TestRecognition", (USER, ""), "ss")
    assert error_of(exc) == "org.freedesktop.DBus.Error.AccessDenied"
    assert env.polkit.asked == [ACTION_CAMERA]


def test_an_unexpected_error_does_not_hand_its_text_to_the_caller(quiet_env, monkeypatch):
    env = quiet_env
    env.polkit.grants = {ACTION_CAMERA}

    def boom(data):
        raise RuntimeError("/var/lib/facial-auth/templates/1000/faces.json: secret detail")
    monkeypatch.setattr(env.core, "analyze", boom)
    with pytest.raises(GLib.Error) as exc:
        raw_call(env.conn, "AnalyzeImage", (b"x",), "ay")
    assert error_of(exc).endswith("Internal")
    assert "secret" not in exc.value.message and "/var/lib" not in exc.value.message


# ------------------------------------------ the daemon, the unit, the installer, the workflow
import re  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def test_the_daemon_forgets_the_development_variables_unless_started_with_dev():
    from facial_auth import daemon
    env = {"FACIAL_AUTH_ROOT": "/tmp/x", "FACIAL_AUTH_LOCALEDIR": "/tmp/y", "FACIAL_AUTH_BUS": "session", "HOME": "/root"}
    daemon.scrub_environment(False, env)
    assert env == {"HOME": "/root"}
    env = {"FACIAL_AUTH_ROOT": "/tmp/x"}
    daemon.scrub_environment(True, env)
    assert env == {"FACIAL_AUTH_ROOT": "/tmp/x"}, "--dev keeps them: that is what they are for"


def test_the_packaged_service_can_never_run_without_polkit(monkeypatch):
    from facial_auth import daemon
    monkeypatch.setattr(daemon.os, "getppid", lambda: 1)
    assert daemon.started_by_systemd({"INVOCATION_ID": "0123abcd"}) is True
    assert daemon.started_by_systemd({}) is False
    monkeypatch.setattr(daemon.os, "getppid", lambda: 4242)                 # a shell, pytest: development
    assert daemon.started_by_systemd({"INVOCATION_ID": "0123abcd"}) is False
    monkeypatch.setattr(daemon, "started_by_systemd", lambda environ=None: True)
    assert daemon.main(["--dev", "--no-polkit"]) == 2


def test_the_doctor_probe_does_not_import_from_the_current_directory(tmp_path, monkeypatch, build_dir):
    """`sudo facial-auth doctor` run in a directory that somebody else can write to executed that
    person's ctypes.py as root."""
    from facial_auth.cli import pam_module_problem
    proof = tmp_path / "proof"
    (tmp_path / "ctypes.py").write_text(f"import os\nopen({str(proof)!r}, 'w').write('ran as uid %d' % os.geteuid())\n")
    monkeypatch.chdir(tmp_path)
    assert pam_module_problem((str(build_dir / "pam" / "pam_facial_auth.so"),)) is None
    assert not proof.exists(), "the planted module was imported"
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    assert pam_module_problem((str(build_dir / "pam" / "pam_facial_auth.so"),)) is None
    assert not proof.exists(), "nor through PYTHONPATH"


def test_the_installer_probe_is_isolated_too():
    postinst = (ROOT / "debian/facial-auth.postinst").read_text()
    assert re.search(r"python3 -I -c '", postinst)
    assert not re.search(r"python3 -c ", postinst)


def test_the_unit_keeps_its_sandbox():
    unit = (ROOT / "data/systemd/facial-authd.service").read_text()
    for line in ("NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectSystem=strict", "ProtectHome=yes",
                 "PrivateTmp=yes", "RestrictAddressFamilies=AF_UNIX", "SystemCallFilter=@system-service",
                 "DevicePolicy=closed", "MemoryMax=1G", "ProtectProc=invisible", "RemoveIPC=yes"):
        assert re.search(rf"^{re.escape(line)}$", unit, re.M), line


@pytest.mark.skipif(subprocess.run(["which", "systemd-analyze"], capture_output=True).returncode != 0,
                    reason="needs systemd-analyze")
def test_systemd_understands_every_directive_of_the_unit():
    r = subprocess.run(["systemd-analyze", "verify", str(ROOT / "data/systemd/facial-authd.service")],
                       capture_output=True, text=True)
    text = r.stdout + r.stderr
    assert "Unknown key" not in text and "Unknown lvalue" not in text and "Invalid" not in text, text


def fake_models(tmp_path, monkeypatch):
    from facial_auth import models
    import hashlib
    spec = lambda name, body, role: models.ModelSpec(name, f"{name}.onnx", hashlib.sha256(body).hexdigest(),  # noqa: E731
                                                     len(body), (), "test", role)
    det, rec = spec("det", b"detector bytes", "detector"), spec("rec", b"recognizer bytes", "recognizer")
    monkeypatch.setattr(models, "required", lambda cv=None: (det, rec))
    src = tmp_path / "usb"
    src.mkdir()
    (src / "det.onnx").write_bytes(b"detector bytes")
    (src / "rec.onnx").write_bytes(b"recognizer bytes")
    return models, src, Paths(tmp_path / "root")


def test_install_from_installs_what_it_checked_even_if_the_source_changes_meanwhile(tmp_path, monkeypatch):
    """It used to check the path, then copy the path again: whoever could write in the source
    directory could swap the file in between (the daemon refuses an altered model at load time, but
    the point is to install what was verified)."""
    models, src, paths = fake_models(tmp_path, monkeypatch)
    real = models.sha256_of

    def swap_after_hashing(path):
        digest = real(path)
        Path(path).write_bytes(b"EVIL")                  # only reached by an implementation that hashes the path
        return digest
    monkeypatch.setattr(models, "sha256_of", swap_after_hashing)
    installed = models.install_from(src, paths)
    assert [p.read_bytes() for p in installed] == [b"detector bytes", b"recognizer bytes"]
    assert all(oct(p.stat().st_mode & 0o777) == "0o644" for p in installed)
    assert sorted(p.name for p in paths.models.iterdir()) == ["det.onnx", "rec.onnx"], "no temporary file left"


def test_install_from_refuses_what_does_not_match_and_installs_nothing_of_it(tmp_path, monkeypatch):
    models, src, paths = fake_models(tmp_path, monkeypatch)
    (src / "rec.onnx").write_bytes(b"recognizer bytez")
    with pytest.raises(RuntimeError, match="does not match"):
        models.install_from(src, paths)
    assert not (paths.models / "rec.onnx").exists()
    (src / "rec.onnx").unlink()
    with pytest.raises(RuntimeError, match="missing or does not match"):
        models.install_from(src, paths)


def test_the_workflow_does_not_leave_the_token_in_the_checked_out_repository():
    text = (ROOT / ".github/workflows/deb.yml").read_text()
    steps = [m.start() for m in re.finditer(r"uses: actions/checkout@", text)]
    assert len(steps) >= 3
    for pos in steps:
        following = text[pos:pos + 160]
        assert re.search(r"with:\s*\n\s*persist-credentials: false", following), following
