# SPDX-License-Identifier: MIT
import json
import os
import stat

import numpy as np
import pytest

from facial_auth import protocol
from facial_auth.config import Config, validate_update, write_settings
from facial_auth.const import Paths
from facial_auth.store import FaceStore, MAX_FACES_PER_USER, StoreError


# ---------------------------------------------------------------- config
def test_defaults_are_secure_by_default():
    c = Config.defaults()
    assert c["recognition", "threshold"] >= 0.4
    assert c.service("sudo").camera_class == "ir", "sudo must require an IR camera by default"
    assert c.service("gdm-password").camera_class == "any"
    assert c.service("sshd") is None and c.service("cron") is None, "unlisted services are denied"
    assert c["security", "allow_root"] is False


def test_config_files_layer_and_clamp(tmp_path):
    p = Paths(tmp_path)
    p.config.parent.mkdir(parents=True)
    p.config.write_text("[recognition]\nthreshold = 0.05\nrequired_matches = 4\n"
                        "[services]\nsudo = any\nbogus = maybe\n[camera]\nwidth = banana\n")
    p.state.mkdir(parents=True)
    p.settings.write_text("[recognition]\nrequired_matches = 5\n")
    c = Config.load(p)
    assert c["recognition", "threshold"] == 0.30, "a typo must not make matching permissive"
    assert c["recognition", "required_matches"] == 5, "GUI settings override /etc"
    assert c.service("sudo").camera_class == "any"
    assert "bogus" not in c.services
    assert c["camera", "width"] == 640
    assert len(c.warnings) >= 3


def test_a_broken_file_is_ignored_as_a_whole_never_half_applied(tmp_path):
    p = Paths(tmp_path)
    p.config.parent.mkdir(parents=True)
    # the syntax error sits *before* the hardened value: it must not be lost silently
    p.config.write_text("[recognition]\nthreshold = 0.8\nthis line is not valid\n[security]\nmax_failures = 2\n")
    c = Config.load(p)
    assert c["recognition", "threshold"] == 0.45 and c["security", "max_failures"] == 5
    assert any("facial-auth.conf" in w for w in c.warnings), "the admin must be told"


def test_duplicate_keys_are_tolerated_last_one_wins(tmp_path):
    p = Paths(tmp_path)
    p.config.parent.mkdir(parents=True)
    p.config.write_text("[services]\nsudo = any\nsudo = ir\n[recognition]\nthreshold = 0.6\n")
    c = Config.load(p)
    assert c.service("sudo").camera_class == "ir" and c["recognition", "threshold"] == 0.6


def test_validate_update_whitelists_and_rejects():
    ok = validate_update({"recognition.threshold": 0.5, "core.enabled": False,
                          "services.sudo": "any", "interaction.sudo": "parallel-tty"})
    assert ok[("core", "enabled")] == "false"
    for bad in ({"recognition.threshold": 0.1}, {"camera.emitter_command": "id"},
                {"services.sudo": "root"}, {"x.y": 1}, {"recognition.required_matches": "many"}):
        with pytest.raises(ValueError):
            validate_update(bad)


def test_write_settings_roundtrip(tmp_path):
    p = Paths(tmp_path)
    write_settings(p.settings, {("recognition", "threshold"): "0.6", ("services", "sudo"): "off"})
    write_settings(p.settings, {("recognition", "timeout"): "5.0"})
    c = Config.load(p)
    assert c["recognition", "threshold"] == 0.6 and c["recognition", "timeout"] == 5.0
    assert c.service("sudo") is None


# -------------------------------------------------------------- protocol
def test_request_roundtrip_with_hostile_values():
    req = protocol.Request(user="al ice", service="su do", tty="/dev/pts/3",
                           rhost="", ruser="a\nVERIFY v=1 user=root")
    line = protocol.build_request(req)
    assert line.count("\n") == 1 and line.endswith("\n")
    back = protocol.parse_request(line)
    assert back == req


@pytest.mark.parametrize("line", [
    "HELLO v=1 user=a", "VERIFY v=2 user=a", "VERIFY v=1", "VERIFY v=1 user=",
    "VERIFY v=1 user=a%2Fb", "VERIFY v=1 user=%00x", "VERIFY garbage", "VERIFY v=x user=a",
    "VERIFY v=1 user=" + "a" * 2000,
])
def test_bad_requests_are_rejected(line):
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_request(line)


def test_replies_are_one_line_each():
    assert protocol.accept("parallel-tty", 8) == b"ACCEPT mode=parallel-tty timeout=8.0\n"
    assert protocol.ok(0.6234) == b"OK score=0.623\n"
    assert protocol.fail("timeout") == b"FAIL reason=timeout\n"
    assert protocol.skip("not-enrolled") == b"SKIP reason=not-enrolled\n"
    with pytest.raises(ValueError):
        protocol.accept("weird", 1)
    r = protocol.parse_reply("ACCEPT mode=parallel timeout=3.5")
    assert r.kind == "ACCEPT" and r.fields["mode"] == "parallel"


# ----------------------------------------------------------------- store
@pytest.fixture
def store(tmp_path):
    names = {1000: "alice", 1001: "bob"}
    return FaceStore(Paths(tmp_path), name_of=lambda uid: names.get(uid, ""))


def vecs(n=3, seed=0):
    return np.random.default_rng(seed).normal(size=(n, 128)).astype(np.float32)


def test_store_add_list_remove_and_permissions(store):
    rec = store.add_face(1000, "  My   face ", vecs(), "rgb", "m", "camera")
    assert rec.label == "My face"
    f = store.paths.templates / "1000" / "faces.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.paths.templates.stat().st_mode) == 0o700
    user = store.load(1000)
    assert [x.public()["samples"] for x in user.faces] == [3]
    assert np.allclose(np.linalg.norm(user.faces[0].vectors, axis=1), 1.0, atol=1e-5)
    assert (store.paths.markers / "alice").exists()
    assert "vectors" not in json.dumps(user.faces[0].public())
    assert store.remove_face(1000, rec.id) and not store.remove_face(1000, rec.id)
    assert not (store.paths.markers / "alice").exists(), "no face left: marker removed"
    assert not (store.paths.templates / "1000").exists()


def test_store_never_stores_images_only_vectors(store):
    store.add_face(1000, "x", vecs(), "ir", "m")
    raw = (store.paths.templates / "1000" / "faces.json").read_text()
    assert "jpeg" not in raw.lower() and len(raw) < 20000


def test_store_fails_closed_on_corruption(store):
    store.add_face(1000, "x", vecs(), "rgb", "m")
    f = store.paths.templates / "1000" / "faces.json"
    for garbage in ("{not json", json.dumps({"version": 99}), json.dumps({"version": 1, "faces": [{"id": "a"}]}),
                    json.dumps({"version": 1, "faces": [{"id": "a", "camera_class": "x", "dim": 128, "vectors": "AA=="}]})):
        f.write_text(garbage)
        assert store.load(1000).faces == [], "damaged data must mean 'no face', never 'any face'"
        assert len(store.templates_for(1000)) == 0


def test_store_rejects_degenerate_embeddings(store):
    for bad in (np.zeros((2, 128)), np.full((2, 128), np.nan)):
        with pytest.raises(StoreError):
            store.add_face(1000, "x", bad, "rgb", "m")
    with pytest.raises(StoreError):
        store.add_face(1000, "x", vecs(), "thermal", "m")


def test_store_limits_and_enable_flag(store):
    for i in range(MAX_FACES_PER_USER):
        store.add_face(1000, f"f{i}", vecs(2, i), "rgb", "m")
    with pytest.raises(StoreError):
        store.add_face(1000, "one too many", vecs(), "rgb", "m")
    store.set_enabled(1000, False)
    assert len(store.templates_for(1000)) == 0 and store.classes_for(1000) == set()
    assert not (store.paths.markers / "alice").exists()
    store.set_enabled(1000, True)
    assert len(store.templates_for(1000, "rgb")) == 2 * MAX_FACES_PER_USER
    assert len(store.templates_for(1000, "ir")) == 0
    with pytest.raises(StoreError):
        store.set_enabled(1001, True)


def test_store_all_templates_and_marker_resync(store):
    store.add_face(1000, "a", vecs(2, 1), "rgb", "m")
    store.add_face(1001, "b", vecs(2, 2), "rgb", "m")
    assert set(store.all_templates("rgb")) == {1000, 1001}
    (store.paths.markers / "stale").touch()
    (store.paths.markers / "alice").unlink()
    store.sync_markers()
    assert sorted(p.name for p in store.paths.markers.iterdir()) == ["alice", "bob"]


def test_shipped_defaults_file_matches_the_built_in_defaults(tmp_path):
    """data/config/defaults.conf documents the defaults: it must never drift."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    p = Paths(tmp_path)
    p.defaults.parent.mkdir(parents=True)
    p.defaults.write_text((root / "data/config/defaults.conf").read_text())
    assert Config.load(p).as_dict() == Config.defaults().as_dict()
    assert Config.load(p).warnings == []
