# SPDX-License-Identifier: MIT
"""Accounts that come from a directory (LDAP, SSSD, Active Directory) must be listed and configurable.

The settings application listed ``pwd.getpwall()`` between uid 1000 and 60000.  That is the *local* user
database: SSSD and nslcd do not enumerate a directory unless asked to (an enumeration of every account
of a company is slow, and off by default), and directory uids are often above 60000.  On a machine
whose users sign in through LDAP, the only account offered was the local administrator.
"""
import pwd

import numpy as np
import pytest

from facial_auth import config as config_mod
from facial_auth import core as core_mod
from facial_auth.const import Paths
from facial_auth.core import ApiError, Core
from facial_auth.store import FaceStore
from facial_auth.system import LogindProbe, NullProbe


def account(name, uid, shell="/bin/bash", gecos=None):
    real = gecos if gecos is not None else name.title() + ",,,"
    return pwd.struct_passwd((name, "x", uid, uid, real, f"/home/{name}", shell))


LOCAL_ADMIN = account("admin", 1000, gecos="Local Administrator,,,")
LDAP_USER = account("jdupont", 1234567, gecos="Jeanne Dupont")          # a directory uid: above 60000
LDAP_BOB = account("bob", 1234568)
NOBODY = account("nobody", 65534, shell="/usr/sbin/nologin")
SYSTEM = account("daemon", 1, shell="/usr/sbin/nologin")


class Probe:
    """What systemd-logind says."""
    def __init__(self, uids=()):
        self.uids = list(uids)

    def is_remote(self, pid):
        return None

    def users(self):
        return list(self.uids)


class Directory:
    """The user database as the daemon's NSS sees it: some accounts are enumerated, all can be resolved."""
    def __init__(self, resolvable, enumerated):
        self.by_name = {a.pw_name: a for a in resolvable}
        self.by_uid = {a.pw_uid: a for a in resolvable}
        self.enumerated = list(enumerated)
        self.enumerations = 0

    def getpwall(self):
        self.enumerations += 1
        return list(self.enumerated)

    def getpwnam(self, name):
        try:
            return self.by_name[name]
        except KeyError:
            raise KeyError(f"getpwnam(): name not found: {name!r}") from None

    def getpwuid(self, uid):
        try:
            return self.by_uid[uid]
        except KeyError:
            raise KeyError(f"getpwuid(): uid not found: {uid}") from None


@pytest.fixture
def system_users(monkeypatch):
    """SSSD's default: a directory account can be looked up, never enumerated."""
    d = Directory(resolvable=[LOCAL_ADMIN, LDAP_USER, LDAP_BOB, NOBODY, SYSTEM], enumerated=[LOCAL_ADMIN, NOBODY, SYSTEM])
    monkeypatch.setattr(pwd, "getpwall", d.getpwall)
    monkeypatch.setattr(pwd, "getpwnam", d.getpwnam)
    monkeypatch.setattr(pwd, "getpwuid", d.getpwuid)
    return d


def make_core(tmp_path, probe=None, config=""):
    paths = Paths(tmp_path)
    if config:
        paths.config.parent.mkdir(parents=True, exist_ok=True)
        paths.config.write_text(config)
    core = Core(paths=paths, session_probe=probe or Probe(), models_probe=lambda: {"ok": True, "missing": []})
    core.directory_ttl = 0.0
    return core


def names(users):
    return [u.pw_name for u in users]


def vectors(seed=3):
    return np.random.RandomState(seed).randn(3, 128).astype(np.float32)


# ------------------------------------------------------------- what is listed
def test_the_failure_as_reported_only_the_local_administrator_was_listed(system_users, tmp_path):
    assert names(make_core(tmp_path).human_users()) == ["admin"], "the old behaviour: the enumeration of the system"


def test_an_account_with_a_session_on_this_machine_is_listed(system_users, tmp_path):
    core = make_core(tmp_path, Probe([LDAP_USER.pw_uid]))
    assert names(core.listed_users()) == ["admin", "jdupont"]


def test_the_account_of_the_person_using_the_application_is_listed(system_users, tmp_path):
    core = make_core(tmp_path)
    assert names(core.listed_users(caller_uid=LDAP_USER.pw_uid)) == ["admin", "jdupont"]


def test_an_account_that_already_has_faces_is_listed(system_users, tmp_path):
    core = make_core(tmp_path)
    core.store.add_face(LDAP_BOB.pw_uid, "face", vectors(), "ir", "sface")
    assert names(core.listed_users()) == ["admin", "bob"]


def test_accounts_named_in_the_configuration_are_listed(system_users, tmp_path):
    core = make_core(tmp_path, config="[core]\nextra_users = jdupont, bob ghost a/b\n")
    assert names(core.listed_users()) == ["admin", "jdupont", "bob"], "unknown names are ignored, not an error"


def test_hostile_names_in_the_configuration_are_ignored(system_users, tmp_path):
    core = make_core(tmp_path, config="[core]\nextra_users = ../etc, a\\x1bb, " + "x" * 300 + "\n")
    assert names(core.listed_users()) == ["admin"]


def test_an_account_is_listed_once_however_many_ways_it_is_known(system_users, tmp_path):
    core = make_core(tmp_path, Probe([LDAP_USER.pw_uid, LDAP_USER.pw_uid]), config="[core]\nextra_users = jdupont\n")
    core.store.add_face(LDAP_USER.pw_uid, "face", vectors(), "ir", "sface")
    assert names(core.listed_users(caller_uid=LDAP_USER.pw_uid)).count("jdupont") == 1


def test_everything_the_system_can_enumerate_is_listed_when_the_directory_is_enumerable(system_users, tmp_path):
    system_users.enumerated += [LDAP_USER, LDAP_BOB]                  # SSSD with "enumerate = true"
    assert names(make_core(tmp_path).listed_users()) == ["admin", "jdupont", "bob"]


def test_system_accounts_and_accounts_that_cannot_log_in_are_not_listed(system_users, tmp_path):
    core = make_core(tmp_path, Probe([NOBODY.pw_uid, SYSTEM.pw_uid]))
    assert names(core.listed_users()) == ["admin"]


def test_root_is_never_listed_unless_the_administrator_allowed_it(system_users, monkeypatch, tmp_path):
    root = account("root", 0, shell="/bin/bash")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: root if uid == 0 else system_users.getpwuid(uid))
    assert "root" not in names(make_core(tmp_path, Probe([0])).listed_users(caller_uid=0))
    allowed = make_core(tmp_path, Probe([0]), config="[security]\nallow_root = true\n[core]\nuid_min = 0\n")
    assert "root" in names(allowed.listed_users(caller_uid=0))


def test_the_uid_window_is_configurable_and_has_no_upper_limit_by_default(system_users, tmp_path):
    system_users.enumerated += [LDAP_USER]
    assert "jdupont" in names(make_core(tmp_path).listed_users())
    narrow = make_core(tmp_path, config="[core]\nuid_max = 60000\nuid_min = 1000\n")
    assert names(narrow.listed_users()) == ["admin"]
    assert names(make_core(tmp_path, config="[core]\nuid_min = 2000\n").listed_users()) == ["jdupont"]


def test_a_site_with_a_huge_directory_can_turn_the_enumeration_off(system_users, tmp_path):
    system_users.enumerated += [LDAP_USER, LDAP_BOB]
    core = make_core(tmp_path, Probe([LDAP_USER.pw_uid]), config="[core]\nlist_directory = false\n")
    assert names(core.listed_users()) == ["jdupont"]
    assert system_users.enumerations == 0


def test_the_enumeration_is_not_repeated_for_every_refresh(system_users, tmp_path):
    core = make_core(tmp_path)
    core.directory_ttl = 60.0
    core.listed_users()
    core.listed_users()
    assert system_users.enumerations == 1
    core.directory_ttl = 0.0
    core.listed_users()
    assert system_users.enumerations == 2


def test_a_huge_directory_cannot_flood_the_list_and_the_accounts_that_matter_stay(system_users, monkeypatch, tmp_path):
    crowd = [account(f"user{i:05d}", 2000000 + i) for i in range(500)]
    system_users.enumerated += crowd
    monkeypatch.setattr(core_mod, "MAX_LISTED_USERS", 20)
    core = make_core(tmp_path, Probe([LDAP_USER.pw_uid]))
    core.store.add_face(LDAP_BOB.pw_uid, "face", vectors(), "ir", "sface")
    listed = names(core.listed_users(caller_uid=LDAP_USER.pw_uid))
    assert len(listed) == 20
    assert {"jdupont", "bob"} <= set(listed), "the caller, a session and an enrolled account come first"


def test_a_probe_that_does_not_know_users_does_not_break_the_list(system_users, tmp_path):
    class Old:
        def is_remote(self, pid):
            return None
    core = make_core(tmp_path, Old())
    assert names(core.listed_users()) == ["admin"]


def test_a_failing_session_lookup_does_not_break_the_list(system_users, tmp_path):
    class Broken(Probe):
        def users(self):
            raise OSError("bus is gone")
    assert names(make_core(tmp_path, Broken()).listed_users()) == ["admin"]


# --------------------------------------------------------------- the summary
def test_an_account_without_faces_is_summarised_without_reading_any_file(system_users, monkeypatch, tmp_path):
    core = make_core(tmp_path)
    core.store.add_face(LOCAL_ADMIN.pw_uid, "face", vectors(), "ir", "sface")
    monkeypatch.setattr(core.store, "load", lambda uid: (_ for _ in ()).throw(AssertionError(f"read {uid}")))
    enrolled = {LOCAL_ADMIN.pw_uid}
    assert core.user_summary(LDAP_USER, enrolled) == {"uid": 1234567, "name": "jdupont", "realname": "Jeanne Dupont",
                                                      "faces": 0, "enabled": True, "locked_out": 0}


def test_the_real_name_falls_back_to_the_login_when_the_directory_has_none(system_users, tmp_path):
    bare = account("nogecos", 1234569, gecos="")
    assert make_core(tmp_path).user_summary(bare)["realname"] == "nogecos"


# ------------------------------------------------------------------ look-ups
def test_an_account_the_list_does_not_show_can_be_looked_up_by_its_login(system_users, tmp_path):
    summary = make_core(tmp_path).lookup_user("jdupont")
    assert summary["uid"] == 1234567 and summary["name"] == "jdupont" and summary["realname"] == "Jeanne Dupont"
    assert summary["faces"] == 0 and summary["enabled"] is True


def test_looking_up_an_unknown_account_says_how_to_check(system_users, tmp_path):
    with pytest.raises(ApiError) as exc:
        make_core(tmp_path).lookup_user("nobody-here")
    assert exc.value.code == "unknown-user" and "getent passwd" in str(exc.value)


@pytest.mark.parametrize("name", ["", "a/b", "../x", "a\nb", "a\x00b", "x" * 257, "a\x1b[31m"])
def test_hostile_names_are_refused_before_the_system_is_asked(system_users, monkeypatch, tmp_path, name):
    core = make_core(tmp_path)

    def never(_name):
        raise AssertionError("the user database was asked")
    monkeypatch.setattr(pwd, "getpwnam", never)
    with pytest.raises(ApiError) as exc:
        core.lookup_user(name)
    assert exc.value.code == "bad-argument"


def test_root_cannot_be_looked_up_unless_allowed(system_users, monkeypatch, tmp_path):
    root = account("root", 0)
    monkeypatch.setattr(pwd, "getpwnam", lambda n: root if n == "root" else system_users.getpwnam(n))
    with pytest.raises(ApiError) as exc:
        make_core(tmp_path).lookup_user("root")
    assert exc.value.code == "not-allowed"


# ------------------------------------------------------------- logind probe
def test_logind_probe_lists_the_users_with_a_session():
    class Bus:
        def call_sync(self, name, path, iface, method, params, reply_type, flags, timeout, cancellable):
            from gi.repository import GLib
            assert (name, method) == ("org.freedesktop.login1", "ListUsers")
            return GLib.Variant("(a(uso))", ([(1000, "admin", "/o/1"), (1234567, "jdupont", "/o/2")],))
    probe = LogindProbe()
    probe._bus = Bus()
    assert probe.users() == [1000, 1234567]


def test_logind_probe_answers_nothing_when_logind_cannot_be_asked():
    class Bus:
        def call_sync(self, *a, **k):
            raise OSError("no such service")
    probe = LogindProbe()
    probe._bus = Bus()
    assert probe.users() == []
    assert NullProbe().users() == []


# ------------------------------------------------------------- configuration
def test_the_new_settings_are_known_documented_and_changeable():
    d = config_mod.Config.defaults()
    assert d["core", "list_directory"] is True and d["core", "uid_min"] == 1000 and d["core", "extra_users"] == ""
    assert d["core", "uid_max"] >= 2 ** 31, "directory uids are not capped at 60000"
    ok = config_mod.validate_update({"core.extra_users": "alice, bob", "core.uid_min": 500, "core.list_directory": False})
    assert ok[("core", "extra_users")] == "alice, bob" and ok[("core", "list_directory")] == "false"
    with pytest.raises(ValueError):
        config_mod.validate_update({"core.uid_min": -1})
    with pytest.raises(ValueError):
        config_mod.validate_update({"core.extra_users": "a\nb"})


# ------------------------------------------------------ D-Bus API and command
# (the same private bus and fake polkit as the other API tests)
import os  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

gi = pytest.importorskip("gi")
from gi.repository import Gio, GLib  # noqa: E402

from facial_auth import dbus_service  # noqa: E402
from facial_auth.const import BUS_NAME, IFACE, OBJECT_PATH  # noqa: E402

from .conftest import USER  # noqa: E402


def dbus(conn, method, args=None, sig="", timeout=20000):
    params = GLib.Variant(f"({sig})", args) if sig else None
    return conn.call_sync(BUS_NAME, OBJECT_PATH, IFACE, method, params, None, Gio.DBusCallFlags.NONE,
                          timeout, None).unpack()


def remote_error(exc):
    return Gio.DBusError.get_remote_error(exc.value)


@pytest.fixture
def api(env, monkeypatch):
    """The API with nothing enumerable: only what the machine knows about people can be listed."""
    env.polkit.grants, env.polkit.asked = set(), []
    monkeypatch.setattr(env.core, "human_users", lambda: [])
    env.core.store.clear(env.uid)
    env.service.caller_uid = lambda sender: 0
    yield env
    env.core.store.clear(env.uid)
    env.service.caller_uid = lambda sender: 0


def listed(env):
    (users,) = dbus(env.conn, "ListUsers")
    return [u["name"] for u in users]


def test_the_list_offers_the_account_of_the_person_using_the_application(api):
    assert listed(api) == []
    api.service.caller_uid = lambda sender: api.uid
    assert listed(api) == [USER]
    (users,) = dbus(api.conn, "ListUsers")
    assert users[0]["uid"] == api.uid and users[0]["faces"] == 0 and users[0]["enabled"] is True


def test_an_account_that_has_faces_stays_in_the_list(api):
    api.core.store.add_face(api.uid, "face", vectors(), "rgb", "sface")
    (users,) = dbus(api.conn, "ListUsers")
    assert [(u["name"], u["faces"]) for u in users] == [(USER, 1)]


def test_the_list_is_no_longer_answered_by_the_workers_kept_for_instant_calls():
    """With a directory behind it, the list can take seconds: it must not hold up GetStatus."""
    assert "ListUsers" not in dbus_service.FAST_METHODS
    assert "LookupUser" not in dbus_service.FAST_METHODS


def test_an_account_is_looked_up_by_its_login_over_d_bus(api):
    (found,) = dbus(api.conn, "LookupUser", (USER,), "s")
    assert found["name"] == USER and found["uid"] == api.uid and found["faces"] == 0
    assert api.polkit.asked == [], "who exists is no secret: nothing to authorise"


@pytest.mark.parametrize("name,error", [("nobody-here", "UnknownUser"), ("root", "NotAllowed"), ("a/b", "BadArgument"),
                                        ("", "BadArgument"), ("x" * 300, "BadArgument")])
def test_looking_up_what_cannot_be_used_is_refused_with_a_reason(api, name, error):
    with pytest.raises(GLib.Error) as exc:
        dbus(api.conn, "LookupUser", (name,), "s")
    assert remote_error(exc).endswith(error)


def test_one_caller_cannot_hold_every_worker_with_slow_lookups(api, monkeypatch):
    release = threading.Event()
    started = []

    def slow(name):
        started.append(name)
        release.wait(20)
        return {"uid": 1, "name": name, "realname": name, "faces": 0, "enabled": True, "locked_out": 0}
    monkeypatch.setattr(api.core, "lookup_user", slow)
    conn = Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SESSION_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
    threads = [threading.Thread(target=lambda: dbus(conn, "LookupUser", ("slow",), "s")) for _ in range(2)]
    for t in threads:
        t.start()
    for _ in range(100):
        if len(started) == 2:
            break
        time.sleep(0.05)
    assert len(started) == 2
    with pytest.raises(GLib.Error) as exc:
        dbus(conn, "LookupUser", ("one-more",), "s")
    assert remote_error(exc).endswith("TooManyRequests")
    assert api.service.core.cfg["core", "enabled"] is True and dbus(api.conn, "GetStatus")[0]["enabled"] is True
    release.set()
    for t in threads:
        t.join(20)


def cli(env, *args):
    e = {**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "..", "src"),
         "FACIAL_AUTH_BUS": "session", "LANGUAGE": "C", "LC_ALL": "C"}
    p = subprocess.run(["/usr/bin/python3.12", "-m", "facial_auth.cli", *args], capture_output=True, text=True,
                       env=e, timeout=60)
    return p.returncode, p.stdout + p.stderr


def test_the_users_command_shows_what_the_daemon_offers_and_what_it_can_resolve(api):
    api.service.caller_uid = lambda sender: api.uid
    rc, out = cli(api, "users")
    assert rc == 0 and USER in out and "no face linked" in out
    rc, out = cli(api, "users", USER)
    assert rc == 0 and USER in out and str(api.uid) in out
    rc, out = cli(api, "users", "nobody-here")
    assert rc == 1 and "no such user" in out and "getent passwd" in out
    api.core.store.add_face(api.uid, "face", vectors(), "rgb", "sface")
    rc, out = cli(api, "users", USER)
    assert rc == 0 and "1 face(s)" in out


# ----------------------------------------------------------- the error text
def test_a_remote_error_reaches_the_user_without_the_bus_prefix():
    """The window showed "GDBus.Error:io.github.neomars.FacialAuth1.Error.UnknownUser: no such user"."""
    from facial_auth import client
    exc = Gio.DBusError.new_for_dbus_error("io.github.neomars.FacialAuth1.Error.UnknownUser", "no such user: ghost")
    assert exc.message.startswith("GDBus.Error:"), "this PyGObject keeps the prefix in the message"
    converted = client._convert(exc)
    assert converted.code == "unknown-user" and str(converted) == "no such user: ghost"
    plain = client._convert(GLib.Error.new_literal(Gio.DBusError.quark(), "just a message", Gio.DBusError.FAILED))
    assert str(plain) == "just a message"
