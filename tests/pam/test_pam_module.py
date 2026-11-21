# SPDX-License-Identifier: MIT
"""End-to-end tests of pam_facial_auth.so with the *real* pam_unix.

A scripted PAM application (pamtest) is run against a PAM stack identical to
the one pam-auth-update generates:

    auth [success=2 conv_err=die default=ignore] pam_facial_auth.so
    auth [success=1 default=ignore] pam_unix.so nullok try_first_pass
    auth requisite pam_deny.so
    auth required  pam_permit.so

and a mock daemon whose behaviour is carried in the `ruser` field.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

import pytest

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="needs root (writes /etc/pam.d, creates users)")

HERE = Path(__file__).resolve().parent
USER, PASSWORD = "fatest", "secret"
LOCKED_USER = "fatest-locked"
PYTHON = "/usr/bin/python3.12" if Path("/usr/bin/python3.12").exists() else sys.executable


class Result:
    def __init__(self, proc, events, log):
        self.proc, self.events, self.log = proc, events, log
        self.rc = proc.returncode

    def tags(self, tag):
        return [e for e in self.events if e[0] == tag]

    def count(self, tag):
        return len(self.tags(tag))

    def infos(self):
        return [e[2] for e in self.tags("INFO")]

    def at(self, tag):
        """Elapsed ms of the first event with this tag."""
        found = self.tags(tag)
        return found[0][1] if found else None

    def requests(self):
        return [e for e in self.log if e["event"] == "request"]

    def log_events(self, name):
        return [e for e in self.log if e["event"] == name]


@pytest.fixture(scope="module")
def env(build_dir, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fa")
    os.chmod(tmp, 0o755)
    sock = tmp / "pam.sock"
    log = tmp / "mock.log"
    module = build_dir / "pam" / "pam_facial_auth.so"
    marker_dir = tmp / "enrolled"
    marker_dir.mkdir()

    for name in (USER, LOCKED_USER):
        if subprocess.run(["id", name], capture_output=True).returncode != 0:
            subprocess.run(["useradd", "-m", "-s", "/bin/bash", name], check=True)
    subprocess.run(["chpasswd"], input=f"{USER}:{PASSWORD}\n{LOCKED_USER}:{PASSWORD}\n",
                   text=True, check=True)
    subprocess.run(["usermod", "-L", LOCKED_USER], check=True)

    stacks = {
        "fa-test": f"socket={sock} marker_dir=- debug",
        "fa-test-seq": f"socket={sock} marker_dir=- mode=sequential debug",
        "fa-test-marker": f"socket={sock} marker_dir={marker_dir} debug",
        "fa-test-nodaemon": f"socket={tmp}/absent.sock marker_dir=- debug",
        "fa-test-quiet": f"socket={sock} marker_dir=- quiet",
        "fa-test-locked-ok": f"socket={sock} marker_dir=- allow_locked debug",
    }
    created = []
    for svc, args in stacks.items():
        path = Path("/etc/pam.d") / svc
        path.write_text(
            f"auth [success=2 conv_err=die default=ignore] {module} {args}\n"
            "auth [success=1 default=ignore] pam_unix.so nullok try_first_pass\n"
            "auth requisite pam_deny.so\n"
            "auth required pam_permit.so\n")
        created.append(path)

    mock = subprocess.Popen([PYTHON, str(HERE / "mockd.py"), "--socket", str(sock),
                             "--log", str(log)], stdout=subprocess.PIPE, text=True)
    assert mock.stdout.readline().strip() == "ready"
    yield {"tmp": tmp, "sock": sock, "log": log, "pamtest": build_dir / "tests/pam/pamtest",
           "marker_dir": marker_dir, "module": module}
    mock.terminate()
    mock.wait(5)
    for path in created:
        path.unlink(missing_ok=True)
    subprocess.run(["userdel", "-r", LOCKED_USER], capture_output=True)
    subprocess.run(["userdel", "-r", USER], capture_output=True)


def scenario(**kw):
    return quote(json.dumps(kw, separators=(",", ":")), safe="")


def run(env, scn, *args, service="fa-test", user=USER, timeout=20, ruser_raw=None, extra_env=None):
    """Run pamtest; `scn` is a scenario dict (sent through ruser)."""
    log_path = env["log"]
    before = log_path.read_text().count("\n") if log_path.exists() else 0
    ruser = ruser_raw if ruser_raw is not None else json.dumps(scn, separators=(",", ":"))
    cmd = [str(env["pamtest"]), "--ruser", ruser, *args, service, user]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env={"PATH": os.environ["PATH"], "LANGUAGE": "C", "LC_ALL": "C", **(extra_env or {})})
    events = []
    for line in proc.stdout.splitlines():
        m = re.match(r"^(\S+) (-?\d+) ?(.*)$", line)
        if m:
            events.append((m.group(1), int(m.group(2)), m.group(3)))
    time.sleep(0.45)  # let the mock flush its closing events
    lines = log_path.read_text().splitlines()[before:] if log_path.exists() else []
    r = Result(proc, events, [json.loads(line) for line in lines])
    assert r.count("ERROR") == 0, f"harness reported errors: {r.tags('ERROR')}"
    return r


# ------------------------------------------------------------ sequential mode
def test_sequential_face_ok(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.3, "score": 0.77}})
    assert r.rc == 0
    assert r.count("PROMPT") == 0, "no password must be asked when the face is recognised"
    assert "Looking for your face..." in r.infos()
    assert 250 <= r.at("RESULT") < 1500
    assert r.requests()[0]["fields"]["user"] == USER
    assert r.requests()[0]["fields"]["service"] == "fa-test"


def test_sequential_face_fail_falls_back_to_password(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "FAIL", "delay": 0.2, "reason": "mismatch"}},
            "--answer", f"0:{PASSWORD}")
    assert r.rc == 0, "classic password login must still work after a face failure"
    assert "Face not recognized." in r.infos()
    assert r.count("PROMPT") == 1


def test_sequential_face_fail_wrong_password_is_a_normal_failure(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "FAIL", "delay": 0.1}}, "--answer", "0:wrong")
    assert r.rc != 0
    assert r.count("PROMPT") == 1


def test_forced_sequential_overrides_daemon_mode(env):
    r = run(env, {"accept": {"mode": "parallel", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.3}}, service="fa-test-seq")
    assert r.rc == 0
    assert r.count("PROMPT") == 0, "forced sequential must not open a parallel prompt"


def test_skip_is_silent_and_password_works(env):
    r = run(env, {"skip": "not-enrolled"}, "--answer", f"0:{PASSWORD}")
    assert r.rc == 0
    assert r.infos() == []
    assert r.count("PROMPT") == 1


def test_quiet_option_hides_messages(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.1}}, service="fa-test-quiet")
    assert r.rc == 0 and r.infos() == []


# -------------------------------------------------------------- parallel mode
@pytest.mark.parametrize("mode", ["parallel-tty", "parallel"])
def test_parallel_face_wins_while_prompt_is_pending(env, mode):
    r = run(env, {"accept": {"mode": mode, "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.4}}, "--post-sleep", "300")
    assert r.rc == 0
    assert r.count("PROMPT") == 1, "the password prompt is shown while the camera scans"
    assert 350 <= r.at("RESULT") < 1500
    if mode == "parallel-tty":
        assert r.count("CONV-CANCELLED") == 1, "terminal frontends: the pending prompt is cancelled"
        assert "Face recognized." in r.infos()
    else:
        assert r.count("CONV-CANCELLED") == 0, "graphical frontends: the prompt is abandoned, never cancelled"


LR = "Slowly turn your head to your left, then to your right, then look at the screen."
RL = "Slowly turn your head to your right, then to your left, then look at the screen."
CHALLENGE = [0.15, "STATE phase=challenge seq=lr"]


# ------------------------------------------------------------ the head-turn test
def test_sequential_the_instruction_is_shown_then_the_face_wins(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 6}, "states": [CHALLENGE],
                  "result": {"kind": "OK", "delay": 0.6}})
    assert r.rc == 0 and r.count("PROMPT") == 0
    assert LR in r.infos()
    assert r.infos().index("Looking for your face...") < r.infos().index(LR)


def test_the_other_order_is_worded_the_other_way_round(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 6},
                  "states": [[0.1, "STATE phase=challenge seq=rl"]], "result": {"kind": "OK", "delay": 0.4}})
    assert r.rc == 0 and RL in r.infos() and LR not in r.infos()


def test_sequential_a_failed_head_turn_falls_back_to_the_password(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 6}, "states": [CHALLENGE],
                  "result": {"kind": "FAIL", "delay": 0.5, "reason": "challenge"}}, "--answer", f"0:{PASSWORD}")
    assert r.rc == 0 and r.count("PROMPT") == 1
    assert r.infos()[-2:] == [LR, "Face not recognized."]


def test_parallel_tty_the_pending_prompt_is_cancelled_to_give_the_instruction(env):
    """Terminal frontends: same gesture as for a recognised face (cancel, restore the terminal),
    then the conversation is free for the instruction."""
    r = run(env, {"accept": {"mode": "parallel-tty", "timeout": 6}, "states": [CHALLENGE],
                  "result": {"kind": "OK", "delay": 0.7}}, "--post-sleep", "200")
    assert r.rc == 0
    assert r.count("PROMPT") == 1 and r.count("CONV-CANCELLED") == 1
    assert r.at("CONV-CANCELLED") < r.at("RESULT")
    assert LR in r.infos() and "Face recognized." in r.infos()
    assert r.infos().index(LR) < r.infos().index("Face recognized.")


def test_parallel_tty_a_failed_head_turn_leaves_a_fresh_password_prompt(env):
    r = run(env, {"accept": {"mode": "parallel-tty", "timeout": 6}, "states": [CHALLENGE],
                  "result": {"kind": "FAIL", "delay": 0.5, "reason": "spoof"}},
            "--answer", "30000:never-typed", "--answer", f"0:{PASSWORD}")
    assert r.rc == 0, "pam_unix must prompt again after the face failed (the first prompt was cancelled)"
    assert r.count("CONV-CANCELLED") == 1 and r.count("PROMPT") == 2
    assert r.infos()[-2:] == [LR, "Face not recognized."]


def test_parallel_graphical_frontends_are_never_interrupted_for_an_instruction(env):
    """A dialog that keeps its password prompt open cannot be taken over: the instruction is not shown
    (the daemon does not ask for a head turn in that mode; this is what happens if it does)."""
    r = run(env, {"accept": {"mode": "parallel", "timeout": 6}, "states": [CHALLENGE],
                  "result": {"kind": "FAIL", "delay": 0.4, "reason": "challenge"}}, "--answer", f"900:{PASSWORD}")
    assert r.rc == 0
    assert r.count("CONV-CANCELLED") == 0 and LR not in r.infos()


@pytest.mark.parametrize("mode", ["sequential", "parallel-tty"])
def test_a_daemon_that_goes_silent_after_the_instruction_costs_the_announced_time_only(env, mode):
    """The scan budget (here 30 s) covers recognition *and* head turn; once the instruction is shown
    the module waits for the head turn's own duration (1 s announced) plus its margin, not for the rest
    of the whole budget."""
    # parallel-tty: the first prompt (the module's own) is cancelled, pam_unix asks a second time
    answers = ["--answer", "30000:never-typed"] if mode == "parallel-tty" else []
    r = run(env, {"accept": {"mode": mode, "timeout": 30}, "states": [[0.1, "STATE phase=challenge seq=lr timeout=1"]],
                  "result": {"kind": "HANG"}}, *answers, "--answer", f"0:{PASSWORD}")
    assert r.rc == 0, "the password must still be asked, and accepted"
    assert LR in r.infos() and "Face not recognized." in r.infos()
    assert 3000 <= r.at("RESULT") < 8000, f"gave up after {r.at('RESULT')} ms (expected about 1 s + 3 s of margin)"


def test_parallel_password_typed_first_beats_a_slow_face(env):
    r = run(env, {"accept": {"mode": "parallel-tty", "timeout": 5},
                  "result": {"kind": "OK", "delay": 4}}, "--answer", f"200:{PASSWORD}")
    assert r.rc == 0
    assert r.count("PROMPT") == 1, "pam_unix must reuse the typed password (PAM_AUTHTOK), not ask again"
    assert r.at("RESULT") < 1500
    assert r.log_events("cancelled"), "the scan must be cancelled as soon as a password is typed"


def test_parallel_wrong_password_fails_without_a_second_prompt(env):
    r = run(env, {"accept": {"mode": "parallel", "timeout": 5},
                  "result": {"kind": "HANG"}}, "--answer", "100:nope")
    assert r.rc != 0
    assert r.count("PROMPT") == 1


def test_parallel_face_fails_then_password_still_available(env):
    r = run(env, {"accept": {"mode": "parallel-tty", "timeout": 5},
                  "result": {"kind": "FAIL", "delay": 0.3, "reason": "timeout"}},
            "--answer", f"1200:{PASSWORD}")
    assert r.rc == 0
    assert r.count("PROMPT") == 1
    assert r.at("RESULT") >= 1100, "the prompt must remain usable after the scan failed"


def test_parallel_empty_password_rescans_the_face(env):
    seq = {"sequence": [
        {"accept": {"mode": "parallel-tty", "timeout": 5}, "result": {"kind": "FAIL", "delay": 0.1}},
        {"accept": {"mode": "parallel-tty", "timeout": 5}, "result": {"kind": "OK", "delay": 0.5}},
    ]}
    r = run(env, seq, "--answer", "400:")
    assert r.rc == 0, "an empty password means: try the face again"
    assert len(r.requests()) == 2


def test_parallel_conversation_refusing_prompts_keeps_scanning(env):
    r = run(env, {"accept": {"mode": "parallel", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.6}}, "--refuse-prompts")
    assert r.rc == 0, "a frontend that cannot prompt must not cancel the face scan"


def test_parallel_tty_cancel_of_uncancellable_conversation_is_bounded(env):
    r = run(env, {"accept": {"mode": "parallel-tty", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.2}},
            "--stubborn", "--stubborn-ms", "3500", "--post-sleep", "3500")
    assert r.rc == 0
    assert r.at("RESULT") < 3500, "never hang because a prompt thread cannot be cancelled"
    assert r.count("END") == 1, "process survived the late return of the abandoned prompt"


def test_abandoned_prompt_may_finish_after_pam_end(env):
    r = run(env, {"accept": {"mode": "parallel", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.2}},
            "--stubborn", "--stubborn-ms", "800", "--post-sleep", "1500")
    assert r.rc == 0
    assert r.count("LATE-ANSWER") == 1 and r.count("END") == 1


# ------------------------------------------------------- robustness / security
def test_daemon_hang_never_blocks_the_password(env):
    r = run(env, {"accept": {"mode": "parallel", "timeout": 1},
                  "result": {"kind": "HANG"}}, "--answer", f"2500:{PASSWORD}")
    assert r.rc == 0


def test_daemon_crash_after_accept_falls_back_to_password(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "CLOSE", "delay": 0.1}}, "--answer", f"0:{PASSWORD}")
    assert r.rc == 0


@pytest.mark.parametrize("kind", ["GARBAGE", "NOLF"])
def test_garbage_from_daemon_is_never_a_success(env, kind):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 1},
                  "result": {"kind": kind, "delay": 0.1}}, "--answer", "0:wrong", timeout=30)
    assert r.rc != 0


def test_missing_daemon_is_transparent(env):
    start = time.monotonic()
    r = run(env, {}, "--answer", f"0:{PASSWORD}", service="fa-test-nodaemon")
    assert r.rc == 0
    assert time.monotonic() - start < 2.0
    assert r.infos() == []


def test_untrusted_socket_owner_is_refused(env):
    """A socket created by an unprivileged user must never be believed."""
    # pytest's own temp dirs are 0700: the unprivileged mock needs a public one.
    d = Path(tempfile.mkdtemp(prefix="fa-evil-", dir="/tmp"))
    os.chmod(d, 0o777)
    sock, log = d / "pam.sock", d / "log"
    log.touch()
    os.chmod(log, 0o666)
    evil = subprocess.Popen([PYTHON, str(HERE / "mockd.py"), "--socket", str(sock),
                             "--log", str(log), "--uid", "65534"],
                            stdout=subprocess.PIPE, text=True)
    try:
        assert evil.stdout.readline().strip() == "ready"
        path = Path("/etc/pam.d/fa-test-evil")
        path.write_text(
            f"auth [success=2 conv_err=die default=ignore] {env['module']} socket={sock} marker_dir=- debug\n"
            "auth [success=1 default=ignore] pam_unix.so nullok try_first_pass\n"
            "auth requisite pam_deny.so\nauth required pam_permit.so\n")
        try:
            r = run({**env, "log": log},
                    {"accept": {"mode": "sequential", "timeout": 5},
                     "result": {"kind": "OK", "delay": 0.1}},
                    "--answer", "0:wrong", service="fa-test-evil")
        finally:
            path.unlink(missing_ok=True)
        assert r.rc != 0, "a fake daemon must not be able to log anyone in"
        assert not r.requests(), "no request must be sent to an untrusted peer"
    finally:
        evil.terminate()
        evil.wait(5)
        shutil.rmtree(d, ignore_errors=True)


def test_remote_login_never_uses_the_camera(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.1}},
            "--rhost", "203.0.113.9", "--answer", f"0:{PASSWORD}")
    assert r.rc == 0 and not r.requests()


@pytest.mark.parametrize("var", ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"])
def test_a_process_started_from_an_ssh_session_never_uses_the_camera(env, var):
    """sudo run over ssh inherits SSH_*: the person typing is not at the local camera."""
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.1}},
            "--answer", f"0:{PASSWORD}", extra_env={var: "198.51.100.7 5000 192.0.2.1 22"})
    assert r.rc == 0 and not r.requests()


def test_loopback_rhost_is_local(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.1}}, "--rhost", "localhost")
    assert r.rc == 0 and r.requests()


def test_locked_account_is_never_unlocked_by_a_face(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.1}}, "--answer", "0:wrong", user=LOCKED_USER)
    assert not r.requests(), "usermod -L must disable face login too"


def test_unknown_user_is_ignored(env):
    r = run(env, {"accept": {"mode": "sequential", "timeout": 5},
                  "result": {"kind": "OK", "delay": 0.1}}, "--answer", "0:x", user="no-such-user-xyz")
    assert not r.requests() and r.rc != 0


def test_marker_fast_path_skips_the_daemon_for_non_enrolled_users(env):
    ok = {"accept": {"mode": "sequential", "timeout": 5}, "result": {"kind": "OK", "delay": 0.1}}
    r = run(env, ok, "--answer", f"0:{PASSWORD}", service="fa-test-marker")
    assert r.rc == 0 and not r.requests(), "no marker file: do not even contact the daemon"
    (env["marker_dir"] / USER).touch()
    try:
        r = run(env, ok, service="fa-test-marker")
        assert r.rc == 0 and r.requests() and r.count("PROMPT") == 0
    finally:
        (env["marker_dir"] / USER).unlink()


def test_user_names_with_odd_characters_are_encoded(env):
    # The protocol is line based: control characters must never inject lines.
    odd = "a b\tc\nINJECTED d=e%"
    r = run(env, {}, "--answer", "0:wrong", ruser_raw=odd, user=USER)
    reqs = r.requests()
    assert len(reqs) == 1, "an embedded newline must not create a second request"
    assert reqs[0]["fields"]["ruser"] == odd, "values must round-trip through percent-encoding"
