# SPDX-License-Identifier: MIT
"""pam_facial_auth.so driven by the *real* sudo on a real pseudo-terminal.

This is the validation of the "parallel-tty" strategy: the password prompt of
sudo stays available while the camera scans; when the face wins, the pending
prompt thread is cancelled and the terminal must be left usable (echo on, no
stolen keystrokes, no half-typed password leaking into the next command).
"""
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not Path("/usr/bin/sudo").exists(),
    reason="needs root and sudo")

HERE = Path(__file__).resolve().parent
USER, PASSWORD = "fasudo", "s3cret"
PYTHON = "/usr/bin/python3.12" if Path("/usr/bin/python3.12").exists() else sys.executable
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class Pty:
    """Run a command with a controlling pseudo-terminal."""

    def __init__(self, argv, env=None):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child
            os.execvpe(argv[0], argv, env or {"PATH": os.environ["PATH"], "TERM": "dumb",
                                              "LANG": "C", "LC_ALL": "C", "HOME": "/tmp"})
        self.buf = ""
        self.status = None

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.fd, 4096)
                except OSError:
                    return
                if not data:
                    return
                self.buf += ANSI.sub("", data.decode(errors="replace"))
            elif self.exited():
                return

    def expect(self, text, timeout=10):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if text in self.buf:
                return True
            self.pump(0.1)
        return text in self.buf

    def send(self, text):
        os.write(self.fd, text.encode())

    def exited(self):
        if self.status is None:
            pid, st = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(st)
        return self.status is not None

    def wait(self, timeout=15):
        end = time.monotonic() + timeout
        while time.monotonic() < end and not self.exited():
            self.pump(0.1)
        self.pump(0.3)
        if not self.exited():
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
            raise TimeoutError(f"process did not exit; output so far:\n{self.buf}")
        return self.status

    def echo_enabled(self):
        return bool(termios.tcgetattr(self.fd)[3] & termios.ECHO)


@pytest.fixture(scope="module")
def sudo_env(build_dir, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sudo")
    os.chmod(tmp, 0o755)
    sock, log, scn = tmp / "pam.sock", tmp / "mock.log", tmp / "scenario.json"
    module = build_dir / "pam" / "pam_facial_auth.so"
    if subprocess.run(["id", USER], capture_output=True).returncode != 0:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", USER], check=True)
    subprocess.run(["chpasswd"], input=f"{USER}:{PASSWORD}\n", text=True, check=True)

    pam = Path("/etc/pam.d/fa-test-sudo")
    pam.write_text(
        f"auth [success=2 conv_err=die default=ignore] {module} socket={sock} marker_dir=- debug\n"
        "auth [success=1 default=ignore] pam_unix.so nullok try_first_pass\n"
        "auth requisite pam_deny.so\nauth required pam_permit.so\n"
        "account required pam_permit.so\nsession required pam_permit.so\n")
    sudoers = Path("/etc/sudoers.d/90-fa-test")
    sudoers.write_text(f"Defaults:{USER} pam_service=fa-test-sudo, timestamp_timeout=0, "
                       f"passwd_tries=3\n{USER} ALL=(ALL) ALL\n")
    sudoers.chmod(0o440)

    mock = subprocess.Popen([PYTHON, str(HERE / "mockd.py"), "--socket", str(sock),
                             "--log", str(log), "--scenario-file", str(scn)],
                            stdout=subprocess.PIPE, text=True)
    assert mock.stdout.readline().strip() == "ready"
    yield {"scn": scn, "log": log}
    mock.terminate()
    mock.wait(5)
    pam.unlink(missing_ok=True)
    sudoers.unlink(missing_ok=True)
    subprocess.run(["userdel", "-r", USER], capture_output=True)


def set_scenario(env, obj):
    env["scn"].write_text(json.dumps(obj))
    env["log"].write_text("")


def requests(env):
    time.sleep(0.4)
    return [json.loads(line) for line in env["log"].read_text().splitlines()
            if '"request"' in line]


def sudo_cmd(args):
    """runuser gives a clean login-less shell with the pty as controlling tty."""
    return ["/usr/sbin/runuser", "-u", USER, "--", "bash", "-c", args]


def test_face_wins_over_the_pending_password_prompt(sudo_env):
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 6},
                            "result": {"kind": "OK", "delay": 1.0, "score": 0.8}})
    # After sudo returns, the shell reports the tty echo flag and a typed-ahead
    # marker: the cancelled prompt must neither steal nor leak keystrokes.
    p = Pty(sudo_cmd("sudo -k; sudo id -un; stty -a | grep -o -- '-\\?echo ' | head -1 | tr -d ' ' "
                     "| sed 's/^/ECHO=/'; read -r -t 3 line; echo \"NEXT=[$line]\""))
    assert p.expect("password for", 8), p.buf          # the password prompt is there...
    assert p.expect("Looking for your face", 1), p.buf  # ...and the face scan announced
    assert p.expect("Face recognized.", 8), p.buf       # face wins while the prompt is pending
    p.send("hello\n")                                   # typed AFTER auth: must reach the shell
    assert p.wait() == 0, p.buf
    assert "root" in p.buf, p.buf
    assert "ECHO=echo" in p.buf, f"terminal left in no-echo mode:\n{p.buf}"
    assert "NEXT=[hello]" in p.buf, f"keystrokes stolen by a dead prompt thread:\n{p.buf}"
    assert p.buf.count("password for") == 1


def test_half_typed_password_never_leaks_when_the_face_wins(sudo_env):
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 6},
                            "result": {"kind": "OK", "delay": 1.2}})
    p = Pty(sudo_cmd("sudo -k; sudo id -un; read -r -t 2 line; echo \"NEXT=[$line]\""))
    assert p.expect("password for", 8)
    p.send("sec")                         # the user starts typing a password...
    assert p.expect("Face recognized.", 8), p.buf
    assert p.wait() == 0
    assert "NEXT=[]" in p.buf, f"typed-ahead password characters leaked:\n{p.buf}"
    assert "sec" not in p.buf.split("password for")[-1].replace("sudo", "")


def test_password_typed_while_scanning_logs_in_and_stops_the_camera(sudo_env):
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 8},
                            "result": {"kind": "OK", "delay": 6.0}})
    p = Pty(sudo_cmd("sudo -k; sudo id -un"))
    assert p.expect("password for", 8)
    time.sleep(0.5)
    p.send(PASSWORD + "\n")
    assert p.wait(10) == 0, p.buf
    assert "root" in p.buf
    assert p.buf.count("password for") == 1, "pam_unix must reuse the typed password"
    assert any(json.loads(line)["event"] == "cancelled"
               for line in sudo_env["log"].read_text().splitlines()), "scan not cancelled"


def test_wrong_password_then_correct_password(sudo_env):
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 8},
                            "result": {"kind": "HANG"}})
    p = Pty(sudo_cmd("sudo -k; sudo id -un"))
    assert p.expect("password for", 8)
    p.send("not-the-password\n")
    assert p.expect("Sorry, try again", 8), p.buf
    assert p.expect("password for", 8)
    p.send(PASSWORD + "\n")
    assert p.wait() == 0 and "root" in p.buf, p.buf


def test_face_fails_then_the_password_prompt_is_still_there(sudo_env):
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 6},
                            "result": {"kind": "FAIL", "delay": 0.4, "reason": "timeout"}})
    p = Pty(sudo_cmd("sudo -k; sudo id -un"))
    assert p.expect("password for", 8)
    time.sleep(1.5)                          # the scan is over, nothing recognised
    p.send(PASSWORD + "\n")
    assert p.wait() == 0 and "root" in p.buf, p.buf


def test_empty_enter_retries_the_face(sudo_env):
    set_scenario(sudo_env, {"sequence": [
        {"accept": {"mode": "parallel-tty", "timeout": 6}, "result": {"kind": "FAIL", "delay": 0.2}},
        {"accept": {"mode": "parallel-tty", "timeout": 6}, "result": {"kind": "OK", "delay": 0.6}}]})
    p = Pty(sudo_cmd("sudo -k; sudo id -un"))
    assert p.expect("password for", 8)
    time.sleep(0.8)
    p.send("\n")                             # "look at me again"
    assert p.wait(15) == 0 and "root" in p.buf, p.buf
    assert len(requests(sudo_env)) == 2


def test_ctrl_c_during_the_scan_aborts_immediately(sudo_env):
    """Signals must reach the prompt thread so sudo reacts as usual, and the
    module must not keep scanning (the HANG scan would last 11 s)."""
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 8},
                            "result": {"kind": "HANG"}})
    p = Pty(sudo_cmd("sudo -k; sudo id -un; echo RC=$?"))
    assert p.expect("password for", 8)
    time.sleep(0.6)
    t0 = time.monotonic()
    p.send("\x03")                           # Ctrl-C
    p.wait(8)                                # the pty child must end by itself
    assert time.monotonic() - t0 < 4, f"Ctrl-C ignored while scanning:\n{p.buf}"
    assert "uid=" not in p.buf and "\nroot" not in p.buf, f"command ran!\n{p.buf}"
    closed = [json.loads(line) for line in sudo_env["log"].read_text().splitlines()
              if json.loads(line)["event"] in ("closed", "cancelled")]
    assert closed and closed[0]["after"] < 4, f"the scan must stop with the prompt: {closed}"


def test_sudo_dash_S_reads_the_password_from_stdin(sudo_env):
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 8},
                            "result": {"kind": "HANG"}})
    p = Pty(sudo_cmd(f"sudo -k; echo '{PASSWORD}' | sudo -S id -un 2>/dev/null"))
    assert p.wait(10) == 0 and "root" in p.buf, p.buf


def test_sudo_dash_n_does_not_hang(sudo_env):
    set_scenario(sudo_env, {"accept": {"mode": "parallel-tty", "timeout": 8},
                            "result": {"kind": "HANG"}})
    p = Pty(sudo_cmd("sudo -k; sudo -n true; echo RC=$?"))
    start = time.monotonic()
    assert p.wait(10) == 0
    assert "RC=1" in p.buf and time.monotonic() - start < 6, p.buf
