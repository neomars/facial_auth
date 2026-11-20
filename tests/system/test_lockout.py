# SPDX-License-Identifier: MIT
"""Anti-lockout proof: whatever breaks in facial-auth, the password keeps working.

Run on an *installed* package (see helpers.py).  Everything goes through the real
`sudo` / `su`, the real `pam_unix` and the real /etc/pam.d/common-auth generated
by pam-auth-update; only the thing on the other end of the socket is made to
misbehave.  For every fault, two facts are checked:

* the correct password is accepted, within a bounded time (never a hang);
* a wrong password is still refused: a fault must never open a door either.

Faults, from the least to the most radical:

    daemon says nonsense / nothing / goes away at any moment of the protocol
    socket missing, stale, not a socket, flooded, planted by another user
    the PAM module file itself missing, empty, truncated, garbage, not a library
    nonsense in the module options of /etc/pam.d/common-auth
    the real facial-authd, started by socket activation, frozen or without a face

What this cannot cover is a module that crashes inside the application (a
segfault cannot be turned into "ignore" by anyone); that is what the sanitizer
and fuzzing runs of tests/pam are for.
"""
import contextlib
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from .helpers import (AUTHENTICATED, COMMON_AUTH, CONNECT_TIMEOUT, MARGIN, MARKER, MARKER_DIR, MODULE,  # noqa: F401
                      PASSWORD, PYTHON, REPORT, SLACK, SOCK, TARGET, USER, WRONG, Pty, box,
                      cut_inside_loaded_segments, drive, reap, requires_installed, su_target, sudo_cmd)

pytestmark = requires_installed

# ------------------------------------------------------------------ the rig
@pytest.fixture(scope="module", autouse=True)
def pristine_system(box):
    """Fail loudly if a test leaves the machine's PAM setup different from how it found it."""
    module_sum = hashlib.sha256(MODULE.read_bytes()).hexdigest()
    stack = COMMON_AUTH.read_bytes()
    MARKER_DIR.mkdir(parents=True, exist_ok=True)
    MARKER.touch()                                   # this user "has a face": the module is fully engaged
    yield
    MARKER.unlink(missing_ok=True)
    SOCK.unlink(missing_ok=True)
    path = os.environ.get("FA_LOCKOUT_REPORT")
    if path:
        Path(path).write_text(json.dumps(REPORT, indent=1))
    assert MODULE.exists() and hashlib.sha256(MODULE.read_bytes()).hexdigest() == module_sum, \
        "a test left the PAM module modified"
    assert COMMON_AUTH.read_bytes() == stack, "a test left /etc/pam.d/common-auth modified"


@pytest.fixture(autouse=True)
def clean_socket():
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    SOCK.unlink(missing_ok=True)
    MARKER.touch()
    yield
    SOCK.unlink(missing_ok=True)


# --------------------------------------------------------- hostile daemons
def read_request(conn):
    conn.settimeout(5)
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(1024)
        if not chunk:
            raise ConnectionError("client left")
        data += chunk
    return data


def hold(conn, seconds=30):
    """Stay silent until the client hangs up (or `seconds` pass)."""
    end = time.monotonic() + seconds
    conn.settimeout(0.1)
    while time.monotonic() < end:
        try:
            if conn.recv(256) == b"":
                return
        except socket.timeout:
            continue
        except OSError:
            return


def accept(mode, timeout="2"):
    return f"ACCEPT mode={mode} timeout={timeout}\n".encode()


def reset(conn):
    """Close with a TCP-style RST (SO_LINGER 0)."""
    import struct
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()


def dribble(conn, data, gap=0.1):
    for i in range(len(data)):
        conn.sendall(data[i:i + 1])
        time.sleep(gap)


# name -> (what the daemon does after reading the request, mode-independent)
BEHAVIOURS = {
    "close-before-reading":     lambda c, m: None,
    "close-after-request":      lambda c, m: read_request(c),
    "silent":                   lambda c, m: (read_request(c), hold(c)),
    "garbage":                  lambda c, m: (read_request(c), c.sendall(b"\x00\xff\x01 garbage \xc3\x28\n"), hold(c)),
    "line-without-newline":     lambda c, m: (read_request(c), c.sendall(b"A" * 4000), hold(c)),
    "huge-line":                lambda c, m: (read_request(c), c.sendall(b"A" * 200_000 + b"\n"), hold(c)),
    "skip":                     lambda c, m: (read_request(c), c.sendall(b"SKIP reason=whatever\n")),
    "ok-before-accept":         lambda c, m: (read_request(c), c.sendall(b"OK score=0.99\n"), hold(c)),
    "accept-then-close":        lambda c, m: (read_request(c), c.sendall(accept(m)), time.sleep(0.4)),
    "accept-then-reset":        lambda c, m: (read_request(c), c.sendall(accept(m)), time.sleep(0.4), reset(c)),
    "accept-then-silent":       lambda c, m: (read_request(c), c.sendall(accept(m)), hold(c)),
    "accept-then-garbage":      lambda c, m: (read_request(c), c.sendall(accept(m) + b"\x00\xff nonsense\n"), hold(c)),
    "accept-then-fail":         lambda c, m: (read_request(c), c.sendall(accept(m) + b"FAIL reason=mismatch\n"), hold(c)),
    "ok-without-newline":       lambda c, m: (read_request(c), c.sendall(accept(m) + b"OK score=0.99"), hold(c)),
    "state-flood":              lambda c, m: (read_request(c), c.sendall(accept(m)), flood(c)),
    "accept-twice":             lambda c, m: (read_request(c), c.sendall(accept(m) * 5), hold(c)),
    "accept-nan-timeout":       lambda c, m: (read_request(c), c.sendall(accept(m, "nan")), hold(c)),
    "accept-inf-timeout":       lambda c, m: (read_request(c), c.sendall(accept(m, "inf")), hold(c)),
    "accept-negative-timeout":  lambda c, m: (read_request(c), c.sendall(accept(m, "-5")), hold(c)),
    "accept-huge-timeout":      lambda c, m: (read_request(c), c.sendall(accept(m, "1e18")), hold(c)),
    "accept-no-timeout":        lambda c, m: (read_request(c), c.sendall(f"ACCEPT mode={m}\n".encode()), hold(c)),
    "accept-unknown-mode":      lambda c, m: (read_request(c), c.sendall(b"ACCEPT mode=bogus timeout=2\n"), hold(c)),
    "accept-very-slowly":       lambda c, m: (read_request(c), dribble(c, accept(m, "2")), hold(c)),
}


def flood(conn, seconds=20):
    end = time.monotonic() + seconds
    conn.settimeout(0.5)
    while time.monotonic() < end:
        try:
            conn.sendall(b"STATE phase=detect\n" * 50)
        except OSError:
            return


# Longest wait before the password prompt, per behaviour: (sequential, parallel).
# Sequential scans first: ACCEPT timeout=2 -> 2s + SLACK; an invalid timeout falls back to 8s.
SEQ_SCAN = 2.0 + SLACK
BUDGET = {
    "close-before-reading":    (0.5, 0.5),
    "close-after-request":     (0.5, 0.5),
    "silent":                  (CONNECT_TIMEOUT, CONNECT_TIMEOUT),
    "garbage":                 (0.5, 0.5),
    "line-without-newline":    (0.5, 0.5),
    "huge-line":               (0.5, 0.5),
    "skip":                    (0.5, 0.5),
    "ok-before-accept":        (0.5, 0.5),
    "accept-then-close":       (1.0, 0.5),
    "accept-then-reset":       (1.0, 0.5),
    "accept-then-silent":      (SEQ_SCAN, 0.5),
    "accept-then-garbage":     (SEQ_SCAN, 0.5),
    "accept-then-fail":        (0.5, 0.5),
    "ok-without-newline":      (SEQ_SCAN, 0.5),
    "state-flood":             (SEQ_SCAN, 0.5),
    "accept-twice":            (SEQ_SCAN, 0.5),
    "accept-nan-timeout":      (8.0 + SLACK, 0.5),
    "accept-inf-timeout":      (8.0 + SLACK, 0.5),
    "accept-negative-timeout": (8.0 + SLACK, 0.5),
    "accept-huge-timeout":     (8.0 + SLACK, 0.5),
    "accept-no-timeout":       (8.0 + SLACK, 0.5),
    "accept-unknown-mode":     (SEQ_SCAN, SEQ_SCAN),        # an unknown mode is scanned sequentially
    "accept-very-slowly":      (3.0 + SEQ_SCAN, 3.0),       # the ACCEPT line takes 3s to arrive
}
SLOW = {"accept-nan-timeout", "accept-inf-timeout", "accept-negative-timeout", "accept-huge-timeout",
        "accept-no-timeout", "accept-very-slowly"}


class HostileDaemon:
    """A facial-authd that misbehaves, listening on the real socket path (as root: trusted)."""

    def __init__(self, behaviour, mode="parallel-tty", backlog=16, serve=True):
        self.behaviour, self.mode, self.backlog, self.serve = behaviour, mode, backlog, serve
        self.connections = 0
        self._stop = threading.Event()

    def __enter__(self):
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(str(SOCK))
        os.chmod(SOCK, 0o666)
        self.srv.listen(self.backlog)
        self.srv.settimeout(0.2)
        if self.serve:
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.srv.close()

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            BEHAVIOURS[self.behaviour](conn, self.mode)
        except (OSError, ConnectionError):
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()


def case_budget(behaviour, mode):
    seq, par = BUDGET[behaviour]
    return seq if mode == "sequential" else par


# ------------------------------------------------- the rig is what it claims
def test_the_rig_is_faithful_a_recognised_face_still_wins():
    """Control: if this fails, every "password still works" result below would be vacuous."""
    stack = [ln for ln in COMMON_AUTH.read_text().splitlines() if ln and not ln.startswith("#")]
    assert "pam_facial_auth.so" in stack[0], "the installed package must be in common-auth"

    class Recognised(HostileDaemon):
        def _serve(self, conn):
            read_request(conn)
            conn.sendall(accept("parallel-tty", "6"))
            time.sleep(0.5)
            conn.sendall(b"OK score=0.93\n")
            time.sleep(0.5)
            conn.close()

    with Recognised("silent") as d:
        p = Pty(sudo_cmd("sudo -k; sudo sh -c 'echo AUTHENTICATED-$(id -un)'"))
        try:
            assert p.wait(15) == 0 and AUTHENTICATED in p.buf, p.buf
            assert d.connections == 1
        finally:
            reap(p)


def test_a_wrong_password_is_refused_on_a_healthy_system():
    """Control for the opposite error: faults below must not be what makes this pass."""
    with HostileDaemon("skip") as d:
        p = Pty(sudo_cmd("sudo -k; sudo -n true; sudo sh -c 'echo AUTHENTICATED-$(id -un)'"))
        try:
            assert p.expect("password for", 8)
            p.send(WRONG + "\n")
            assert p.expect("Sorry, try again", 15)
            assert AUTHENTICATED not in p.buf
            assert d.connections >= 1
        finally:
            reap(p)


# --------------------------------------------- a daemon that misbehaves
FAST = [b for b in BEHAVIOURS if b not in SLOW]


@pytest.mark.parametrize("mode", ["sequential", "parallel-tty", "parallel"])
@pytest.mark.parametrize("behaviour", FAST)
def test_password_works_when_the_daemon_misbehaves(behaviour, mode):
    with HostileDaemon(behaviour, mode) as d:
        drive(f"{behaviour}/{mode}", budget=case_budget(behaviour, mode))
        assert d.connections >= 1, "the module never talked to the fake daemon: nothing was tested"


@pytest.mark.parametrize("mode", ["sequential", "parallel-tty"])
@pytest.mark.parametrize("behaviour", sorted(SLOW))
def test_password_works_when_the_daemon_misbehaves_slowly(behaviour, mode):
    with HostileDaemon(behaviour, mode) as d:
        drive(f"{behaviour}/{mode}", budget=case_budget(behaviour, mode), wrong_first=(mode == "parallel-tty"))
        assert d.connections >= 1


def test_a_password_typed_long_after_the_scan_gave_up_still_works():
    """parallel-tty: the scan is abandoned after timeout+slack, the prompt must stay usable."""
    with HostileDaemon("accept-then-silent", "parallel-tty") as d:
        drive("late-password/parallel-tty", budget=0.5, type_after=SEQ_SCAN + 1.5, wrong_first=False)
        assert d.connections == 1


def test_users_without_a_face_never_pay_for_any_of_it():
    """No marker: the module returns before touching the socket, a frozen daemon costs nothing."""
    MARKER.unlink(missing_ok=True)
    with HostileDaemon("silent", "sequential") as d:
        shown = drive("no-face/silent", budget=0.5)
        assert shown < 1.5
        assert d.connections == 0, "an account without a face must not even contact the daemon"


# ---------------------------------------- no daemon / a socket that is not
def make_stale_socket():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(SOCK))
    s.close()                                    # the file stays, nobody listens


def make_regular_file():
    SOCK.write_text("not a socket")


def make_directory():
    SOCK.mkdir()


def make_fifo():
    os.mkfifo(SOCK)


def make_symlink_to_dev_null():
    SOCK.symlink_to("/dev/null")


def make_dangling_symlink():
    SOCK.symlink_to("/nonexistent/place")


def remove_run_directory():
    shutil.rmtree(SOCK.parent)


def nothing():
    pass


SOCKET_STATES = {
    "absent": nothing,
    "stale-socket-nobody-listens": make_stale_socket,
    "regular-file": make_regular_file,
    "directory": make_directory,
    "fifo": make_fifo,
    "symlink-to-dev-null": make_symlink_to_dev_null,
    "dangling-symlink": make_dangling_symlink,
    "run-directory-missing": remove_run_directory,
}


@pytest.mark.parametrize("state", SOCKET_STATES)
def test_password_works_without_a_usable_daemon_socket(state):
    SOCK.unlink(missing_ok=True)
    SOCKET_STATES[state]()
    try:
        shown = drive(f"socket/{state}", budget=0.5)
        assert shown < 1.5, "a missing daemon must cost nothing"
    finally:
        if SOCK.is_dir() and not SOCK.is_symlink():
            shutil.rmtree(SOCK, ignore_errors=True)
        else:
            SOCK.unlink(missing_ok=True)
        SOCK.parent.mkdir(parents=True, exist_ok=True)


def test_a_daemon_that_never_accepts_and_a_full_queue_do_not_block_logins():
    """The accept loop is dead (thread crash, fd exhaustion...) and the backlog is full:
    a blocking connect() would then wait forever and nobody could log in at all."""
    with HostileDaemon("silent", backlog=0, serve=False) as d:
        fillers = []
        for _ in range(4):                        # occupy every slot the kernel grants
            f = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_NONBLOCK)
            with contextlib.suppress(OSError):
                f.connect(str(SOCK))
            fillers.append(f)
        try:
            drive("never-accepting-full-queue", budget=CONNECT_TIMEOUT)
        finally:
            for f in fillers:
                f.close()


def test_a_socket_planted_by_another_user_is_never_believed():
    """Anybody may create sockets in a directory they control: the module must check WHO answers."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:                                  # child: bind as root, listen as nobody
        try:
            os.close(r)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(str(SOCK))
            os.chmod(SOCK, 0o666)
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            s.listen(16)                          # SO_PEERCRED reports the uid of the listener
            os.write(w, b"x")
            while True:
                conn, _ = s.accept()
                try:
                    conn.sendall(accept("sequential", "2") + b"OK score=0.99\n")
                    time.sleep(0.2)
                finally:
                    conn.close()
        finally:
            os._exit(0)
    os.close(w)
    try:
        assert os.read(r, 1) == b"x"
        # "OK" from an impostor must not authenticate: the (wrong) password is still refused.
        drive("impostor-says-OK", budget=0.5)
    finally:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(r)


# ----------------------------------------------------- the module itself
@contextlib.contextmanager
def module_replaced(kind, tmp):
    backup = Path(tmp) / "pam_facial_auth.so.orig"
    shutil.copy2(MODULE, backup)
    original = backup.read_bytes()

    def put(data):
        staged = MODULE.with_name(".staged-test-module")
        staged.write_bytes(data)
        staged.chmod(0o644)
        os.replace(staged, MODULE)

    try:
        if kind == "missing":
            MODULE.unlink()
        elif kind == "empty":
            put(b"")
        elif kind == "text-file":
            put(b"this is not a shared object\n")
        elif kind == "random-bytes":
            put(os.urandom(30000))
        elif kind == "truncated":
            put(cut_inside_loaded_segments(original))
        elif kind == "elf-header-only":
            put(original[:64] + b"\0" * 4096)
        elif kind == "an-executable":
            put(Path("/bin/true").read_bytes())
        elif kind == "library-without-pam-symbols":
            libm = next(Path("/lib/x86_64-linux-gnu").glob("libm.so.6")).resolve()
            put(libm.read_bytes())
        else:
            raise AssertionError(kind)
        yield
    finally:
        put(original)
        os.chmod(MODULE, 0o644)


TRUNCATED_KILLS_THE_LOADER = pytest.mark.xfail(
    strict=False,
    reason="the dynamic loader maps a truncated library and dies with SIGBUS (any truncated .so does that, "
           "libc included): no PAM setting can ignore a crash. dpkg replaces files atomically, so the installed "
           "module is never half-written; the installer refuses to ENABLE a module that cannot load "
           "(test_the_installer_never_enables_a_module_that_cannot_be_loaded)")
MODULE_FAULTS = ["missing", "empty", "text-file", "random-bytes",
                 pytest.param("truncated", marks=TRUNCATED_KILLS_THE_LOADER),
                 "elf-header-only", "an-executable", "library-without-pam-symbols"]


@pytest.mark.parametrize("kind", MODULE_FAULTS)
def test_password_works_when_the_pam_module_file_is_broken(kind, box):
    """Removed by a bad upgrade, truncated by a full disk, replaced by garbage...:
    libpam treats a module it cannot load as 'unknown' and `default=ignore` skips it."""
    with module_replaced(kind, box["tmp"]):
        shown = drive(f"module/{kind}", budget=0.5)
        assert shown < 1.5


def run_postinst():
    """The maintainer script as installed by dpkg (what `apt install` runs after unpacking)."""
    return subprocess.run(["/var/lib/dpkg/info/facial-auth.postinst", "configure"], capture_output=True,
                          text=True, timeout=180)


def test_the_installer_never_enables_a_module_that_cannot_be_loaded(box):
    """A truncated file kills the loader (SIGBUS) inside sudo, and PAM cannot ignore that: so the
    installer loads the module once in a throw-away process and leaves it out of the stack, or
    takes it out, when that fails."""
    stack = COMMON_AUTH.read_text()
    assert "pam_facial_auth" in stack
    try:
        with module_replaced("truncated", box["tmp"]):
            r = run_postinst()
            assert "NOT enabled" in r.stderr, r.stderr
            assert "pam_facial_auth" not in COMMON_AUTH.read_text(), "a module that cannot load stayed in the stack"
            drive("installer-gate/damaged-module-left-out", budget=0.5)
        r = run_postinst()                         # healthy file again: enabled again
        assert "NOT enabled" not in r.stderr, r.stderr
        assert "pam_facial_auth" in COMMON_AUTH.read_text()
    finally:
        COMMON_AUTH.write_text(stack)              # exactly what we found


@pytest.mark.parametrize("kind", ["missing", "random-bytes"])
def test_su_also_works_when_the_pam_module_file_is_broken(kind, box, su_target):
    with module_replaced(kind, box["tmp"]):
        su_password_works(f"module/{kind}", budget=0.5)


# ------------------------------------------------------------------ su
def su_password_works(name, budget):
    t0 = time.monotonic()
    wrong = Pty(sudo_cmd(f"su {TARGET} -c 'echo AUTHENTICATED-$(id -un)'"))
    try:
        assert wrong.expect("Password", budget + MARGIN), f"[{name}] su shows no prompt\n{wrong.buf}"
        wrong.send(WRONG + "\n")
        assert wrong.expect("Authentication failure", 15), f"[{name}] wrong password not refused\n{wrong.buf}"
        assert "AUTHENTICATED" not in wrong.buf
    finally:
        reap(wrong)
    t0 = time.monotonic()                                # the delay of the run that succeeds
    p = Pty(sudo_cmd(f"su {TARGET} -c 'echo AUTHENTICATED-$(id -un)'"))
    try:
        assert p.expect("Password", budget + MARGIN), f"[{name}] su shows no prompt\n{p.buf}"
        shown = time.monotonic() - t0
        p.send(PASSWORD + "\n")
        assert p.wait(15 + budget) == 0 and f"AUTHENTICATED-{TARGET}" in p.buf, f"[{name}] right password refused\n{p.buf}"
        REPORT.append({"case": f"su/{name}", "prompt_after_s": round(shown, 1), "total_s": round(time.monotonic() - t0, 1)})
    finally:
        reap(p)


@pytest.mark.parametrize("behaviour", ["silent", "garbage", "accept-then-silent", "accept-then-close"])
def test_su_works_when_the_daemon_misbehaves(behaviour, su_target):
    with HostileDaemon(behaviour, "parallel-tty") as d:
        su_password_works(f"{behaviour}/parallel-tty", budget=case_budget(behaviour, "parallel-tty"))
        assert d.connections >= 1


def test_su_works_when_nobody_listens(su_target):
    su_password_works("no-daemon", budget=0.5)


# ------------------------------------------- configuration gone wrong
@contextlib.contextmanager
def common_auth_options(options):
    original = COMMON_AUTH.read_text()
    lines = original.splitlines(keepends=True)
    idx = next(i for i, ln in enumerate(lines) if "pam_facial_auth.so" in ln and not ln.startswith("#"))
    lines[idx] = lines[idx].rstrip() + " " + options + "\n"
    COMMON_AUTH.write_text("".join(lines))
    try:
        yield
    finally:
        COMMON_AUTH.write_text(original)


JUNK_OPTIONS = {
    "unknown-and-malformed": "bogus_option foo=bar mode=nonsense connect_timeout=abc max_rescans=-5 =",
    "socket-path-too-long": "socket=/" + "a" * 300,
    "extreme-numbers": "connect_timeout=1e999 max_rescans=99999999999999999999",
    "unusable-paths": "socket=/proc/self/mem marker_dir=/proc/self/nonexistent",
    "empty-values": "socket= marker_dir= mode= connect_timeout=",
}


@pytest.mark.parametrize("label", JUNK_OPTIONS)
def test_password_works_with_nonsense_module_options(label):
    with common_auth_options(JUNK_OPTIONS[label]):
        with HostileDaemon("silent", "sequential"):
            drive(f"options/{label}", budget=CONNECT_TIMEOUT)


# --------------------------------------- the real daemon, really activated
DAEMON = "/usr/libexec/facial-auth/facial-authd"
needs_real_daemon = pytest.mark.skipif(
    not (shutil.which("systemd-socket-activate") and shutil.which("dbus-daemon") and shutil.which("setpriv")
         and Path(DAEMON).exists()),
    reason="needs systemd-socket-activate, dbus-daemon, setpriv")


@pytest.fixture
def real_daemon():
    """The installed facial-authd, started the way facial-authd.socket does: the daemon
    receives the listening socket (LISTEN_FDS) and runs as the unprivileged facial-auth user."""
    work = Path(tempfile.mkdtemp(prefix="fa-lockout-"))
    work.chmod(0o755)
    bus_sock = work / "bus.sock"
    conf = work / "bus.conf"
    conf.write_text(f"""<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path={bus_sock}</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow own="*"/><allow send_type="method_call"/>
<allow send_type="signal"/><allow send_requested_reply="true" send_type="method_return"/>
<allow send_requested_reply="true" send_type="error"/><allow receive_type="method_call"/>
<allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/>
</policy></busconfig>""")
    bus = subprocess.run(["dbus-daemon", f"--config-file={conf}", "--fork", "--print-pid"],
                         capture_output=True, text=True, check=True)
    bus_pid = int(bus.stdout.split()[0])
    log = work / "daemon.log"
    proc = subprocess.Popen(
        ["systemd-socket-activate", "-l", str(SOCK), f"--setenv=DBUS_SYSTEM_BUS_ADDRESS=unix:path={bus_sock}",
         "setpriv", "--reuid=facial-auth", "--regid=facial-auth", "--groups=video",
         PYTHON, DAEMON, "--debug"],
        stdout=open(log, "wb"), stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 10
    while not SOCK.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert SOCK.exists(), log.read_text()
    SOCK.chmod(0o666)

    class Handle:
        pass
    h = Handle()
    h.log = lambda: log.read_text()
    h.pids = lambda: subprocess.run(["pgrep", "-f", f"{DAEMON}"], capture_output=True, text=True).stdout.split()
    yield h
    for pid in h.pids():
        with contextlib.suppress(ProcessLookupError):
            os.kill(int(pid), signal.SIGCONT)
            os.kill(int(pid), signal.SIGKILL)
    proc.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(5)
    with contextlib.suppress(ProcessLookupError):
        os.kill(bus_pid, signal.SIGTERM)
    SOCK.unlink(missing_ok=True)
    shutil.rmtree(work, ignore_errors=True)


@needs_real_daemon
def test_the_real_daemon_started_on_demand_says_not_enrolled_and_the_password_works(real_daemon):
    shown = drive("real-daemon/marker-but-no-face", budget=3.0)
    assert shown < 3.0 + MARGIN
    assert "skip user=fasystem service=sudo reason=not-enrolled" in real_daemon.log(), real_daemon.log()


@needs_real_daemon
def test_a_frozen_real_daemon_costs_a_few_seconds_not_the_login(real_daemon):
    # Wake it up (activation), then freeze it: it still owns the socket but never answers.
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(str(SOCK))
    c.sendall(b"VERIFY v=1 user=nobody service=sudo tty= rhost= ruser=\n")
    c.settimeout(10)
    assert c.recv(100).startswith(b"SKIP")
    c.close()
    pids = real_daemon.pids()
    assert pids, "the daemon should be running by now"
    for pid in pids:
        os.kill(int(pid), signal.SIGSTOP)
    drive("real-daemon/frozen", budget=CONNECT_TIMEOUT)


@needs_real_daemon
def test_a_crowd_of_idle_connections_only_costs_the_face_never_the_password(real_daemon):
    """Anyone can connect to the 0666 socket: the daemon caps its workers, the rest gets SKIP busy."""
    crowd = []
    try:
        for _ in range(60):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(str(SOCK))
            crowd.append(s)                                # connected, says nothing
        drive("real-daemon/60-idle-connections", budget=CONNECT_TIMEOUT)
    finally:
        for s in crowd:
            s.close()
