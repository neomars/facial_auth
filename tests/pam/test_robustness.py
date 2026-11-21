# SPDX-License-Identifier: MIT
"""The module must not crash, whatever the daemon (or anybody on that socket) sends.

Everything else in the test-suite shows that a *misbehaving* daemon degrades to
"use the password".  A *crash* inside sudo, login or the screen locker cannot be
degraded by anyone, so it gets its own evidence: the module is rebuilt with
AddressSanitizer + UndefinedBehaviorSanitizer and attacked in two ways.

* tests/pam/fuzz_input.c   - every parser, called directly with random bytes;
* a random daemon         - the whole module, through real libpam, against a
                             server that sends random protocol fragments, hangs
                             up or resets at random moments.

    FA_FUZZ_ITERATIONS=5000000 FA_FUZZ_CONVERSATIONS=3000 pytest tests/pam/test_robustness.py
"""
import os
import random
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="needs root (writes /etc/pam.d)")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
USER = "farobust"
SANITIZE = ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined", "-fno-omit-frame-pointer"]
CFLAGS = ["-g", "-O1", "-Wall", *SANITIZE]
ENV = {"PATH": os.environ["PATH"], "LANGUAGE": "C", "LC_ALL": "C",
       "ASAN_OPTIONS": "detect_leaks=0:exitcode=77:strict_string_checks=1:detect_stack_use_after_return=1",
       "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1:exitcode=78"}
FINDINGS = ("AddressSanitizer", "runtime error", "UndefinedBehaviorSanitizer", "LeakSanitizer")


@pytest.fixture(scope="module")
def sanitized(build_dir, tmp_path_factory):
    """pam_facial_auth.so, pamtest and fuzz_input, all built with the sanitizers."""
    out = tmp_path_factory.mktemp("asan")
    inc = [f"-I{build_dir / 'pam'}", f"-I{ROOT / 'pam'}"]
    jobs = {
        "module": ["gcc", *CFLAGS, "-shared", "-fPIC", *inc, str(ROOT / "pam/pam_facial_auth.c"),
                   "-o", str(out / "pam_facial_auth.so"), "-lpam", "-lpthread", "-ldl", "-Wl,-z,nodelete"],
        "pamtest": ["gcc", *CFLAGS, str(HERE / "pamtest.c"), "-o", str(out / "pamtest"), "-lpam", "-lpthread"],
        "fuzz": ["gcc", *CFLAGS, *inc, str(HERE / "fuzz_input.c"), "-o", str(out / "fuzz_input"),
                 "-lpam", "-lpthread", "-ldl", "-lm"],
    }
    for name, cmd in jobs.items():
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            pytest.skip(f"cannot build {name} with the sanitizers: {r.stderr[-400:]}")
        assert "warning" not in r.stderr, f"{name}: compiler warnings\n{r.stderr}"
    return out


def test_every_parser_survives_hostile_input(sanitized):
    iterations = os.environ.get("FA_FUZZ_ITERATIONS", "300000")
    r = subprocess.run([str(sanitized / "fuzz_input"), iterations, "12345"], capture_output=True, text=True,
                       env=ENV, timeout=600)
    assert r.returncode == 0, f"rc={r.returncode}\n{r.stdout}\n{r.stderr[-3000:]}"
    assert "no finding" in r.stdout


# ---------------------------------------------------------- random daemon
def random_stream(rng):
    """A fragment of 'protocol' made of valid pieces, broken pieces and noise."""
    pieces = [b"ACCEPT mode=sequential timeout=2\n", b"ACCEPT mode=parallel timeout=3\n",
              b"ACCEPT mode=parallel-tty timeout=1\n", b"ACCEPT mode=parallel-tty timeout=nan\n",
              b"ACCEPT\n", b"SKIP reason=x\n", b"STATE phase=detect\n", b"OK score=0.93\n", b"OK\n",
              b"FAIL reason=mismatch\n", b"FAIL\n", b"\n", b"\n\n\n", b"OK score=", b"ACCEPT mode=",
              b"STATE phase=challenge seq=lr\n", b"STATE phase=challenge seq=rl\n", b"STATE phase=challenge\n",
              b"STATE phase=challenge seq=" + b"A" * 300 + b"\n", b"FAIL reason=challenge\n",
              b"timeout=1e999 ", b"\x00", b"\xff\xfe", b"=" * 100, b"A" * 2500, b" " * 1500]
    out = b""
    for _ in range(rng.randint(0, 8)):
        if rng.random() < 0.25:
            out += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 600)))
        else:
            out += rng.choice(pieces)
    return out


class RandomDaemon:
    def __init__(self, path, seed):
        self.path, self.rng = path, random.Random(seed)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.connections = 0

    def start(self):
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(str(self.path))
        os.chmod(self.path, 0o666)
        self.srv.listen(16)
        self.srv.settimeout(0.2)
        threading.Thread(target=self.loop, daemon=True).start()

    def close(self):
        self.stop.set()
        self.srv.close()

    def loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                rng = random.Random(self.rng.getrandbits(64))
                self.connections += 1
            threading.Thread(target=self.talk, args=(conn, rng), daemon=True).start()

    @staticmethod
    def talk(conn, rng):
        """Four kinds of conversation: pure noise, a valid handshake followed by noise, a valid
        handshake then a success, a valid handshake then a refusal."""
        story = rng.random()
        mode = rng.choice(["sequential", "parallel", "parallel-tty"])
        handshake = f"ACCEPT mode={mode} timeout={rng.choice(['0.5', '1', '2', 'nan', '1e99'])}\n".encode()
        try:
            conn.settimeout(1)
            if rng.random() < 0.9:
                conn.recv(1024)                            # the VERIFY line (or nothing)
            if story < 0.30:
                for _ in range(rng.randint(0, 4)):
                    conn.sendall(random_stream(rng))
                    time.sleep(rng.random() * 0.03)
            elif story < 0.55:
                conn.sendall(handshake)
                for _ in range(rng.randint(0, 3)):
                    conn.sendall(random_stream(rng))
                    time.sleep(rng.random() * 0.03)
            elif story < 0.85:
                conn.sendall(handshake)
                time.sleep(rng.random() * 0.4)             # before, during or after the prompt thread starts
                if rng.random() < 0.5:                     # the head-turn test: the prompt thread is cancelled for it
                    conn.sendall(f"STATE phase=challenge seq={rng.choice(['lr', 'rl'])}\n".encode())
                    time.sleep(rng.random() * 0.2)
                conn.sendall(b"STATE phase=detect\n" * rng.randint(0, 3) + b"OK score=0.93\n")
                time.sleep(0.05)
            else:
                conn.sendall(handshake)
                time.sleep(rng.random() * 0.2)
                conn.sendall(b"FAIL reason=mismatch\n")
            how = rng.random()
            if how < 0.2:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            elif how < 0.4:
                time.sleep(0.15)                           # hold on a little, then hang up
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


@pytest.fixture(scope="module")
def random_rig(sanitized, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fuzz")
    os.chmod(tmp, 0o755)
    if subprocess.run(["id", USER], capture_output=True).returncode != 0:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", USER], check=True)
    # A locked account never reaches the daemon (by design): without a password this whole test
    # would only exercise the early return.
    subprocess.run(["chpasswd"], input=f"{USER}:fuzz-password\n", text=True, check=True)
    sock = tmp / "pam.sock"
    stack = Path("/etc/pam.d/fa-fuzz")
    stack.write_text(
        f"auth [success=2 conv_err=die default=ignore] {sanitized}/pam_facial_auth.so "
        f"socket={sock} marker_dir=- connect_timeout=1\n"
        "auth [success=1 default=ignore] pam_unix.so nullok try_first_pass\n"
        "auth requisite pam_deny.so\n"
        "auth required pam_permit.so\n")
    yield {"sock": sock, "tmp": tmp}
    stack.unlink(missing_ok=True)
    subprocess.run(["userdel", "-r", USER], capture_output=True)


def test_a_random_daemon_never_crashes_the_module(sanitized, random_rig):
    count = int(os.environ.get("FA_FUZZ_CONVERSATIONS", "120"))
    seed = int(os.environ.get("FA_FUZZ_SEED", "20240607"))
    daemon = RandomDaemon(random_rig["sock"], seed)
    daemon.start()
    outcomes = {}
    rng = random.Random(seed)
    try:
        for i in range(count):
            args = [str(sanitized / "pamtest")]
            if rng.random() < 0.85:
                args.append("--refuse-prompts")              # prompts fail fast: the run always ends
            else:
                # One scripted answer per prompt that can appear: the module's own prompt (cancelled
                # when the head-turn instruction is shown, which consumes its answer) and pam_unix's.
                for _ in range(3):
                    args += ["--answer", "0:wrong-password"]
            if rng.random() < 0.1:
                args.append("--stubborn")
            r = subprocess.run([*args, "fa-fuzz", USER], capture_output=True, text=True, env=ENV, timeout=60)
            outcomes[r.returncode] = outcomes.get(r.returncode, 0) + 1
            blob = r.stdout + r.stderr
            assert not any(f in blob for f in FINDINGS), f"conversation {i} (seed {seed}):\n{blob[-3000:]}"
            assert "ERROR" not in r.stdout, f"harness error in conversation {i}:\n{r.stdout}"
            assert r.returncode in (0, 1), f"conversation {i}: rc={r.returncode} (crash or sanitizer exit)\n{blob[-2000:]}"
    finally:
        daemon.close()
    assert daemon.connections >= count, \
        f"only {daemon.connections} connections for {count} conversations: the module did not talk to the daemon"
    # A random daemon sometimes says OK (rc 0) and mostly does not (rc 1: wrong/refused password).
    assert set(outcomes) <= {0, 1}
    if count >= 100:
        assert outcomes.get(0, 0) > 0, "the success path was never exercised"
    print(f"\nrandom daemon: {count} conversations, {daemon.connections} connections, outcomes {outcomes}")
