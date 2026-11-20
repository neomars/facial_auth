# SPDX-License-Identifier: MIT
"""The socket server must not stop accepting while the daemon lives.

When the accept loop dies the listening socket stays open (systemd and the daemon both hold
it): connections pile up unanswered, and every login of an account with a linked face waits for
the PAM module's timeout.  Whatever goes wrong with one client - no thread left, no file
descriptor left - that client is turned away with "SKIP busy" and the loop carries on.
"""
import errno
import socket
import threading
import time

import pytest

from facial_auth import server as server_mod
from facial_auth.server import MAX_CLIENTS, PamServer


class Decision:
    accept = False
    reason = "stub"


class StubCore:
    def touch(self):
        pass

    def decide(self, req, uid, pid):
        return Decision()


def ask(path, line=b"VERIFY v=1 user=x service=sudo tty= rhost= ruser=\n", timeout=5):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(timeout)
    c.connect(path)
    c.sendall(line)
    try:
        return c.recv(200).decode().strip()
    finally:
        c.close()


@pytest.fixture
def rig(tmp_path):
    path = str(tmp_path / "pam.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(64)
    started = []

    def start(srv):
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        started.append((srv, t))
        return t

    yield path, listener, start
    for srv, t in started:
        srv.stop()
        t.join(3)


def test_the_normal_case(rig):
    path, listener, start = rig
    start(PamServer(StubCore(), listener))
    assert ask(path) == "SKIP reason=stub"


def test_a_thread_that_cannot_be_started_only_turns_that_client_away(rig, monkeypatch):
    path, listener, start = rig
    srv = PamServer(StubCore(), listener)
    failures = {"left": 2}

    class Threading:
        Event, Lock = threading.Event, threading.Lock

        class Thread(threading.Thread):
            def start(self):
                if self.name == "pam-client" and failures["left"] > 0:
                    failures["left"] -= 1
                    raise RuntimeError("can't start new thread")
                super().start()

    monkeypatch.setattr(server_mod, "threading", Threading)
    start(srv)
    assert ask(path) == "SKIP reason=busy"
    assert ask(path) == "SKIP reason=busy"
    assert ask(path) == "SKIP reason=stub", "the accept loop must survive and serve the next client"
    assert srv._clients == 0, "the slot taken for the client that could not be served must be given back"


def test_accept_errors_other_than_a_timeout_are_survived(rig):
    path, listener, start = rig

    class Flaky:
        """EMFILE / ENOMEM from accept() are transient: wait a little, try again."""

        def __init__(self, real):
            self.real, self.failures = real, 3

        def accept(self):
            if self.failures:
                self.failures -= 1
                raise OSError(errno.EMFILE, "Too many open files")
            return self.real.accept()

        def __getattr__(self, name):
            return getattr(self.real, name)

    srv = PamServer(StubCore(), Flaky(listener))
    t = start(srv)
    assert ask(path, timeout=10) == "SKIP reason=stub"
    assert t.is_alive()


def test_stopping_still_ends_the_loop(rig):
    _path, listener, start = rig
    srv = PamServer(StubCore(), listener)
    t = start(srv)
    time.sleep(0.2)
    srv.stop()
    t.join(3)
    assert not t.is_alive()


def test_idle_connections_cannot_starve_a_real_request(rig):
    """The socket is world-writable: somebody can open a crowd of connections and say nothing."""
    path, listener, start = rig
    start(PamServer(StubCore(), listener))
    crowd = []
    try:
        for _ in range(MAX_CLIENTS + 20):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            crowd.append(s)
        t0 = time.monotonic()
        answer = ask(path)
        assert answer in ("SKIP reason=busy", "SKIP reason=stub"), answer
        assert time.monotonic() - t0 < 1.5, "a crowd of silent clients delayed a real request"
    finally:
        for s in crowd:
            s.close()
