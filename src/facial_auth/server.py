# SPDX-License-Identifier: MIT
"""Unix-socket server speaking the PAM line protocol (docs/PROTOCOL.md)."""
from __future__ import annotations

import logging
import select
import socket
import struct
import threading
import time

from . import protocol
from .core import Core

log = logging.getLogger(__name__)

MAX_CLIENTS = 8
READ_TIMEOUT = 3.0


def peer_credentials(conn: socket.socket) -> tuple[int, int, int]:
    """(pid, uid, gid) of the connecting process, from the kernel."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def peer_gone(conn: socket.socket) -> bool:
    """The module closes the connection to cancel (or sends anything)."""
    try:
        readable, _, _ = select.select([conn], [], [], 0)
        if not readable:
            return False
        return conn.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b""
    except (BlockingIOError, InterruptedError):
        return False
    except OSError:
        return True


class PamServer:
    def __init__(self, core: Core, listener: socket.socket) -> None:
        self.core, self.listener = core, listener
        self._stop = threading.Event()
        self._clients = 0
        self._lock = threading.Lock()

    def serve_forever(self) -> None:
        """Accept clients until stopped.

        This loop must never die while the daemon lives: the socket would stay
        open, connections would pile up unanswered in its queue and every login
        would wait for the module's timeout.  Whatever goes wrong with one
        client (no thread left, no file descriptor left...) it is turned away
        with ``SKIP busy`` and the loop carries on.
        """
        self.listener.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set() or self.listener.fileno() < 0:
                    break                      # closed on purpose
                log.warning("accept failed (%s): retrying", exc)   # EMFILE, ENOMEM...
                time.sleep(0.2)
                continue
            with self._lock:
                busy = self._clients >= MAX_CLIENTS
                if not busy:
                    self._clients += 1
            if not busy:
                try:
                    threading.Thread(target=self._guard, args=(conn,), daemon=True,
                                     name="pam-client").start()
                    continue
                except RuntimeError as exc:    # "can't start new thread" (TasksMax, memory)
                    log.warning("cannot start a client thread (%s): refusing this client", exc)
                    with self._lock:
                        self._clients -= 1
            conn.settimeout(1.0)               # a client that does not read must not stall the loop
            self._send(conn, protocol.skip("busy"))
            conn.close()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.listener.close()
        except OSError:
            pass

    # -------------------------------------------------------------------
    @staticmethod
    def _send(conn: socket.socket, data: bytes) -> bool:
        try:
            conn.sendall(data)
            return True
        except OSError:
            return False

    def _guard(self, conn: socket.socket) -> None:
        try:
            self.handle(conn)
        except Exception:  # noqa: BLE001 - never let a client kill the daemon
            log.exception("error while serving a PAM client")
            self._send(conn, protocol.skip("internal"))
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._lock:
                self._clients -= 1

    def _read_request(self, conn: socket.socket) -> str | None:
        conn.settimeout(READ_TIMEOUT)
        data = b""
        while b"\n" not in data:
            try:
                chunk = conn.recv(256)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            data += chunk
            if len(data) > protocol.MAX_LINE + 1:
                return None
        conn.settimeout(None)
        return data.split(b"\n", 1)[0].decode("utf-8", errors="replace")

    def handle(self, conn: socket.socket) -> None:
        pid, uid, _gid = peer_credentials(conn)
        line = self._read_request(conn)
        if line is None:
            self._send(conn, protocol.skip("bad-request"))
            return
        try:
            req = protocol.parse_request(line)
        except protocol.ProtocolError as exc:
            log.warning("bad request from pid %s: %s", pid, exc)
            self._send(conn, protocol.skip("bad-request"))
            return

        self.core.touch()
        decision = self.core.decide(req, uid, pid)
        if not decision.accept:
            log.info("skip user=%s service=%s reason=%s", req.user, req.service, decision.reason)
            self._send(conn, protocol.skip(decision.reason))
            return
        if not self._send(conn, protocol.accept(decision.mode, decision.accept_timeout)):
            return

        # In parallel modes the prompt appears at once; do not even power the
        # camera for non-interactive callers (sudo -S answers within ms).
        end = time.monotonic() + decision.start_delay
        while time.monotonic() < end:
            if peer_gone(conn):
                return
            time.sleep(0.02)

        res = self.core.verify(
            decision, cancelled=lambda: peer_gone(conn),
            progress=lambda phase, **fields: self._send(conn, protocol.state(phase, **fields)))
        if res.reason == "cancelled":
            return
        self._send(conn, protocol.ok(res.score) if res.ok else protocol.fail(res.reason or "error"))
