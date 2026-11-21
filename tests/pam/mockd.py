#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Mock facial-authd speaking the PAM line protocol (docs/PROTOCOL.md).

The scenario of every connection is carried by the `ruser` field of the
VERIFY request: a percent-encoded JSON object, e.g.

    {"accept": {"mode": "parallel", "timeout": 5},
     "result": {"kind": "OK", "delay": 0.4, "score": 0.9}}

or {"skip": "not-enrolled"}.  Every request is appended to --log as JSON.
"""
import argparse
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import unquote


def parse_line(line):
    parts = line.strip().split(" ")
    fields = {}
    for tok in parts[1:]:
        key, _, value = tok.partition("=")
        fields[key] = unquote(value)
    return parts[0], fields


class Mock:
    def __init__(self, path, log, scenario_file=None):
        self.path = path
        self.scenario_file = scenario_file
        self.log = open(log, "a", buffering=1)
        self.lock = threading.Lock()
        self.counts = {}

    def record(self, **entry):
        entry["t"] = round(time.monotonic(), 3)
        with self.lock:
            self.log.write(json.dumps(entry) + "\n")

    def serve(self):
        if os.path.exists(self.path):
            os.unlink(self.path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.path)
        os.chmod(self.path, 0o666)
        srv.listen(16)
        print("ready", flush=True)
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        conn.settimeout(5)
        try:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                data += chunk
            verb, fields = parse_line(data.split(b"\n")[0].decode())
        except Exception as exc:  # noqa: BLE001
            self.record(event="bad-request", error=str(exc))
            return
        key = fields.get("ruser", "") or "{}"
        try:
            scenario = json.loads(key)
        except ValueError:
            scenario = {"skip": "bad-scenario"}
            # Real frontends (sudo) fix PAM_RUSER themselves: use the file.
            if self.scenario_file and os.path.exists(self.scenario_file):
                key = open(self.scenario_file).read()
                scenario = json.loads(key)
        if "sequence" in scenario:  # n-th connection with the same scenario
            with self.lock:
                idx = self.counts.get(key, 0)
                self.counts[key] = idx + 1
            seq = scenario["sequence"]
            scenario = seq[min(idx, len(seq) - 1)]
        self.record(event="request", verb=verb, fields=fields)

        if "skip" in scenario:
            conn.sendall(f"SKIP reason={scenario['skip']}\n".encode())
            conn.close()
            return
        acc = scenario.get("accept", {"mode": "sequential", "timeout": 5})
        conn.sendall(f"ACCEPT mode={acc['mode']} timeout={acc['timeout']}\n".encode())

        res = scenario.get("result", {"kind": "HANG"})
        kind, delay = res["kind"], res.get("delay", 0)
        conn.settimeout(None)
        start = time.monotonic()

        def wait_or_close(seconds):
            """Sleep up to `seconds`; True if the client closed meanwhile."""
            conn.settimeout(0.02)
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                try:
                    if conn.recv(64) == b"":
                        return True
                except socket.timeout:
                    continue
                except OSError:
                    return True
            return False

        for at, line in sorted(scenario.get("states", []), key=lambda e: e[0]):
            wait = at - (time.monotonic() - start)
            if wait > 0 and wait_or_close(wait):
                self.record(event="cancelled", after=round(time.monotonic() - start, 3))
                return
            try:
                conn.sendall((line + "\n").encode())
            except OSError:
                return
            self.record(event="state", line=line)
        delay = max(0.0, delay - (time.monotonic() - start))

        if kind == "HANG":
            wait_or_close(30)
            self.record(event="closed", after=round(time.monotonic() - start, 3))
            return
        if wait_or_close(delay):
            self.record(event="cancelled", after=round(time.monotonic() - start, 3))
            return
        try:
            if kind == "OK":
                conn.sendall(f"OK score={res.get('score', 0.9)}\n".encode())
            elif kind == "FAIL":
                conn.sendall(f"FAIL reason={res.get('reason', 'mismatch')}\n".encode())
            elif kind == "GARBAGE":
                conn.sendall(b"\x00\x01 total nonsense\n")
                wait_or_close(5)
            elif kind == "CLOSE":
                pass
            elif kind == "NOLF":  # an endless line without newline
                conn.sendall(b"A" * 4000)
                wait_or_close(5)
            self.record(event="answered", kind=kind,
                        after=round(time.monotonic() - start, 3))
        except OSError:
            self.record(event="cancelled", after=round(time.monotonic() - start, 3))
        finally:
            # Linger a little so the client can read what we sent.
            if wait_or_close(0.3):
                pass
            conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--uid", type=int, default=None, help="drop to this uid first")
    ap.add_argument("--scenario-file", default=None)
    args = ap.parse_args()
    if args.uid is not None:
        os.setgid(args.uid)
        os.setuid(args.uid)
    Mock(args.socket, args.log, args.scenario_file).serve()


if __name__ == "__main__":
    sys.exit(main())
