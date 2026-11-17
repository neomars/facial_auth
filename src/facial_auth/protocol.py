# SPDX-License-Identifier: MIT
"""Line protocol spoken with pam_facial_auth.so (see docs/PROTOCOL.md)."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote, unquote

PROTO_VERSION = 1
MAX_LINE = 1023

MODES = ("sequential", "parallel", "parallel-tty")

SKIP_REASONS = (
    "not-enrolled", "disabled", "service-denied", "remote-session", "lid-closed",
    "no-camera", "camera-class", "busy", "locked-out", "root-denied",
    "user-unknown", "bad-request", "internal",
)
FAIL_REASONS = ("timeout", "no-face", "mismatch", "spoof", "camera-error",
                "cancelled", "error")


class ProtocolError(ValueError):
    pass


def enc(value: object) -> str:
    """Percent-encode like the C module (RFC 3986 unreserved set)."""
    return quote(str(value), safe="-._~")


def dec(value: str) -> str:
    return unquote(value, errors="replace")


@dataclass
class Request:
    user: str = ""
    service: str = ""
    tty: str = ""
    rhost: str = ""
    ruser: str = ""
    version: int = PROTO_VERSION


def parse_request(line: str) -> Request:
    """Parse ``VERIFY v=1 user=... service=...``; raises ProtocolError."""
    if len(line) > MAX_LINE:
        raise ProtocolError("line too long")
    parts = line.rstrip("\r\n").split(" ")
    if parts[0] != "VERIFY":
        raise ProtocolError(f"unknown verb {parts[0][:20]!r}")
    fields: dict[str, str] = {}
    for tok in parts[1:]:
        if not tok:
            continue
        key, sep, value = tok.partition("=")
        if not sep or not key.isalnum():
            raise ProtocolError("malformed field")
        fields[key] = dec(value)
    try:
        version = int(fields.get("v", "0"))
    except ValueError as exc:
        raise ProtocolError("bad version") from exc
    if version != PROTO_VERSION:
        raise ProtocolError(f"unsupported protocol version {version}")
    user = fields.get("user", "")
    if not user or any(ord(c) < 32 or c == "/" for c in user) or len(user) > 256:
        raise ProtocolError("bad user")
    return Request(user=user, service=fields.get("service", ""),
                   tty=fields.get("tty", ""), rhost=fields.get("rhost", ""),
                   ruser=fields.get("ruser", ""), version=version)


def build_request(req: Request) -> str:
    return (f"VERIFY v={req.version} user={enc(req.user)} service={enc(req.service)} "
            f"tty={enc(req.tty)} rhost={enc(req.rhost)} ruser={enc(req.ruser)}\n")


def accept(mode: str, timeout: float) -> bytes:
    if mode not in MODES:
        raise ValueError(mode)
    return f"ACCEPT mode={mode} timeout={timeout:.1f}\n".encode()


def skip(reason: str) -> bytes:
    return f"SKIP reason={reason}\n".encode()


def state(phase: str) -> bytes:
    return f"STATE phase={phase}\n".encode()


def ok(score: float) -> bytes:
    return f"OK score={score:.3f}\n".encode()


def fail(reason: str) -> bytes:
    return f"FAIL reason={reason}\n".encode()


@dataclass
class Reply:
    kind: str = ""
    fields: dict[str, str] = field(default_factory=dict)


def parse_reply(line: str) -> Reply:
    parts = line.rstrip("\r\n").split(" ")
    if parts[0] not in ("ACCEPT", "SKIP", "STATE", "OK", "FAIL"):
        raise ProtocolError(f"unknown reply {parts[0][:20]!r}")
    fields = {}
    for tok in parts[1:]:
        key, _, value = tok.partition("=")
        fields[key] = dec(value)
    return Reply(parts[0], fields)
