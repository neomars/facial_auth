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
    "no-camera", "camera-class", "camera-unverified", "busy", "locked-out", "root-denied",
    "user-unknown", "bad-request", "internal",
)
# "challenge": the identity was recognised but the head-turn test was not completed;
# "spoof": it showed a flat picture or another person.
FAIL_REASONS = ("timeout", "no-face", "mismatch", "spoof", "challenge", "camera-error",
                "cancelled", "error")
CHALLENGE_SEQUENCES = ("lr", "rl")


class ProtocolError(ValueError):
    pass


# Longest value accepted for each field of a request.  The daemon writes them to the journal and
# any local user can talk to its socket: a field is one printable line of reasonable length or the
# whole request is refused ("SKIP bad-request": the password is asked for as usual).
FIELD_LIMITS = {"user": 256, "service": 64, "tty": 128, "rhost": 256, "ruser": 256}


def _field(name: str, value: str) -> str:
    if len(value) > FIELD_LIMITS[name] or not value.isprintable():
        raise ProtocolError(f"bad {name}")
    return value


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
    user = _field("user", fields.get("user", ""))
    if not user or "/" in user:
        raise ProtocolError("bad user")
    return Request(user=user, service=_field("service", fields.get("service", "")),
                   tty=_field("tty", fields.get("tty", "")), rhost=_field("rhost", fields.get("rhost", "")),
                   ruser=_field("ruser", fields.get("ruser", "")), version=version)


def build_request(req: Request) -> str:
    return (f"VERIFY v={req.version} user={enc(req.user)} service={enc(req.service)} "
            f"tty={enc(req.tty)} rhost={enc(req.rhost)} ruser={enc(req.ruser)}\n")


def accept(mode: str, timeout: float) -> bytes:
    if mode not in MODES:
        raise ValueError(mode)
    return f"ACCEPT mode={mode} timeout={timeout:.1f}\n".encode()


def skip(reason: str) -> bytes:
    return f"SKIP reason={reason}\n".encode()


def state(phase: str, **fields: object) -> bytes:
    """``STATE phase=face``, or ``STATE phase=challenge seq=lr`` (the module shows the instruction)."""
    extra = "".join(f" {k}={enc(v)}" for k, v in fields.items())
    return f"STATE phase={phase}{extra}\n".encode()


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
