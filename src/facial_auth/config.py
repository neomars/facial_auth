# SPDX-License-Identifier: MIT
"""Configuration: defaults < /etc/facial-auth < drop-ins < GUI settings.

The schema below is the single source of truth: it defines the type, the
default value and the *safe range* of every option.  Out-of-range values are
clamped (and reported) rather than trusted: a typo in the configuration must
never make the face check trivially permissive.
"""
from __future__ import annotations

import configparser
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .const import Paths

log = logging.getLogger(__name__)

TRUE = {"1", "true", "yes", "on"}
FALSE = {"0", "false", "no", "off"}

# (section, key) -> (kind, default, low, high_or_choices)
SCHEMA: dict[tuple[str, str], tuple[str, Any, Any, Any]] = {
    ("core", "enabled"): ("bool", True, None, None),
    ("core", "idle_timeout"): ("float", 900.0, 10.0, 86400.0),
    ("core", "log_level"): ("choice", "info", None, ("debug", "info", "warning", "error")),

    ("camera", "device"): ("str", "auto", None, None),
    ("camera", "preference"): ("choice", "ir-first", None, ("ir-first", "rgb-first", "ir-only", "rgb-only")),
    ("camera", "class"): ("choice", "auto", None, ("auto", "ir", "rgb")),
    ("camera", "width"): ("int", 640, 160, 1920),
    ("camera", "height"): ("int", 480, 120, 1080),
    ("camera", "warmup_frames"): ("int", 3, 0, 30),
    ("camera", "dark_threshold"): ("float", 6.0, 0.0, 100.0),
    ("camera", "emitter_command"): ("str", "", None, None),
    ("camera", "emitter_stop_command"): ("str", "", None, None),
    ("camera", "allow_virtual"): ("bool", False, None, None),

    # Cosine similarity of SFace embeddings.  0.363 is the zoo's LFW operating
    # point; below 0.30 would be reckless, so that is the hard floor.
    ("recognition", "threshold"): ("float", 0.45, 0.30, 0.95),
    ("recognition", "required_matches"): ("int", 3, 2, 12),
    ("recognition", "impostor_margin"): ("float", 0.05, 0.0, 0.5),
    ("recognition", "timeout"): ("float", 8.0, 1.0, 30.0),
    ("recognition", "sequential_timeout"): ("float", 4.0, 1.0, 30.0),
    ("recognition", "no_face_timeout"): ("float", 2.0, 0.5, 30.0),
    ("recognition", "min_face_px"): ("int", 90, 40, 600),
    ("recognition", "max_fps"): ("float", 15.0, 2.0, 60.0),
    ("recognition", "parallel_start_delay"): ("float", 0.15, 0.0, 2.0),

    ("liveness", "mode"): ("choice", "basic", None, ("off", "basic")),

    ("security", "max_failures"): ("int", 5, 1, 100),
    ("security", "failure_window"): ("float", 60.0, 5.0, 3600.0),
    ("security", "lockout"): ("float", 60.0, 5.0, 86400.0),
    ("security", "allow_root"): ("bool", False, None, None),
    ("security", "abort_if_lid_closed"): ("bool", True, None, None),
    ("security", "abort_if_remote"): ("bool", True, None, None),
}

# Per-service defaults.  camera class required: any | ir | off.
# RGB webcams can be fooled by a photograph, so privilege escalation
# (sudo, su, polkit) needs an infrared camera unless the admin opts in.
DEFAULT_SERVICES = {
    "gdm-password": "any", "lightdm": "any", "sddm": "any", "login": "any",
    "xscreensaver": "any", "cinnamon-screensaver": "any", "mate-screensaver": "any",
    "sudo": "ir", "sudo-i": "ir", "su": "ir", "su-l": "ir", "polkit-1": "ir",
}
DEFAULT_INTERACTION = {
    "default": "sequential",
    "sudo": "parallel-tty", "sudo-i": "parallel-tty", "su": "parallel-tty",
    "su-l": "parallel-tty", "login": "parallel-tty",
    "polkit-1": "parallel",
}
SERVICE_CLASSES = ("any", "ir", "off")
INTERACTION_MODES = ("sequential", "parallel", "parallel-tty")

# What the GUI/D-Bus API is allowed to change at run time.
WRITABLE = {k for k in SCHEMA if k[0] in ("core", "camera", "recognition", "liveness")
            and k not in {("camera", "emitter_command"), ("camera", "emitter_stop_command"),
                          ("camera", "allow_virtual")}}


@dataclass(frozen=True)
class ServicePolicy:
    camera_class: str   # any | ir | off
    mode: str           # sequential | parallel | parallel-tty


class Config:
    def __init__(self, values: dict[tuple[str, str], Any], services: dict[str, str],
                 interaction: dict[str, str], warnings: list[str] | None = None) -> None:
        self._v = values
        self.services = services
        self.interaction = interaction
        self.warnings = warnings or []

    # -- access -----------------------------------------------------------
    def get(self, section: str, key: str) -> Any:
        return self._v[(section, key)]

    def __getitem__(self, item: tuple[str, str]) -> Any:
        return self._v[item]

    def service(self, name: str) -> ServicePolicy | None:
        """Policy of a PAM service, None when face login is not allowed."""
        cls = self.services.get(name, "off")
        if cls == "off":
            return None
        mode = self.interaction.get(name, self.interaction.get("default", "sequential"))
        if mode not in INTERACTION_MODES:
            mode = "sequential"
        return ServicePolicy(cls, mode)

    def as_dict(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for (sec, key), val in self._v.items():
            out.setdefault(sec, {})[key] = val
        out["services"] = dict(self.services)
        out["interaction"] = dict(self.interaction)
        return out

    # -- loading ----------------------------------------------------------
    @classmethod
    def defaults(cls) -> "Config":
        return cls._build(configparser.ConfigParser(interpolation=None))

    @classmethod
    def load(cls, paths: Paths | None = None) -> "Config":
        """Layer the files; a file that does not parse is ignored *as a whole*.

        Keeping the part before a syntax error would silently drop whatever
        comes after it (e.g. a hardened threshold) and fall back to defaults.
        """
        paths = paths or Paths()
        merged = configparser.ConfigParser(interpolation=None)
        errors: list[str] = []
        files = [paths.defaults, paths.config]
        if paths.config_dropins.is_dir():
            files += sorted(paths.config_dropins.glob("*.conf"))
        files.append(paths.settings)
        for f in files:
            if not Path(f).is_file():
                continue
            single = configparser.ConfigParser(interpolation=None, strict=False,
                                               inline_comment_prefixes=("#", ";"))
            try:
                single.read(f, encoding="utf-8")
            except (configparser.Error, OSError, UnicodeDecodeError) as exc:
                log.error("ignoring configuration file %s: %s", f, exc)
                errors.append(f"{f}: {exc}")
                continue
            merged.read_dict({sec: dict(single[sec]) for sec in single.sections()})
        cfg = cls._build(merged)
        cfg.warnings = errors + cfg.warnings
        return cfg

    @classmethod
    def _build(cls, parser: configparser.ConfigParser) -> "Config":
        warnings: list[str] = []
        values: dict[tuple[str, str], Any] = {}
        for (sec, key), (kind, default, low, high) in SCHEMA.items():
            raw = parser.get(sec, key, fallback=None) if parser.has_section(sec) else None
            values[(sec, key)] = _convert(sec, key, raw, kind, default, low, high, warnings)
        services = dict(DEFAULT_SERVICES)
        if parser.has_section("services"):
            for name, val in parser.items("services"):
                val = val.strip().lower()
                if val in SERVICE_CLASSES:
                    services[name] = val
                else:
                    warnings.append(f"[services] {name}: invalid value {val!r}, ignored")
        interaction = dict(DEFAULT_INTERACTION)
        if parser.has_section("interaction"):
            for name, val in parser.items("interaction"):
                val = val.strip().lower()
                if val in INTERACTION_MODES:
                    interaction[name] = val
                else:
                    warnings.append(f"[interaction] {name}: invalid value {val!r}, ignored")
        for w in warnings:
            log.warning("configuration: %s", w)
        return cls(values, services, interaction, warnings)


def _convert(sec: str, key: str, raw: str | None, kind: str, default: Any, low: Any,
             high: Any, warnings: list[str]) -> Any:
    if raw is None:
        return default
    raw = raw.strip()
    where = f"[{sec}] {key}"
    try:
        if kind == "bool":
            if raw.lower() in TRUE:
                return True
            if raw.lower() in FALSE:
                return False
            raise ValueError("expected true/false")
        if kind in ("int", "float"):
            val = int(raw) if kind == "int" else float(raw)
            if val != val:  # NaN
                raise ValueError("not a number")
            clamped = min(max(val, low), high)
            if clamped != val:
                warnings.append(f"{where}: {val} out of range [{low}, {high}], using {clamped}")
            return clamped
        if kind == "choice":
            if raw.lower() in high:
                return raw.lower()
            raise ValueError(f"expected one of {', '.join(high)}")
        return raw
    except ValueError as exc:
        warnings.append(f"{where}: {exc} (got {raw!r}), using default {default!r}")
        return default


def validate_update(changes: dict[str, Any]) -> dict[tuple[str, str], str]:
    """Validate a GUI/D-Bus change set ``{"section.key": value}``.

    Returns the normalised ``{(section, key): "value"}`` to persist, raises
    ``ValueError`` for anything unknown, not writable or out of range.
    """
    out: dict[tuple[str, str], str] = {}
    for name, value in changes.items():
        sec, _, key = str(name).partition(".")
        if (sec, key) in SCHEMA:
            if (sec, key) not in WRITABLE:
                raise ValueError(f"{name} cannot be changed at run time")
            kind, _default, low, high = SCHEMA[(sec, key)]
            warnings: list[str] = []
            text = str(value).lower() if kind in ("bool", "choice") else str(value)
            converted = _convert(sec, key, text, kind, None, low, high, warnings)
            if warnings:
                raise ValueError(warnings[0])
            out[(sec, key)] = ("true" if converted else "false") if kind == "bool" else str(converted)
        elif sec == "services" and key:
            if str(value) not in SERVICE_CLASSES:
                raise ValueError(f"{name}: expected one of {', '.join(SERVICE_CLASSES)}")
            out[(sec, key)] = str(value)
        elif sec == "interaction" and key:
            if str(value) not in INTERACTION_MODES:
                raise ValueError(f"{name}: expected one of {', '.join(INTERACTION_MODES)}")
            out[(sec, key)] = str(value)
        else:
            raise ValueError(f"unknown option {name}")
    return out


def write_settings(path: Path, changes: dict[tuple[str, str], str]) -> None:
    """Merge ``changes`` into the daemon-owned settings file (atomic write)."""
    parser = configparser.ConfigParser(interpolation=None)
    if path.is_file():
        parser.read(path, encoding="utf-8")
    for (sec, key), val in changes.items():
        if not parser.has_section(sec):
            parser.add_section(sec)
        parser.set(sec, key, val)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("# Managed by facial-authd (changes made from the settings app).\n")
        fh.write("# These values override /etc/facial-auth/facial-auth.conf.\n")
        parser.write(fh)
    tmp.chmod(0o644)
    tmp.replace(path)
