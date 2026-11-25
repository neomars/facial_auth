# SPDX-License-Identifier: MIT
"""Daemon core: policy, camera selection, verification, enrollment.

Transport-agnostic (no socket, no D-Bus): the PAM server and the D-Bus service
are thin layers over this class, which keeps it unit-testable.
"""
from __future__ import annotations

import logging
import os
import pwd
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import numpy as np

from . import challenge, irtest, models, protocol, scan, system, v4l2
from .camera import CameraBroker, CameraBusy, CameraError, FrameSource, OpenCVCamera
from .config import Config
from .const import Paths
from .engine import EngineUnavailable, FaceEngine, load_engine
from .ratelimit import FailureLimiter
from .store import FaceStore
from .trust import CameraTrust

log = logging.getLogger(__name__)

NO_LOGIN_SHELLS = ("nologin", "false")
CAMERA_CACHE_SECONDS = 5.0
# The accounts offered to the settings application.  A directory (LDAP...) can hold thousands: the
# enumeration is remembered for a short while, and the answer is bounded (the accounts that matter -
# the person asking, accounts with faces or a session - come first, the enumeration fills what is left).
DIRECTORY_CACHE_SECONDS = 20.0
MAX_LISTED_USERS = 2000
MAX_EXTRA_USERS = 200


class ApiError(Exception):
    """An error with a stable machine readable code (mapped to a D-Bus error)."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass
class Decision:
    accept: bool
    reason: str = ""
    uid: int = -1
    username: str = ""
    service: str = ""
    mode: str = "sequential"
    timeout: float = 4.0
    no_face_timeout: float | None = None
    start_delay: float = 0.0
    camera: v4l2.CameraInfo | None = None
    camera_class: str = ""
    challenge: bool = False          # the person must also pass the head-turn test
    challenge_timeout: float = 0.0

    @property
    def accept_timeout(self) -> float:
        """What the PAM module is told: it waits for the scan *and* the head turn."""
        return self.timeout + self.challenge_timeout


def _skip(reason: str, **kw) -> Decision:
    return Decision(False, reason, **kw)


class Core:
    def __init__(self, paths: Paths | None = None, cfg: Config | None = None,
                 store: FaceStore | None = None,
                 engine_loader: Callable[[], FaceEngine] | None = None,
                 camera_factory: Callable[[v4l2.CameraInfo, str], FrameSource] | None = None,
                 camera_lister: Callable[[], list[v4l2.CameraInfo]] | None = None,
                 session_probe: system.SessionProbe | None = None,
                 lid_probe: Callable[[], bool] | None = None,
                 models_probe: Callable[[], dict] | None = None,
                 owner: tuple[int, int] | None = None) -> None:
        self.paths = paths or Paths()
        self.cfg = cfg or Config.load(self.paths)
        self.store = store or FaceStore(self.paths, owner=owner)
        self.trust = CameraTrust(self.paths, owner=owner)
        self._engine_loader = engine_loader or (lambda: load_engine(self.paths))
        self._camera_factory = camera_factory or self._default_camera
        self._camera_lister = camera_lister or (lambda: v4l2.discover(self.paths))
        self.sessions = session_probe or system.NullProbe()
        self._lid = lid_probe or (lambda: system.lid_closed(self.paths))
        self._models = models_probe or (lambda: models.status(self.paths))
        self.broker = CameraBroker()
        self.limiter = FailureLimiter(self.cfg["security", "max_failures"],
                                      self.cfg["security", "failure_window"],
                                      self.cfg["security", "lockout"],
                                      growth=self.cfg["security", "lockout_growth"],
                                      max_lockout=self.cfg["security", "lockout_max"],
                                      state_file=self.paths.state / "lockout.json")
        self._cams: tuple[float, list[v4l2.CameraInfo]] = (0.0, [])
        self._lock = threading.Lock()
        self.active = 0                       # running scans / sessions (idle timer)
        self.last_activity = time.monotonic()
        self.started = time.time()
        self.directory_ttl = DIRECTORY_CACHE_SECONDS
        self._directory: tuple[float, list[pwd.struct_passwd]] | None = None
        self._directory_lock = threading.Lock()

    # ------------------------------------------------------------ plumbing
    def reload(self) -> None:
        self.cfg = Config.load(self.paths)
        self._directory = None
        self.limiter.configure(self.cfg["security", "max_failures"],
                               self.cfg["security", "failure_window"],
                               self.cfg["security", "lockout"],
                               growth=self.cfg["security", "lockout_growth"],
                               max_lockout=self.cfg["security", "lockout_max"])

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def idle_for(self) -> float:
        return 0.0 if self.active else time.monotonic() - self.last_activity

    def engine(self) -> FaceEngine:
        try:
            return self._engine_loader()
        except EngineUnavailable as exc:
            raise ApiError("engine-unavailable", str(exc)) from exc

    def cameras(self, refresh: bool = False) -> list[v4l2.CameraInfo]:
        with self._lock:
            ts, cams = self._cams
            if refresh or time.monotonic() - ts > CAMERA_CACHE_SECONDS:
                cams = self._camera_lister()
                self._cams = (time.monotonic(), cams)
            return cams

    def _default_camera(self, info: v4l2.CameraInfo, camera_class: str) -> FrameSource:
        c = self.cfg
        return OpenCVCamera(info.path, info.name, camera_class, c["camera", "width"],
                            c["camera", "height"], c["camera", "warmup_frames"],
                            c["camera", "emitter_command"], c["camera", "emitter_stop_command"])

    def pick_camera(self, classes: set[str]) -> tuple[v4l2.CameraInfo, str] | None:
        """Best camera among the permitted classes (infrared first)."""
        c = self.cfg
        for cls in ("ir", "rgb"):
            if cls not in classes:
                continue
            cam = v4l2.select(self.cameras(), c["camera", "device"], c["camera", "preference"],
                              c["camera", "class"], cls, c["camera", "allow_virtual"])
            if cam:
                return cam, cls
        return None

    # ---------------------------------------------------- PAM verification
    def decide(self, req: protocol.Request, peer_uid: int, peer_pid: int) -> Decision:
        """All the cheap checks, in order, before any camera is touched."""
        cfg = self.cfg
        if not cfg["core", "enabled"]:
            return _skip("disabled")
        try:
            pw = pwd.getpwnam(req.user)
        except KeyError:
            return _skip("user-unknown")
        d = dict(uid=pw.pw_uid, username=pw.pw_name, service=req.service)
        # An unprivileged caller (screen locker run as the user) may only ask
        # about itself; root (sudo, su, gdm, polkit) may ask about anyone.
        if peer_uid != 0 and peer_uid != pw.pw_uid:
            return _skip("bad-request", **d)
        if pw.pw_uid == 0 and not cfg["security", "allow_root"]:
            return _skip("root-denied", **d)
        svc = cfg.service(req.service)
        if svc is None:
            return _skip("service-denied", **d)
        if cfg["security", "abort_if_remote"]:
            if req.rhost and req.rhost not in ("localhost", "127.0.0.1", "::1", "localhost.localdomain"):
                return _skip("remote-session", **d)
            if self.sessions.is_remote(peer_pid):
                return _skip("remote-session", **d)
        if cfg["security", "abort_if_lid_closed"] and self._lid():
            return _skip("lid-closed", **d)
        enrolled = self.store.classes_for(pw.pw_uid)
        if not enrolled:
            return _skip("not-enrolled", **d)
        if self.limiter.remaining(pw.pw_uid) > 0:
            return _skip("locked-out", **d)
        allowed = {"any": {"ir", "rgb"}, "ir": {"ir"}}[svc.camera_class] & enrolled
        picked = self.pick_camera(allowed) if allowed else None
        if picked is None:
            cams = [c for c in self.cameras() if c.usable]
            return _skip("camera-class" if cams else "no-camera", **d)
        if (svc.camera_class == "ir" and cfg["camera", "require_ir_check"]
                and not self.trust.is_verified(picked[0])):
            # "infrared" is a guess made from pixel formats: a monochrome sensor without an infrared
            # filter sees a phone screen.  Until `facial-auth check-camera` shows otherwise it is
            # not what this service asked for.
            log.info("%s: camera %s is not verified as infrared (facial-auth check-camera)",
                     req.service, picked[0].name)
            return _skip("camera-unverified", **d)
        status = self._models()
        if not status["ok"]:
            log.error("models missing: %s", status["missing"])
            return _skip("internal", **d)
        with_challenge = cfg["liveness", "mode"] == "challenge"
        mode = svc.mode
        if with_challenge and mode == "parallel":
            # The instruction ("turn your head...") needs a conversation of its own, which a graphical
            # dialog that keeps its password prompt open cannot give: scan first, then ask.
            mode = "sequential"
        parallel = mode != "sequential"
        return Decision(
            True, "", mode=mode,
            timeout=cfg["recognition", "timeout" if parallel else "sequential_timeout"],
            no_face_timeout=None if parallel else cfg["recognition", "no_face_timeout"],
            start_delay=cfg["recognition", "parallel_start_delay"] if parallel else 0.0,
            camera=picked[0], camera_class=picked[1], challenge=with_challenge,
            challenge_timeout=cfg["liveness", "challenge_timeout"] if with_challenge else 0.0, **d)

    def verify(self, d: Decision, cancelled: Callable[[], bool],
               progress: Callable[[str], None] | None = None) -> scan.ScanResult:
        """Run the scan for an accepted decision and record the outcome."""
        self.touch()
        with self._lock:
            self.active += 1
        try:
            engine = self.engine()
            templates = self.store.templates_for(d.uid, d.camera_class, engine.model_id)
            if not len(templates):
                return scan.ScanResult(False, "error")
            rivals = [t for uid, t in self.store.all_templates(d.camera_class, engine.model_id).items()
                      if uid != d.uid]
            others = np.vstack(rivals) if rivals else None
            try:
                sequence = challenge.draw_sequence() if d.challenge else ""
                with self.broker.use(lambda: self._camera_factory(d.camera, d.camera_class),
                                     who=f"verify:{d.username}") as cam:
                    res = scan.Scanner(engine).verify(self.cfg, cam, templates, others, d.timeout,
                                                      d.no_face_timeout, cancelled, progress, sequence)
            except CameraBusy as exc:
                log.warning("%s", exc)
                return scan.ScanResult(False, "camera-error")
            except CameraError as exc:
                log.error("camera error: %s", exc)
                return scan.ScanResult(False, "camera-error")
            self._record(d, res)
            return res
        except ApiError as exc:
            log.error("%s", exc)
            return scan.ScanResult(False, "error")
        finally:
            with self._lock:
                self.active -= 1
            self.touch()

    def _record(self, d: Decision, res: scan.ScanResult) -> None:
        if res.ok:
            self.limiter.record_success(d.uid)
        elif res.reason in ("mismatch", "spoof", "challenge") and self.limiter.record_failure(d.uid):
            log.warning("face login for %s locked for %.0fs after repeated failures",
                        d.username, self.limiter.remaining(d.uid))
        log.info("verify user=%s service=%s camera=%s ok=%s reason=%s score=%.2f frames=%d "
                 "duration=%.1fs%s", d.username, d.service, d.camera_class, res.ok,
                 res.reason or "-", res.score, res.frames, res.duration,
                 "" if not res.challenge else " head-turn=%(sequence)s peak=%(peak)s steps=%(steps)s" % {
                     "sequence": res.challenge.get("sequence", "-"), "peak": res.challenge.get("peak", "-"),
                     "steps": res.challenge.get("steps", "-")})

    # --------------------------------------------------------- management
    def _looks_human(self, pw: pwd.struct_passwd) -> bool:
        if pw.pw_uid == 0 and not self.cfg["security", "allow_root"]:
            return False
        return (self.cfg["core", "uid_min"] <= pw.pw_uid <= self.cfg["core", "uid_max"]
                and not pw.pw_shell.endswith(NO_LOGIN_SHELLS))

    def human_users(self) -> list[pwd.struct_passwd]:
        """The accounts the system *enumerates*: the local ones, and a directory's (LDAP, SSSD, AD) only
        when its client is set to enumerate, which most are not.  See listed_users() for the rest."""
        if not self.cfg["core", "list_directory"]:
            return []
        with self._directory_lock:
            if self._directory is not None and time.monotonic() - self._directory[0] < self.directory_ttl:
                return self._directory[1]
            try:
                found = [pw for pw in pwd.getpwall() if self._looks_human(pw)]
            except Exception as exc:  # noqa: BLE001 - an NSS module can fail in many ways
                log.warning("cannot enumerate the user database: %s", exc)
                found = []
            found.sort(key=lambda p: p.pw_uid)
            self._directory = (time.monotonic(), found)
            return found

    def _extra_user_names(self) -> list[str]:
        names: list[str] = []
        for token in self.cfg["core", "extra_users"].replace(",", " ").split():
            if protocol.valid_user_name(token) and token not in names:
                names.append(token)
            if len(names) >= MAX_EXTRA_USERS:
                break
        return names

    def listed_users(self, caller_uid: int | None = None) -> list[pwd.struct_passwd]:
        """Accounts offered by the settings application and `facial-auth users`.

        A directory account is usually *not* in the enumeration, so the list is built from what the
        machine knows about people: the one using the application, accounts that have faces, accounts
        with a session (a directory user who signed in is there), the logins named in the settings,
        and then whatever the system can enumerate.  Any other account is added by typing its login
        (lookup_user).  Accounts are listed once, in the order of importance, bounded.
        """
        found: dict[int, pwd.struct_passwd] = {}

        def known(uid: int) -> pwd.struct_passwd | None:
            try:
                return pwd.getpwuid(uid)
            except (KeyError, OverflowError):
                return None

        def add(pw: pwd.struct_passwd | None, *, filtered: bool = False) -> None:
            if pw is None or pw.pw_uid in found or len(found) >= MAX_LISTED_USERS:
                return
            if pw.pw_uid == 0 and not self.cfg["security", "allow_root"]:
                return
            if filtered and not self._looks_human(pw):
                return
            found[pw.pw_uid] = pw

        if caller_uid is not None:
            add(known(caller_uid))
        for uid in self.store.users():
            add(known(uid))
        sessions_of = getattr(self.sessions, "users", None)
        try:
            session_uids = sessions_of() if sessions_of else []
        except Exception as exc:  # noqa: BLE001
            log.debug("cannot list the accounts with a session: %s", exc)
            session_uids = []
        for uid in session_uids:
            add(known(uid), filtered=True)
        for name in self._extra_user_names():
            try:
                add(pwd.getpwnam(name))
            except KeyError:
                pass
        for pw in self.human_users():
            add(pw)
        return sorted(found.values(), key=lambda p: p.pw_uid)

    def user_summary(self, pw: pwd.struct_passwd, enrolled: set[int] | None = None) -> dict:
        """``enrolled``: the uids that have a face file; an account outside it is not read from disk."""
        if enrolled is not None and pw.pw_uid not in enrolled:
            count, enabled = 0, True
        else:
            faces = self.store.load(pw.pw_uid)
            count, enabled = len(faces.faces), faces.enabled
        return {"uid": pw.pw_uid, "name": pw.pw_name,
                "realname": pw.pw_gecos.split(",")[0] or pw.pw_name,
                "faces": count, "enabled": enabled,
                "locked_out": int(self.limiter.remaining(pw.pw_uid))}

    def account_of(self, username: str) -> pwd.struct_passwd:
        if not protocol.valid_user_name(username):
            raise ApiError("bad-argument", "not a valid account name")
        try:
            pw = pwd.getpwnam(username)
        except KeyError as exc:
            raise ApiError("unknown-user", f"no such user: {username} (the system does not know this account: "
                           f"check 'getent passwd {username}')") from exc
        if pw.pw_uid == 0 and not self.cfg["security", "allow_root"]:
            raise ApiError("not-allowed", "root cannot use face authentication")
        return pw

    def uid_of(self, username: str) -> int:
        return self.account_of(username).pw_uid

    def lookup_user(self, username: str) -> dict:
        """An account of the system, found by its login (what the list cannot show)."""
        return self.user_summary(self.account_of(username))

    def analyze(self, data: bytes) -> dict:
        try:
            frame = scan.decode_image(data)
        except ValueError as exc:
            raise ApiError("bad-image", str(exc)) from exc
        return scan.analyze(self.engine(), frame, self.cfg["recognition", "min_face_px"]).public()

    def add_face(self, username: str, label: str, images: list[bytes], camera_class: str,
                 source: str) -> dict:
        uid = self.uid_of(username)
        if camera_class not in ("rgb", "ir"):
            raise ApiError("bad-argument", "camera_class must be rgb or ir")
        frames = []
        for i, data in enumerate(images):
            try:
                frames.append(scan.decode_image(data))
            except ValueError as exc:
                raise ApiError("bad-image", f"image {i + 1}: {exc}") from exc
        engine = self.engine()
        try:
            vectors = scan.embed_images(engine, frames, self.cfg["recognition", "min_face_px"])
        except scan.EnrollError as exc:
            detail = ", ".join(f"#{i + 1}: {why}" for i, why in sorted(exc.details.items()))
            raise ApiError(exc.code, f"{exc}" + (f" ({detail})" if detail else "")) from exc
        from .store import StoreError
        try:
            rec = self.store.add_face(uid, label, np.stack(vectors), camera_class, engine.model_id, source)
        except StoreError as exc:
            raise ApiError("store-error", str(exc)) from exc
        self.limiter.reset(uid)
        log.info("face %s linked to %s (%d samples, %s, source=%s)", rec.id, username,
                 len(vectors), camera_class, source)
        return rec.public()

    def test_user(self, username: str, camera_class: str | None, cancelled: Callable[[], bool],
                  progress: Callable[..., None] | None = None) -> dict:
        """Interactive check used by the settings app ("does it recognise me?")."""
        uid = self.uid_of(username)
        enrolled = self.store.classes_for(uid)
        classes = ({camera_class} & enrolled) if camera_class else enrolled
        if not classes:
            raise ApiError("not-enrolled", "no face of this kind is linked to the account")
        picked = self.pick_camera(classes)
        if picked is None:
            raise ApiError("no-camera", "no suitable camera found")
        with_challenge = self.cfg["liveness", "mode"] == "challenge"
        d = Decision(True, uid=uid, username=username, service="test", mode="sequential",
                     timeout=self.cfg["recognition", "timeout"], camera=picked[0], camera_class=picked[1],
                     challenge=with_challenge,
                     challenge_timeout=self.cfg["liveness", "challenge_timeout"] if with_challenge else 0.0)
        res = self.verify(d, cancelled, progress)
        out = {"ok": res.ok, "reason": res.reason, "score": round(res.score, 3),
               "camera_class": picked[1], "duration": round(res.duration, 2)}
        if res.challenge:
            out["head_turn"] = ", ".join(f"{k}={v}" for k, v in sorted(res.challenge.items()))
        return out

    def verify_infrared(self, cancelled: Callable[[], bool], progress: Callable[..., None] | None = None,
                        baseline_s: float = 2.0, show_s: float = 6.0, clock: Callable[[], float] = time.monotonic,
                        sleep: Callable[[float], None] = time.sleep) -> dict:
        """Show the infrared camera a bright phone screen (irtest.py) and record whether it saw it."""
        picked = self.pick_camera({"ir"})
        if picked is None:
            raise ApiError("no-camera", "no infrared camera found")
        info, _cls = picked
        acc = irtest.Accumulator(self.cfg["camera", "dark_threshold"])
        with self._lock:
            self.active += 1
        try:
            with self.broker.use(lambda: self._camera_factory(info, "ir"), who="check-camera") as cam:
                start, told = clock(), False
                if progress:
                    progress("baseline")
                while True:
                    elapsed = clock() - start
                    if cancelled():
                        raise ApiError("cancelled", "the check was cancelled")
                    if elapsed >= baseline_s + show_s:
                        break
                    if elapsed >= baseline_s and not told:
                        told = True
                        if progress:
                            progress("show-screen")
                    frame = cam.read()
                    if frame is None:
                        sleep(0.03)
                        continue
                    (acc.add_baseline if elapsed < baseline_s else acc.add_shown)(frame)
                    sleep(0.05)
        except CameraBusy as exc:
            raise ApiError("camera-busy", str(exc)) from exc
        except CameraError as exc:
            raise ApiError("camera-error", str(exc)) from exc
        finally:
            with self._lock:
                self.active -= 1
            self.touch()
        result = acc.verdict()
        if result["verdict"] == "infrared":
            self.trust.record(info, True, result)
        elif result["verdict"] == "sees-visible-light":
            self.trust.record(info, False, result)
        result["camera"] = info.name
        return result

    def status(self) -> dict:
        cams = self.cameras(refresh=True)
        pick = self.pick_camera({"ir", "rgb"})
        mstat = self._models()
        return {
            "version": __import__("facial_auth").__version__,
            "enabled": self.cfg["core", "enabled"],
            "models_ok": mstat["ok"], "models_missing": ",".join(mstat["missing"]),
            "cameras": len(cams),
            "camera": pick[0].path if pick else "", "camera_name": pick[0].name if pick else "",
            "camera_class": pick[1] if pick else "",
            # "unverified": nothing known yet; "failed": it sees a phone screen, so it is no infrared camera
            "camera_ir_check": (self.trust.status(pick[0]) if pick and pick[1] == "ir" else "n/a"),
            "require_ir_check": self.cfg["camera", "require_ir_check"],
            "lid_closed": self._lid(),
            "uptime": int(time.time() - self.started),
        }
