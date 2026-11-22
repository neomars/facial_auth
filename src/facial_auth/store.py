# SPDX-License-Identifier: MIT
"""Face template storage.

Layout (owned by the daemon user, nothing readable by others)::

    /var/lib/facial-auth/templates/<uid>/faces.json   0600  (dir 0700)
    /var/lib/facial-auth/enrolled/<username>          0644  empty marker

Only *embeddings* (128 floats per sample) are stored, never photographs.  The
markers let the PAM module skip the daemon for users without a face; they carry
no biometric data and grant nothing (success is only ever decided by the
daemon).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import pwd
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import numpy as np

from .const import Paths

log = logging.getLogger(__name__)

FORMAT_VERSION = 1
MAX_FACES_PER_USER = 10
MAX_VECTORS_PER_FACE = 20
CAMERA_CLASSES = ("rgb", "ir")


class StoreError(Exception):
    pass


@dataclass
class FaceRecord:
    id: str
    label: str
    created: float
    camera_class: str
    model: str
    source: str
    vectors: np.ndarray = field(repr=False)

    def public(self) -> dict:
        """Metadata that may be shown in a UI (no biometric data)."""
        return {"id": self.id, "label": self.label, "created": int(self.created),
                "camera_class": self.camera_class, "model": self.model,
                "source": self.source, "samples": int(len(self.vectors))}


@dataclass(frozen=True)
class Orphan:
    """Faces filed under a uid that does not (or no longer) belong to the account they were enrolled for."""
    uid: int
    recorded: str      # the account name the faces were enrolled for
    current: str       # what the uid is called now; "" when no account has it (or it cannot be looked up)


@dataclass
class UserFaces:
    uid: int
    username: str = ""
    enabled: bool = True
    faces: list[FaceRecord] = field(default_factory=list)


def normalise(vectors: np.ndarray) -> np.ndarray:
    """L2-normalise rows so that a dot product is the cosine similarity."""
    v = np.asarray(vectors, dtype=np.float32)
    if v.ndim == 1:
        v = v[None, :]
    norms = np.linalg.norm(v, axis=1, keepdims=True)
    if not np.all(np.isfinite(v)) or np.any(norms < 1e-6):
        raise StoreError("invalid embedding")
    return v / norms


def username_of(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return ""


class FaceStore:
    def __init__(self, paths: Paths | None = None,
                 name_of: Callable[[int], str] = username_of,
                 owner: tuple[int, int] | None = None) -> None:
        self.paths = paths or Paths()
        self._name_of = name_of
        self._owner = owner      # chown target when running as root (tests/CLI)
        self._lock = threading.RLock()
        self._warned: set[tuple[int, str, str]] = set()

    # -- file helpers -----------------------------------------------------
    def _dir(self, uid: int) -> Path:
        return self.paths.templates / str(int(uid))

    def _file(self, uid: int) -> Path:
        return self._dir(uid) / "faces.json"

    def _mkdir(self, path: Path, mode: int) -> None:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
        if self._owner and os.geteuid() == 0:
            os.chown(path, *self._owner)

    # -- read -------------------------------------------------------------
    def load(self, uid: int) -> UserFaces:
        """Never raises: a damaged file means "no faces" (fail closed).

        Faces are filed under the uid but belong to the *account* they were enrolled for: when the uid
        is now called something else (account deleted and the uid given to somebody new, account
        renamed, user database unreachable) they are not used.  Nothing is deleted here.
        """
        out = UserFaces(uid=int(uid), username=self._name_of(uid))
        f = self._file(uid)
        with self._lock:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if data.get("version") != FORMAT_VERSION:
                    raise ValueError(f"unsupported version {data.get('version')!r}")
                recorded = str(data.get("username", ""))
                if recorded and recorded != out.username:
                    self._warn_orphan(uid, recorded, out.username)
                    return out
                out.enabled = bool(data.get("enabled", True))
                for item in data.get("faces", []):
                    dim = int(item["dim"])
                    raw = base64.b64decode(item["vectors"], validate=True)
                    vec = np.frombuffer(raw, dtype=np.float32).reshape(-1, dim).copy()
                    cls = item["camera_class"]
                    if cls not in CAMERA_CLASSES or not len(vec):
                        raise ValueError("bad face entry")
                    out.faces.append(FaceRecord(
                        id=str(item["id"]), label=str(item.get("label", "")),
                        created=float(item.get("created", 0)), camera_class=cls,
                        model=str(item.get("model", "")), source=str(item.get("source", "")),
                        vectors=normalise(vec)))
            except FileNotFoundError:
                pass
            except (ValueError, KeyError, TypeError, AttributeError, StoreError, json.JSONDecodeError, OSError) as exc:
                log.error("unreadable face data for uid %s (%s): treated as empty", uid, exc)
                out.faces = []
        return out

    def _warn_orphan(self, uid: int, recorded: str, current: str) -> None:
        key = (int(uid), recorded, current)
        if key not in self._warned:
            self._warned.add(key)
            log.warning("faces filed under uid %s were enrolled for %r, which is %s: they are not used "
                        "('facial-auth purge-orphans' removes them)", uid, recorded,
                        f"now called {current!r}" if current else "no longer an account")

    def orphans(self) -> list[Orphan]:
        """Every record whose recorded account name is not the name of its uid today."""
        found: list[Orphan] = []
        try:
            entries = sorted((p for p in self.paths.templates.iterdir() if p.name.isdigit()),
                             key=lambda p: int(p.name))
        except FileNotFoundError:
            return found
        for d in entries:
            try:
                data = json.loads((d / "faces.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            recorded = str(data.get("username", "")) if isinstance(data, dict) else ""
            current = self._name_of(int(d.name))
            if recorded and recorded != current:
                found.append(Orphan(int(d.name), recorded, current))
        return found

    def purge_orphans(self) -> list[Orphan]:
        """Delete the records listed by orphans() and rebuild the markers from what is left.

        Only an administrator's explicit command calls this: a failed user-database lookup looks like
        a deleted account and must never cost anybody their enrolled face.
        """
        with self._lock:
            found = self.orphans()
            for o in found:
                shutil.rmtree(self._dir(o.uid), ignore_errors=True)
            self.sync_markers()
        return found

    def users(self) -> list[int]:
        try:
            return sorted(int(p.name) for p in self.paths.templates.iterdir()
                          if p.name.isdigit() and (p / "faces.json").is_file())
        except FileNotFoundError:
            return []

    def templates_for(self, uid: int, camera_class: str | None = None,
                      model: str | None = None) -> np.ndarray:
        """All sample vectors of a user (for one camera class), shape (n, dim)."""
        user = self.load(uid)
        if not user.enabled:
            return np.zeros((0, 128), dtype=np.float32)
        rows = [f.vectors for f in user.faces
                if (camera_class is None or f.camera_class == camera_class)
                and (model is None or f.model == model)]
        return np.vstack(rows) if rows else np.zeros((0, 128), dtype=np.float32)

    def classes_for(self, uid: int) -> set[str]:
        user = self.load(uid)
        return {f.camera_class for f in user.faces} if user.enabled else set()

    def all_templates(self, camera_class: str, model: str | None = None) -> dict[int, np.ndarray]:
        out = {}
        for uid in self.users():
            t = self.templates_for(uid, camera_class, model)
            if len(t):
                out[uid] = t
        return out

    # -- write ------------------------------------------------------------
    def _save(self, user: UserFaces) -> None:
        if not user.faces and user.enabled:
            # nothing left: drop the file (and the marker) entirely
            self._file(user.uid).unlink(missing_ok=True)
            try:
                self._dir(user.uid).rmdir()
            except OSError:
                pass
            return
        self._mkdir(self.paths.templates, 0o700)
        self._mkdir(self._dir(user.uid), 0o700)
        payload = {
            "version": FORMAT_VERSION, "uid": user.uid, "username": user.username,
            "enabled": user.enabled,
            "faces": [{
                "id": f.id, "label": f.label, "created": f.created,
                "camera_class": f.camera_class, "model": f.model, "source": f.source,
                "dim": int(f.vectors.shape[1]),
                "vectors": base64.b64encode(f.vectors.astype(np.float32).tobytes()).decode(),
            } for f in user.faces],
        }
        target = self._file(user.uid)
        tmp = target.with_name("faces.json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        if self._owner and os.geteuid() == 0:
            os.chown(tmp, *self._owner)
        os.replace(tmp, target)

    def add_face(self, uid: int, label: str, vectors: np.ndarray, camera_class: str,
                 model: str, source: str = "camera") -> FaceRecord:
        if camera_class not in CAMERA_CLASSES:
            raise StoreError(f"unknown camera class {camera_class!r}")
        vec = normalise(vectors)
        if len(vec) > MAX_VECTORS_PER_FACE:
            vec = vec[:MAX_VECTORS_PER_FACE]
        label = " ".join(str(label).split())[:64] or "Face"
        with self._lock:
            user = self.load(uid)
            if len(user.faces) >= MAX_FACES_PER_USER:
                raise StoreError(f"at most {MAX_FACES_PER_USER} faces per account")
            rec = FaceRecord(id=secrets.token_hex(4), label=label, created=time.time(),
                             camera_class=camera_class, model=model, source=source, vectors=vec)
            user.faces.append(rec)
            self._save(user)
            self.sync_marker(uid)
        return rec

    def remove_face(self, uid: int, face_id: str) -> bool:
        with self._lock:
            user = self.load(uid)
            kept = [f for f in user.faces if f.id != face_id]
            if len(kept) == len(user.faces):
                return False
            user.faces = kept
            self._save(user)
            self.sync_marker(uid)
            return True

    def clear(self, uid: int) -> int:
        with self._lock:
            user = self.load(uid)
            n = len(user.faces)
            user.faces = []
            user.enabled = True
            self._save(user)
            self.sync_marker(uid)
            return n

    def set_enabled(self, uid: int, enabled: bool) -> None:
        with self._lock:
            user = self.load(uid)
            if not user.faces:
                raise StoreError("no face is linked to this account")
            user.enabled = bool(enabled)
            self._save(user)
            self.sync_marker(uid)

    # -- markers ----------------------------------------------------------
    def sync_marker(self, uid: int) -> None:
        user = self.load(uid)
        name = user.username
        if not name or "/" in name or name.startswith("."):
            return
        marker = self.paths.markers / name
        want = bool(user.faces) and user.enabled
        try:
            if want:
                self._mkdir(self.paths.markers, 0o755)
                marker.touch(mode=0o644, exist_ok=True)
                if self._owner and os.geteuid() == 0:
                    os.chown(marker, *self._owner)
            else:
                marker.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("cannot update marker %s: %s", marker, exc)

    def sync_markers(self) -> None:
        """Rebuild every marker (daemon start-up, after a rename...)."""
        wanted = set()
        for uid in self.users():
            user = self.load(uid)
            if user.faces and user.enabled and user.username:
                wanted.add(user.username)
            self.sync_marker(uid)
        try:
            for m in self.paths.markers.iterdir():
                if m.name not in wanted:
                    m.unlink(missing_ok=True)
        except FileNotFoundError:
            pass
