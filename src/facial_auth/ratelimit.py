# SPDX-License-Identifier: MIT
"""Per-account lock-out after repeated *wrong-face* scans.

Only attempts where a face was seen but did not match (or looked fake) count:
a user who simply was not in front of the camera, or who typed their password
first, must never be penalised.  A lock-out only disables the face path for
that account; the password login is untouched.

Every lock-out that follows another one lasts longer (``growth`` times, up to ``max_lockout``):
with a fixed one-minute lock-out somebody holding a photograph could try five times a minute for
as long as they like.  A success clears the memory; so does a long quiet period.

The lock-outs and the strikes behind them are also written to a small file (``state_file``): the
daemon leaves after a quarter of an hour without requests and is restarted by upgrades and crashes,
and a lock-out that a restart wipes lasts only as long as somebody's patience.
"""
from __future__ import annotations

import json
import logging
import math
import os
import tempfile
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

MEMORY_SECONDS = 6 * 3600.0       # a lock-out is forgotten after this long without a new one
STATE_VERSION = 1
MAX_STRIKES = 64                  # the exponent of the growth: far beyond any ceiling, never an overflow


class FailureLimiter:
    def __init__(self, max_failures: int, window: float, lockout: float,
                 clock: Callable[[], float] = time.monotonic, growth: float = 1.0,
                 max_lockout: float | None = None, state_file: Path | None = None,
                 wall_clock: Callable[[], float] = time.time) -> None:
        self.max_failures, self.window, self.lockout = max_failures, window, lockout
        self.growth = growth
        self.max_lockout = max_lockout if max_lockout is not None else lockout
        self._clock = clock
        self._wall = wall_clock                 # the monotonic clock starts again at every boot
        self._state_file = state_file
        self._fails: dict[int, deque[float]] = defaultdict(deque)
        self._locked_until: dict[int, float] = {}
        self._strikes: dict[int, tuple[int, float]] = {}     # uid -> (lock-outs so far, when the last one began)
        self._lock = threading.Lock()
        self._load()

    # -- persistence ---------------------------------------------------------------
    def _ceiling(self) -> float:
        return max(self.max_lockout, self.lockout)

    def _load(self) -> None:
        """Take back the lock-outs of the previous run.  Whatever the file holds, it can only make a
        lock-out shorter than ``max_lockout`` or forget it: a damaged file is ignored."""
        if self._state_file is None:
            return
        try:
            data = json.loads(Path(self._state_file).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION or not isinstance(data.get("accounts"), dict):
            return
        now, wall = self._clock(), self._wall()
        for key, entry in data["accounts"].items():
            try:
                uid = int(key)
                until = float(entry["locked_until"])
                count = max(0, min(int(entry["strikes"]), MAX_STRIKES))
                last = float(entry["last_strike"])
            except (KeyError, TypeError, ValueError, OverflowError):
                continue
            left = until - wall
            if math.isfinite(left) and left > 0:
                self._locked_until[uid] = now + min(left, self._ceiling())
            elif left == math.inf:
                self._locked_until[uid] = now + self._ceiling()
            age = wall - last
            if count and math.isfinite(age) and 0 <= age <= MEMORY_SECONDS:     # a clock set back gives age < 0
                self._strikes[uid] = (count, now - age)

    def _save(self) -> None:
        """Write the state (called with the lock held).  Never raises: failing to remember must not
        make anybody's login fail."""
        if self._state_file is None:
            return
        now, wall = self._clock(), self._wall()
        accounts = {}
        for uid in set(self._locked_until) | set(self._strikes):
            count, began = self._strikes.get(uid, (0, now))
            accounts[str(uid)] = {
                "locked_until": wall + max(0.0, self._locked_until.get(uid, 0.0) - now),
                "strikes": count,
                "last_strike": wall - (now - began),
            }
        path = Path(self._state_file)
        tmp = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".lockout.", dir=path.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"version": STATE_VERSION, "accounts": accounts}, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError as exc:
            log.debug("cannot save the lock-outs to %s: %s", path, exc)
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def configure(self, max_failures: int, window: float, lockout: float, growth: float = 1.0,
                  max_lockout: float | None = None) -> None:
        with self._lock:
            self.max_failures, self.window, self.lockout = max_failures, window, lockout
            self.growth = growth
            self.max_lockout = max_lockout if max_lockout is not None else lockout

    def remaining(self, uid: int) -> float:
        """Seconds of lock-out left (0 when the account is free)."""
        with self._lock:
            left = self._locked_until.get(uid, 0.0) - self._clock()
            if left <= 0:
                self._locked_until.pop(uid, None)
                return 0.0
            return left

    def record_failure(self, uid: int) -> bool:
        """Returns True when this failure triggers a lock-out."""
        now = self._clock()
        with self._lock:
            q = self._fails[uid]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max_failures:
                count, began = self._strikes.get(uid, (0, now))
                if now - began > MEMORY_SECONDS:
                    count = 0
                duration = min(self.lockout * self.growth ** min(count, MAX_STRIKES), self._ceiling())
                self._strikes[uid] = (count + 1, now)
                self._locked_until[uid] = now + duration
                q.clear()
                self._save()
                return True
            return False

    def record_success(self, uid: int) -> None:
        with self._lock:
            self._fails.pop(uid, None)
            was_locked = self._locked_until.pop(uid, None) is not None
            had_strikes = self._strikes.pop(uid, None) is not None
            if was_locked or had_strikes:
                self._save()

    def reset(self, uid: int | None = None) -> None:
        with self._lock:
            if uid is None:
                self._fails.clear()
                self._locked_until.clear()
                self._strikes.clear()
            else:
                self._fails.pop(uid, None)
                self._locked_until.pop(uid, None)
                self._strikes.pop(uid, None)
            self._save()
