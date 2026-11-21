# SPDX-License-Identifier: MIT
"""Per-account lock-out after repeated *wrong-face* scans.

Only attempts where a face was seen but did not match (or looked fake) count:
a user who simply was not in front of the camera, or who typed their password
first, must never be penalised.  A lock-out only disables the face path for
that account; the password login is untouched.

Every lock-out that follows another one lasts longer (``growth`` times, up to ``max_lockout``):
with a fixed one-minute lock-out somebody holding a photograph could try five times a minute for
as long as they like.  A success clears the memory; so does a long quiet period.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Callable


MEMORY_SECONDS = 6 * 3600.0       # a lock-out is forgotten after this long without a new one


class FailureLimiter:
    def __init__(self, max_failures: int, window: float, lockout: float,
                 clock: Callable[[], float] = time.monotonic, growth: float = 1.0,
                 max_lockout: float | None = None) -> None:
        self.max_failures, self.window, self.lockout = max_failures, window, lockout
        self.growth = growth
        self.max_lockout = max_lockout if max_lockout is not None else lockout
        self._clock = clock
        self._fails: dict[int, deque[float]] = defaultdict(deque)
        self._locked_until: dict[int, float] = {}
        self._strikes: dict[int, tuple[int, float]] = {}     # uid -> (lock-outs so far, when the last one began)
        self._lock = threading.Lock()

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
                duration = min(self.lockout * self.growth ** count, max(self.max_lockout, self.lockout))
                self._strikes[uid] = (count + 1, now)
                self._locked_until[uid] = now + duration
                q.clear()
                return True
            return False

    def record_success(self, uid: int) -> None:
        with self._lock:
            self._fails.pop(uid, None)
            self._locked_until.pop(uid, None)
            self._strikes.pop(uid, None)

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
