# SPDX-License-Identifier: MIT
"""Per-account lock-out after repeated *wrong-face* scans.

Only attempts where a face was seen but did not match (or looked fake) count:
a user who simply was not in front of the camera, or who typed their password
first, must never be penalised.  A lock-out only disables the face path for
that account; the password login is untouched.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Callable


class FailureLimiter:
    def __init__(self, max_failures: int, window: float, lockout: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_failures, self.window, self.lockout = max_failures, window, lockout
        self._clock = clock
        self._fails: dict[int, deque[float]] = defaultdict(deque)
        self._locked_until: dict[int, float] = {}
        self._lock = threading.Lock()

    def configure(self, max_failures: int, window: float, lockout: float) -> None:
        with self._lock:
            self.max_failures, self.window, self.lockout = max_failures, window, lockout

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
                self._locked_until[uid] = now + self.lockout
                q.clear()
                return True
            return False

    def record_success(self, uid: int) -> None:
        with self._lock:
            self._fails.pop(uid, None)
            self._locked_until.pop(uid, None)

    def reset(self, uid: int | None = None) -> None:
        with self._lock:
            if uid is None:
                self._fails.clear()
                self._locked_until.clear()
            else:
                self._fails.pop(uid, None)
                self._locked_until.pop(uid, None)
