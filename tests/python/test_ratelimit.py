# SPDX-License-Identifier: MIT
"""The face-path lock-out: with a fixed delay, patience was all it took to try a photograph for ever."""
from facial_auth.ratelimit import MEMORY_SECONDS, FailureLimiter


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def fail(lim, uid, n):
    locked = False
    for _ in range(n):
        locked = lim.record_failure(uid)
    return locked


def test_each_lock_out_lasts_longer_than_the_previous_one_up_to_a_ceiling():
    clock = Clock()
    lim = FailureLimiter(3, 60, 60, clock, growth=2.0, max_lockout=500.0)
    seen = []
    for _ in range(6):
        assert fail(lim, 1, 3)
        seen.append(round(lim.remaining(1)))
        clock.t += lim.remaining(1) + 1
        assert lim.remaining(1) == 0
    assert seen == [60, 120, 240, 480, 500, 500]


def test_a_success_forgets_the_strikes():
    clock = Clock()
    lim = FailureLimiter(3, 60, 60, clock, growth=2.0, max_lockout=3600.0)
    fail(lim, 1, 3)
    clock.t += 61
    fail(lim, 1, 3)                      # second lock-out: 120 s
    clock.t += 121
    lim.record_success(1)
    fail(lim, 1, 3)
    assert round(lim.remaining(1)) == 60


def test_a_long_quiet_period_forgets_them_too():
    clock = Clock()
    lim = FailureLimiter(3, 60, 60, clock, growth=2.0, max_lockout=3600.0)
    fail(lim, 1, 3)
    clock.t += MEMORY_SECONDS + 100
    fail(lim, 1, 3)
    assert round(lim.remaining(1)) == 60


def test_accounts_do_not_share_their_strikes():
    clock = Clock()
    lim = FailureLimiter(3, 60, 60, clock, growth=2.0, max_lockout=3600.0)
    fail(lim, 1, 3)
    clock.t += 61
    fail(lim, 1, 3)
    fail(lim, 2, 3)
    assert round(lim.remaining(2)) == 60 and round(lim.remaining(1)) == 120


def test_without_growth_it_behaves_as_before():
    clock = Clock()
    lim = FailureLimiter(3, 60, 60, clock)
    for _ in range(3):
        fail(lim, 1, 3)
        assert round(lim.remaining(1)) == 60
        clock.t += 61


def test_the_password_is_never_involved():
    """The limiter only answers 'should the face path be tried'; nothing here can refuse a password."""
    lim = FailureLimiter(1, 60, 60, Clock(), growth=10.0, max_lockout=86400.0)
    assert lim.record_failure(1) and lim.remaining(1) > 0
