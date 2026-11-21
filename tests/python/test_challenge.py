# SPDX-License-Identifier: MIT
"""The head-turn test, on synthetic scenes whose 3-D truth is known (tests/python/synth3d.py).

What must hold:
* a real head turning to the requested side, then the other, then looking ahead, passes;
* the same movement in the wrong order does not (a recorded clip cannot answer a random question);
* a flat picture - however a hand tilts, rotates and moves it - never passes, and neither does a
  sheet bent by hand;
* the same person must be there all along and at the end.
"""
import numpy as np
import pytest

from facial_auth import challenge
from facial_auth.challenge import HeadTurn, Params

from .synth3d import Scene, head_turns, settle, tilted_sheet

FPS = 15.0
MARGIN = 0.05
PARAMS = Params(timeout=5.0)


def play(scene, poses, sequence="lr", params=PARAMS, similarity=0.9, found=True, hook=None, seed=0):
    """Feed the poses to a fresh HeadTurn, then keep showing the last frame (the person stands still)
    until the challenge ends or times out; returns the final State."""
    rng = np.random.default_rng(seed)
    ht = HeadTurn(params, sequence, start=0.0)
    frames = [scene.render(*pose, rng=rng) for pose in settle() + list(poses)]
    assert ht.begin(*frames[3]) or ht.state.verdict == "failed"
    if ht.state.verdict == "failed":
        return ht.state
    images = [image for image, _lm in frames[4:]]
    i = 4
    while ht.state.verdict == "pending" and i / FPS <= params.timeout + 1.0:
        image = images[i - 4] if i - 4 < len(images) else images[-1]
        sim, f = (similarity, found)
        if hook:
            sim, f = hook(i, sim, f)
        ht.feed(image, f, sim, -1.0, MARGIN, i / FPS)
        i += 1
    return ht.state


# ---------------------------------------------------------------------------- real heads
@pytest.mark.parametrize("first, sequence", [(+1, "lr"), (-1, "rl")])
@pytest.mark.parametrize("nose", [30.0, 20.0])
def test_a_head_turning_as_asked_passes(first, sequence, nose):
    st = play(Scene("head", nose_mm=nose, seed=3), head_turns(first), sequence)
    assert st.verdict == "passed", (st.reason, st.peak, st.step, st.points)
    assert st.step == 2 and st.peak > 0.03


def test_the_sign_convention_a_turn_to_the_users_left_is_positive():
    scene = Scene("head", seed=4)
    rng = np.random.default_rng(0)
    base, lm0 = scene.render(rng=rng)
    tracker = challenge.Tracker(base, lm0)
    assert tracker.usable
    left = None
    for yaw in np.linspace(0, np.radians(18), 8):
        image, _ = scene.render(yaw=yaw, rng=rng)
        tracker.update(image)
        left = tracker.measure()
    assert left is not None and left[0] > 0.03, left


@pytest.mark.parametrize("asked, done", [("lr", -1), ("rl", +1)])
def test_the_wrong_order_does_not_pass_so_a_recorded_clip_is_useless(asked, done):
    st = play(Scene("head", seed=5), head_turns(done), asked)
    assert st.verdict == "failed" and st.reason == "challenge-timeout"


def test_mirrored_cameras_are_handled_by_an_option():
    st = play(Scene("head", seed=6), head_turns(+1), "rl", Params(mirror=True))
    assert st.verdict == "passed"


def test_not_turning_enough_times_out_without_being_called_flat():
    st = play(Scene("head", seed=7), head_turns(+1, amplitude_deg=3.0))
    assert st.verdict == "failed" and st.reason in ("challenge-timeout", "no-texture")
    assert st.peak < 0.02 and st.step == 0


@pytest.mark.parametrize("seed", [3, 4, 5])
def test_a_clear_turn_of_about_eighteen_degrees_is_enough(seed):
    """What the instruction asks for ("clearly"): 15 to 20 degrees to each side."""
    st = play(Scene("head", nose_mm=20.0, seed=seed), head_turns(+1, amplitude_deg=18.0))
    assert st.verdict == "passed", (st.reason, st.peak, st.step)


def test_somebody_who_turned_almost_far_enough_is_not_taken_for_a_picture():
    """peak 0.019 against a bar of 0.02: a timeout, not a "flat surface" (which counts as a spoof)."""
    st = play(Scene("head", nose_mm=20.0, seed=4), head_turns(+1, amplitude_deg=15.0))
    if st.verdict == "failed":
        assert st.reason == "challenge-timeout", (st.reason, st.peak)


def test_a_slight_turn_is_not_enough_and_the_failure_says_to_turn_further():
    from facial_auth.scan import hint_for
    st = play(Scene("head", nose_mm=20.0, seed=8), head_turns(+1, amplitude_deg=6.0))
    assert st.verdict == "failed" and st.step == 0 and st.peak < PARAMS.turn
    assert hint_for(st, PARAMS.turn) == "too-little"


def test_a_generous_time_budget_lets_a_slow_gesture_finish():
    """"Slowly" must not cost the login: three seconds per cycle, instruction read for a while first."""
    slow = [(0.0, 0.0, 0.0)] * 30 + head_turns(+1, frames=90)       # 2 s of reading, a 6 s gesture
    st = play(Scene("head", seed=9), slow, params=Params(timeout=12.0))
    assert st.verdict == "passed", (st.reason, st.peak, st.step)
    st = play(Scene("head", seed=9), slow, params=Params(timeout=5.0))
    assert st.verdict == "failed", "...and the old budget would not have"


def test_a_quick_flick_is_told_apart_from_a_turn_in_the_wrong_direction():
    from facial_auth.scan import hint_for
    flick = [(0.0, 0.0, 0.0)] * 2 + [(0.0, 0.0, 0.0), (0.12, 0, 0), (0.35, 0, 0), (0.0, 0, 0)] + [(0.0, 0, 0)] * 10
    st = play(Scene("head", nose_mm=30.0, seed=3), flick, "lr", PARAMS)
    assert st.verdict == "failed" and st.step == 0
    assert hint_for(st, PARAMS.turn) in ("too-fast", "too-little"), (st.peak, st.first_sign)
    st = play(Scene("head", nose_mm=30.0, seed=3), head_turns(-1), "lr", PARAMS)
    assert hint_for(st, PARAMS.turn) == "wrong-way", (st.first_sign, st.wanted_first, st.peak)


def test_the_failure_hints_tell_the_causes_apart():
    from facial_auth.challenge import State
    from facial_auth.scan import hint_for
    turn = PARAMS.turn
    assert hint_for(State(verdict="passed"), turn) == ""
    assert hint_for(State(verdict="failed", reason="challenge-timeout", step=0, peak=0.004), turn) == "too-little"
    # the bar was reached on the asked side, but not for long enough: a flick
    assert hint_for(State(verdict="failed", reason="challenge-timeout", step=0, peak=0.05, first_sign=1,
                          wanted_first=1), turn) == "too-fast"
    # the other side first (or a mirrored camera)
    assert hint_for(State(verdict="failed", reason="challenge-timeout", step=0, peak=0.05, first_sign=-1,
                          wanted_first=1), turn) == "wrong-way"
    assert hint_for(State(verdict="failed", reason="challenge-timeout", step=1, peak=0.05, first_sign=1,
                          wanted_first=1), turn) == "second-turn"
    for reason, hint in [("final-match", "final-match"), ("lost-face", "lost-face"), ("no-texture", "no-texture"),
                         ("identity-changed", "identity-changed"), ("flat-surface", "flat")]:
        assert hint_for(State(verdict="failed", reason=reason, step=1, peak=0.05), turn) == hint


# ------------------------------------------------------------------------------- attacks
@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize("sequence", ["lr", "rl"])
def test_a_flat_picture_moved_by_hand_never_passes(seed, sequence):
    st = play(Scene("flat", seed=10 + seed), tilted_sheet(seed), sequence)
    assert st.verdict == "failed", (st.peak, st.step)
    assert st.reason in ("flat-surface", "challenge-timeout")
    assert st.step < 2


def test_a_picture_that_is_tilted_a_lot_is_called_flat_not_merely_slow():
    st = play(Scene("flat", seed=21), tilted_sheet(3, amplitude_deg=40.0), "lr")
    assert st.reason == "flat-surface"


@pytest.mark.parametrize("seed", range(4))
def test_a_sheet_bent_by_hand_is_not_a_nose(seed):
    st = play(Scene("bent", bend_mm=20.0, seed=30 + seed), tilted_sheet(seed), "lr")
    assert st.verdict == "failed"


def test_a_still_picture_just_times_out():
    st = play(Scene("flat", seed=40), [(0.0, 0.0, 0.0)] * 6)
    assert st.verdict == "failed" and st.reason == "challenge-timeout"


# --------------------------------------------------------------------------------- identity
def test_somebody_else_in_the_middle_of_the_turn_is_refused():
    def swap(i, sim, found):
        return (0.05, found) if 14 <= i <= 20 else (sim, found)

    st = play(Scene("head", seed=8), head_turns(+1), hook=swap)
    assert st.verdict == "failed" and st.reason == "identity-changed"


def test_the_same_person_must_be_there_again_at_the_end():
    def stranger_at_the_end(i, sim, found):
        return (0.3, found) if i >= 22 else (sim, found)      # a lookalike: not unlike enough to be a swap

    st = play(Scene("head", seed=9), head_turns(+1), hook=stranger_at_the_end)
    assert st.verdict == "failed" and st.reason == "final-match" and st.step == 2


def test_a_face_that_leaves_the_picture_fails():
    def gone(i, sim, found):
        return (None, False) if i >= 12 else (sim, found)

    st = play(Scene("head", seed=11), head_turns(+1), hook=gone)
    assert st.verdict == "failed" and st.reason == "lost-face"


def test_a_scene_without_texture_cannot_be_judged():
    ht = HeadTurn(PARAMS, "lr")
    blank = np.full((480, 640, 3), 90, np.uint8)
    lm = np.array([[270, 200], [370, 200], [320, 260], [290, 300], [350, 300]], np.float64)
    assert ht.begin(blank, lm) is False
    assert ht.state.verdict == "failed" and ht.state.reason == "no-texture"


def test_sequences_are_drawn_at_random():
    import random
    seen = {challenge.draw_sequence(random.Random(i)) for i in range(20)}
    assert seen == {"lr", "rl"}
