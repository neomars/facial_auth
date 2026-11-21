# SPDX-License-Identifier: MIT
"""Active liveness: "turn your head slowly", judged on 3-D parallax.

Why this and not "blink" or "does the picture move": a photograph held in front of the camera
can be tilted, moved, rotated and bent by hand, and every rigid motion of a *flat* surface is a
homography.  So the test is not "did the face move" but "is the face flat":

1. Dozens of texture points of the face are tracked from frame to frame (Lucas-Kanade).
2. A plane is fitted to the points of the *inner* face (brows, eyes, mouth) - the part a sheet of
   paper can imitate even when it is bent.
3. The nose region is compared with that plane.  On a real head it sticks out (about 3 cm) and,
   when the head turns, slides sideways against the plane in the direction of the turn
   ("parallax"); on a flat or gently bent picture it stays glued to it, whatever the
   inclination of the sheet.

The signed parallax rho (in units of the distance between the eyes) is therefore at the same
time the proof of depth and the measure of the turn: the user must turn towards their left,
then towards their right - in an order drawn at random - and look at the screen again.
The same identity must be present all along and at the end, so a swap cannot be slipped in.

Measured on real portraits through the real face detector (see docs/SECURITY.md): a flat sheet
moved at will gives |rho| below 0.02, a head turned by 15-25 degrees gives 0.04-0.06.

What it does not stop: a recorded video of the right head movements played in front of a
colour camera (an infrared camera does not see a screen), a sheet folded into a real nose,
a mask.
"""
from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass, field

import numpy as np

# OpenCV is imported when a challenge starts, not when the daemon does: the module of a login that
# found the daemon asleep waits a few seconds at most for its first answer.
log = logging.getLogger(__name__)

#: +1 = towards the user's own left (the nose moves towards the right of the image),
#: -1 = towards their right.  Drawn at random for every attempt.
SEQUENCES = {"lr": (+1, -1), "rl": (-1, +1)}

LK = dict(winSize=(21, 21), maxLevel=3, criteria=None)     # criteria filled in with cv2 at first use
MAX_POINTS = 150          # texture points over the inner face
NOSE_WANTED = 8           # if the nose region has fewer, look there on its own (last resort)
MIN_ALIVE = 20            # tracked points needed at all
MIN_PLANE = 12            # ... in the inner face, outside the nose
MIN_NOSE = 4              # ... around the tip of the nose
FORWARD_BACKWARD_PX = 1.0


@dataclass(frozen=True)
class Params:
    turn: float = 0.025          # |rho| that counts as "turned"
    hold: int = 3                # consecutive frames beyond `turn`
    timeout: float = 8.0         # seconds for the whole challenge
    mirror: bool = False         # camera image already mirrored (rare)
    flat_motion: float = 0.03    # shape change that proves the surface was rotated ...
                                 # ... while rho never reached `turn`: nothing stuck out
    swap_similarity: float = 0.15    # a frame this unlike the account = somebody else
    swap_frames: int = 3
    lost_seconds: float = 1.5    # face missing for this long = the person left
    threshold: float = 0.45      # similarity needed for the final identity check
    required: int = 3            # ... on this many consecutive frames


@dataclass
class State:
    verdict: str = "pending"     # pending | passed | failed
    reason: str = ""             # challenge-timeout | flat-surface | identity-changed | lost-face | no-texture
    step: int = 0
    phase: str = "turn"          # turn | back
    rho: float = float("nan")
    points: int = 0
    peak: float = 0.0            # largest |rho| seen
    shape_change: float = 0.0
    log: list = field(default_factory=list)


def draw_sequence(rng: random.Random | None = None) -> str:
    return (rng or random).choice(sorted(SEQUENCES))


def _lk_params() -> dict:
    import cv2
    if LK["criteria"] is None:
        LK["criteria"] = (cv2.TERM_CRITERIA_EPS | cv2.TERM_CRITERIA_COUNT, 30, 0.01)
    return LK


def _gray(frame: np.ndarray, clahe) -> np.ndarray:
    import cv2
    g = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if frame.ndim == 3 else frame
    return clahe.apply(g)


def _face_mask(shape, lm: np.ndarray) -> np.ndarray:
    """Inner face ellipse built from the 5 landmarks (right eye, left eye, nose, right/left mouth corner)."""
    import cv2
    eyes = (lm[0] + lm[1]) / 2
    mouth = (lm[3] + lm[4]) / 2
    D = float(np.linalg.norm(lm[1] - lm[0]))
    v = mouth - eyes
    centre = (eyes + mouth) / 2 - 0.12 * v
    angle = math.degrees(math.atan2(lm[1][1] - lm[0][1], lm[1][0] - lm[0][0]))
    mask = np.zeros(shape[:2], np.uint8)
    axes = (max(1, int(0.78 * D)), max(1, int(0.62 * np.linalg.norm(v) + 0.55 * D)))
    cv2.ellipse(mask, (int(centre[0]), int(centre[1])), axes, angle, 0, 360, 255, -1)
    return mask


class Tracker:
    """Lucas-Kanade tracks of face texture, from a baseline frame."""

    def __init__(self, frame: np.ndarray, landmarks: np.ndarray) -> None:
        import cv2
        self._clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(4, 4))
        self.lm0 = np.asarray(landmarks, np.float64)
        g = _gray(frame, self._clahe)
        pts = cv2.goodFeaturesToTrack(g, MAX_POINTS, 0.005, 4, mask=_face_mask(frame.shape, self.lm0),
                                      blockSize=5)
        found = np.empty((0, 2), np.float32) if pts is None else pts.reshape(-1, 2).astype(np.float32)
        # The nose is a small part of the face and sometimes the least textured: when it came out
        # short of points, look there on its own with a slightly lower (not a careless) bar.
        d0 = float(np.linalg.norm(self.lm0[1] - self.lm0[0]))
        nose = self.lm0[2]
        radius = 0.30 * d0
        have = int(np.sum(np.linalg.norm(found - nose, axis=1) < radius)) if len(found) else 0
        if have < NOSE_WANTED:
            nose_mask = np.zeros(frame.shape[:2], np.uint8)
            cv2.circle(nose_mask, (int(nose[0]), int(nose[1])), max(2, int(radius)), 255, -1)
            extra = cv2.goodFeaturesToTrack(g, NOSE_WANTED * 2, 0.002, 3, mask=nose_mask, blockSize=5)
            if extra is not None:
                extra = extra.reshape(-1, 2).astype(np.float32)
                if len(found):
                    far = np.min(np.linalg.norm(extra[:, None, :] - found[None, :, :], axis=2), axis=1) > 2.5
                    extra = extra[far]
                found = np.vstack([found, extra]) if len(found) else extra
        self.p0 = found
        self.pt = self.p0.copy()
        self.alive = np.ones(len(self.p0), bool)
        self._prev = g

    @property
    def usable(self) -> bool:
        return len(self.p0) >= MIN_ALIVE

    def update(self, frame: np.ndarray) -> None:
        import cv2
        g = _gray(frame, self._clahe)
        idx = np.flatnonzero(self.alive)
        if len(idx):
            lk = _lk_params()
            fwd, st1, _ = cv2.calcOpticalFlowPyrLK(self._prev, g, self.pt[idx].reshape(-1, 1, 2), None, **lk)
            back, st2, _ = cv2.calcOpticalFlowPyrLK(g, self._prev, fwd, None, **lk)
            err = np.linalg.norm(back.reshape(-1, 2) - self.pt[idx], axis=1)
            good = (st1.ravel() == 1) & (st2.ravel() == 1) & (err < FORWARD_BACKWARD_PX)
            self.pt[idx[good]] = fwd.reshape(-1, 2)[good]
            self.alive[idx[~good]] = False
        self._prev = g

    def measure(self) -> tuple[float, float, int] | None:
        """(rho, shape_change, tracked_points); rho is NaN when the nose region has too few points.

        rho > 0: the nose slid towards the right of the image against the inner-face plane, i.e.
        the head turned towards the user's own left."""
        import cv2
        alive = self.alive
        n = int(alive.sum())
        if n < MIN_ALIVE:
            return None
        P0, Pt = self.p0[alive].astype(np.float64), self.pt[alive].astype(np.float64)
        e0, e1, nose = self.lm0[0], self.lm0[1], self.lm0[2]
        D0 = float(np.linalg.norm(e1 - e0))
        if D0 < 8:
            return None
        u0 = (e1 - e0) / D0
        v0 = np.array([-u0[1], u0[0]])
        rel = P0 - nose
        xs, ys, dist = rel @ u0, rel @ v0, np.linalg.norm(rel, axis=1)
        inner = (np.abs(xs) < 0.62 * D0) & (ys > -1.3 * D0) & (ys < 1.0 * D0)
        plane = inner & (dist > 0.42 * D0)
        near = dist < 0.30 * D0
        if plane.sum() < MIN_PLANE:
            return None
        Hm, _ = cv2.findHomography(P0[plane], Pt[plane], cv2.LMEDS)
        if Hm is None:
            return None
        # how much the plane itself changed shape (foreshortening, perspective): evidence of rotation
        pp = cv2.perspectiveTransform(P0[plane][None], Hm)[0]
        sim, _ = cv2.estimateAffinePartial2D(P0[plane], pp, method=cv2.LMEDS)
        shape = 0.0
        if sim is not None:
            shape = float(np.sqrt(np.mean(np.sum((pp - (P0[plane] @ sim[:, :2].T + sim[:, 2])) ** 2, axis=1)))) / D0
        if near.sum() < MIN_NOSE:
            return float("nan"), shape, n
        pred = cv2.perspectiveTransform(P0[near][None], Hm)[0]
        r = Pt[near] - pred
        ends = cv2.perspectiveTransform(np.array([[e0, e1]]), Hm)[0]
        u = ends[1] - ends[0]
        D = float(np.linalg.norm(u))
        if D < 1e-6:
            return None
        return float(np.median(r @ (u / D))) / D, shape, n


class HeadTurn:
    """One attempt: turn towards ``SEQUENCES[sequence][0]``, then the other way, then look ahead."""

    def __init__(self, params: Params, sequence: str = "lr", start: float = 0.0) -> None:
        if sequence not in SEQUENCES:
            raise ValueError(sequence)
        self.p, self.sequence, self.steps = params, sequence, SEQUENCES[sequence]
        self.state = State()
        self._tracker: Tracker | None = None
        self._start = start
        self._streak = 0            # consecutive frames beyond the threshold in the current direction
        self._recent: list[float] = []
        self._missing_since: float | None = None
        self._unlike = 0
        self._match = 0
        self._nan_run = 0

    # ----------------------------------------------------------------- start
    def begin(self, frame: np.ndarray, landmarks: np.ndarray) -> bool:
        """Baseline = a frame where the identity was just recognised.  False: not enough texture."""
        self._tracker = Tracker(frame, landmarks)
        if not self._tracker.usable:
            self._fail("no-texture")
            return False
        return True

    # ---------------------------------------------------------------- frames
    def feed(self, frame: np.ndarray, found: bool, similarity: float | None, rival: float, margin: float,
             now: float) -> State:
        """``found``: the main face was detected; ``similarity``: best cosine similarity of that
        face to the account's templates (None when not computed); ``rival``/``margin``: see Scanner."""
        st = self.state
        if st.verdict != "pending" or self._tracker is None:
            return st
        if now - self._start > self.p.timeout:
            return self._timeout()

        # --- identity continuity -------------------------------------------------------
        if not found:
            if self._missing_since is None:
                self._missing_since = now
            if now - self._missing_since > self.p.lost_seconds:
                return self._fail("lost-face")
        else:
            self._missing_since = None
        if similarity is not None:
            self._unlike = self._unlike + 1 if similarity < self.p.swap_similarity else 0
            if self._unlike >= self.p.swap_frames:
                return self._fail("identity-changed")

        # --- both turns done: the same person must be there once more, looking ahead ----
        if st.phase == "back":
            if similarity is not None:
                ok = similarity >= self.p.threshold and similarity >= rival + margin
                self._match = self._match + 1 if ok else 0
                if self._match >= self.p.required:
                    st.verdict = "passed"
            return st

        # --- geometry ------------------------------------------------------------------
        self._tracker.update(frame)
        m = self._tracker.measure()
        if m is None:
            st.points = int(self._tracker.alive.sum())
            self._nan_run += 1
            if self._nan_run > 20:
                return self._fail("no-texture")
            return st
        rho, shape, n = m
        st.points, st.shape_change = n, max(st.shape_change, shape)
        if math.isnan(rho):
            self._nan_run += 1
            if self._nan_run > 20:
                return self._fail("no-texture")
            return st
        self._nan_run = 0
        if self.p.mirror:
            rho = -rho
        self._recent = (self._recent + [rho])[-3:]
        rho = float(np.median(self._recent))
        st.rho = rho
        st.peak = max(st.peak, abs(rho))
        st.log.append((round(now - self._start, 2), round(rho, 4), round(shape, 4), n))

        # --- state machine: turn towards the requested side, then the other one ---------
        want = self.steps[st.step]
        if want * rho >= self.p.turn:
            self._streak += 1
            if self._streak >= self.p.hold:
                st.step += 1
                self._streak = 0
                if st.step >= len(self.steps):
                    st.phase = "back"
        else:
            self._streak = 0
        return st

    # ---------------------------------------------------------------- verdicts
    def _fail(self, reason: str) -> State:
        self.state.verdict, self.state.reason = "failed", reason
        return self.state

    def _timeout(self) -> State:
        st = self.state
        # rotated a lot (the plane changed shape) yet nothing ever stuck out: a flat picture
        if st.shape_change >= self.p.flat_motion and st.peak < self.p.turn:
            return self._fail("flat-surface")
        return self._fail("challenge-timeout")
