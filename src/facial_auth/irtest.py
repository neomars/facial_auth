# SPDX-License-Identifier: MIT
"""Does the "infrared" camera see a phone screen?  (it must not)

A real infrared camera has a filter that blocks visible light: a phone showing a bright white page
is a dark rectangle to it.  A monochrome sensor without that filter sees a saturated white
rectangle - and a photograph shown on a phone then looks like a face.

The person first looks at the camera (baseline), then holds a phone with a bright white page close
to the lens.  Only three things are measured, on the central part of the image, with no model:
the share of saturated pixels, the brightness against the baseline, and how much the picture
changed (something must have been shown, or the test proves nothing).
"""
from __future__ import annotations

import numpy as np

SATURATED = 235
SEES_SATURATION = 0.10       # this much of the picture saturated: it sees the screen
BLIND_SATURATION = 0.03      # ... less than this: it does not
SEES_BRIGHTER = 45.0         # brighter than the baseline by this much: it sees the screen
BLIND_BRIGHTER = 20.0
MIN_CHANGE = 8.0             # mean absolute difference to the baseline: something was put in front


def _centre(frame: np.ndarray) -> np.ndarray:
    gray = frame[:, :, 0] if frame.ndim == 3 else frame
    h, w = gray.shape
    return gray[int(h * 0.15):int(h * 0.85), int(w * 0.15):int(w * 0.85)]


class Accumulator:
    """Frames in, verdict out; keeps one running mean picture, not the frames."""

    def __init__(self, dark: float = 6.0) -> None:
        self.dark = dark
        self._sum: np.ndarray | None = None
        self._n = 0
        self._base_means: list[float] = []
        self.shown: list[tuple[float, float, float]] = []   # (mean, saturated share, change)

    def add_baseline(self, frame: np.ndarray) -> None:
        c = _centre(frame).astype(np.float32)
        if float(c.mean()) < self.dark:           # emitter off in a strobing camera
            return
        self._sum = c if self._sum is None else self._sum + c
        self._n += 1
        self._base_means.append(float(c.mean()))

    def add_shown(self, frame: np.ndarray) -> None:
        c = _centre(frame).astype(np.float32)
        if float(c.mean()) < self.dark and self._n == 0:
            return
        base = self._sum / self._n if self._n else np.zeros_like(c)
        self.shown.append((float(c.mean()), float(np.mean(c >= SATURATED)), float(np.mean(np.abs(c - base)))))

    def verdict(self) -> dict:
        if self._n < 3 or len(self.shown) < 5:
            return {"verdict": "inconclusive", "reason": "too-few-frames", "frames": self._n + len(self.shown)}
        base = float(np.median(self._base_means))
        mean, sat, change = (float(np.percentile([s[i] for s in self.shown], 90)) for i in range(3))
        out = {"baseline": round(base, 1), "peak_brightness": round(mean, 1),
               "saturated": round(sat, 4), "change": round(change, 1), "frames": self._n + len(self.shown)}
        if sat >= SEES_SATURATION or mean >= base + SEES_BRIGHTER:
            return {**out, "verdict": "sees-visible-light"}
        if change < MIN_CHANGE:
            return {**out, "verdict": "inconclusive", "reason": "nothing-shown"}
        if sat < BLIND_SATURATION and mean <= base + BLIND_BRIGHTER:
            return {**out, "verdict": "infrared"}
        return {**out, "verdict": "inconclusive", "reason": "ambiguous"}
