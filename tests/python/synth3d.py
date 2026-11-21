# SPDX-License-Identifier: MIT
"""Synthetic textured scenes for the head-turn challenge: no photograph needed.

A scene is a textured surface seen by a pinhole camera: a face-like head (cheek ellipsoid + a nose
that sticks out 3 cm), a flat sheet (a photograph, a phone screen) or a sheet bent by hand.  The
texture is a random mosaic with plenty of corners, the way a real face has eyebrows, nostrils, lips
and moles.  Every pose gives a rendered frame *and* the exact landmarks a face detector would find,
so the tests exercise the real tracking code on frames whose 3-D truth is known.

The same renderer, fed with real portraits, was used to choose the thresholds (docs/SECURITY.md).
"""
from __future__ import annotations

import cv2
import numpy as np

from facial_auth.engine import EMBEDDING_DIM, Face
from facial_auth.store import normalise

W, H = 640, 480
F = 600.0
IOD_MM = 63.0
S = 0.9                                  # millimetres per texture pixel


def make_texture(seed: int, size: int = 280) -> np.ndarray:
    rng = np.random.default_rng(seed)
    img = np.full((size, size, 3), 128, np.float32)
    yy, xx = np.mgrid[0:size, 0:size]
    img += (25 * np.sin(xx / 37.0 + seed) + 20 * np.cos(yy / 29.0 - seed))[..., None]
    for _ in range(260):
        cx, cy = rng.integers(0, size, 2)
        r = int(rng.integers(2, 9))
        col = rng.integers(40, 215, 3).tolist()
        if rng.random() < 0.5:
            cv2.circle(img, (int(cx), int(cy)), r, col, -1)
        else:
            cv2.rectangle(img, (int(cx), int(cy)), (int(cx) + r * 2, int(cy) + r), col, -1)
    img = cv2.GaussianBlur(img, (0, 0), 0.9)
    return np.clip(img, 0, 255).astype(np.uint8)


def rot(yaw: float, pitch: float, roll: float) -> np.ndarray:
    cy, sy, cp, sp, cr, sr = np.cos(yaw), np.sin(yaw), np.cos(pitch), np.sin(pitch), np.cos(roll), np.sin(roll)
    ry = np.array([[cy, 0, sy], [0, 1, 0], [-sy, 0, cy]])
    rp = np.array([[1, 0, 0], [0, cp, -sp], [0, sp, cp]])
    rr = np.array([[cr, -sr, 0], [sr, cr, 0], [0, 0, 1]])
    return ry @ rp @ rr


class Scene:
    """kind: "head" | "flat" | "bent" (bend_mm: how far the middle of the sheet bulges)."""

    def __init__(self, kind: str = "head", nose_mm: float = 30.0, bend_mm: float = 25.0, seed: int = 1,
                 distance: float = 450.0) -> None:
        self.kind, self.nose_mm, self.bend_mm, self.distance = kind, nose_mm, bend_mm, distance
        self.tex = make_texture(seed)
        size = self.tex.shape[0]
        self.centre = np.array([size / 2, size * 0.36])                       # between the eyes
        iod = IOD_MM / S
        # right eye, left eye, nose tip, right and left corner of the mouth (texture pixels)
        self.lm_tex = self.centre + np.array([[-iod / 2, 0], [iod / 2, 0], [0, 48 / S],
                                              [-24 / S, 72 / S], [24 / S, 72 / S]])
        # sample the texture twice as densely as the image needs: no holes to fill after the rotation
        tex2 = cv2.resize(self.tex, None, fx=2, fy=2, interpolation=cv2.INTER_LINEAR)
        uu, vv = np.meshgrid(np.arange(tex2.shape[1], dtype=np.float32), np.arange(tex2.shape[0], dtype=np.float32))
        x, y = (uu / 2 - self.centre[0]) * S, (vv / 2 - self.centre[1]) * S
        inside = ((x / 75.0) ** 2 + ((y - 35.0) / 105.0) ** 2) < 1.0
        z = self._depth(x, y)
        self.points = np.stack([x[inside], y[inside], z[inside]], 1).astype(np.float64)
        self.colours = tex2[inside]
        self.pivot = np.array([0.0, 0.0, -95.0 if kind == "head" else 0.0])
        lx = (self.lm_tex[:, 0] - self.centre[0]) * S
        ly = (self.lm_tex[:, 1] - self.centre[1]) * S
        self.landmarks3d = np.stack([lx, ly, self._depth(lx, ly)], 1)

    def _depth(self, x: np.ndarray, y: np.ndarray) -> np.ndarray:
        x, y = np.asarray(x, np.float64), np.asarray(y, np.float64)
        if self.kind == "flat":
            return np.zeros_like(x)
        if self.kind == "bent":                      # a sheet curved about the vertical axis
            return self.bend_mm * (1 - (x / 95.0) ** 2)
        a, b, y0, cheek = 69.0, 132.0, 31.5, 45.0
        base = cheek * np.sqrt(np.clip(1 - (x / a) ** 2 - ((y - y0) / b) ** 2, 0, 1)) - 0.55 * cheek
        nose = self.nose_mm * np.exp(-(((x - 0) / (0.16 * IOD_MM * 1.2)) ** 2
                                       + ((y - 48.0) / (0.30 * IOD_MM * 1.2)) ** 2) / 2)
        return base + nose

    def render(self, yaw: float = 0.0, pitch: float = 0.0, roll: float = 0.0, shift: tuple[float, float] = (0, 0),
               noise: float = 1.5, rng: np.random.Generator | None = None) -> tuple[np.ndarray, np.ndarray]:
        """(BGR frame, 5x2 landmarks) for a pose in radians."""
        rng = rng or np.random.default_rng(0)
        r = rot(yaw, pitch, roll)

        def project(p: np.ndarray) -> np.ndarray:
            q = (p - self.pivot) @ r.T + self.pivot + [shift[0], shift[1], self.distance]
            return np.stack([F * q[:, 0] / q[:, 2] + W / 2, F * q[:, 1] / q[:, 2] + H / 2], 1), q[:, 2]

        xy, depth = project(self.points)
        ix, iy = np.round(xy[:, 0]).astype(int), np.round(xy[:, 1]).astype(int)
        ok = (ix >= 0) & (ix < W) & (iy >= 0) & (iy < H)
        order = np.argsort(-depth[ok])                      # far first: near points overwrite
        out = np.full((H, W, 3), 55, np.uint8)
        filled = np.zeros((H, W), np.uint8)
        sel = (ix[ok][order], iy[ok][order])
        out[sel[1], sel[0]] = self.colours[ok][order]
        filled[sel[1], sel[0]] = 255
        holes = cv2.morphologyEx(filled, cv2.MORPH_CLOSE, np.ones((3, 3), np.uint8)) & ~filled
        if holes.any():                                     # a few pixels at the silhouette: a median is enough
            out = np.where(holes[..., None] > 0, cv2.medianBlur(out, 3), out)
        out = np.clip(out.astype(np.float32) + rng.normal(0, noise, out.shape), 0, 255).astype(np.uint8)
        lm, _ = project(self.landmarks3d)
        return out, lm


# ------------------------------------------------------------------- movements
def settle(frames: int = 4) -> list[tuple[float, float, float]]:
    return [(0.0, 0.0, 0.0)] * frames


def head_turns(first: int, amplitude_deg: float = 20.0, frames: int = 40, tail: int = 8) -> list:
    """Turn towards `first` (+1: the user's left), swing to the other side, come back, look ahead."""
    t = np.linspace(0, 1, frames)
    yaw = np.radians(amplitude_deg) * first * np.sin(2 * np.pi * t)
    return [(float(y), 0.0, 0.0) for y in yaw] + [(0.0, 0.0, 0.0)] * tail


def tilted_sheet(seed: int, frames: int = 60, amplitude_deg: float = 38.0) -> list:
    """What a hand does to a sheet of paper: wide, oblique, wandering rotations."""
    rng = np.random.default_rng(seed)
    t = np.linspace(0, 1, frames)
    amp = np.radians(amplitude_deg)
    out = []
    ph = rng.uniform(0, 6.28, 3)
    fr = rng.uniform(0.7, 1.7, 3)
    for ti in t:
        out.append((amp * np.sin(2 * np.pi * fr[0] * ti + ph[0]),
                    0.7 * amp * np.sin(2 * np.pi * fr[1] * ti + ph[1]),
                    0.25 * amp * np.sin(2 * np.pi * fr[2] * ti + ph[2])))
    return out


FPS = 15.0


class SceneEngine:
    """Detects the landmarks the scene was rendered with; recognises `identity`."""

    model_id = "fake"
    detector_id = "scene"

    def __init__(self):
        self.landmarks = None
        self.identity = 1

    def detect(self, frame):
        if self.landmarks is None:
            return []
        lm = np.asarray(self.landmarks, np.float32)
        x0, y0 = lm.min(0) - [50, 60]
        x1, y1 = lm.max(0) + [50, 40]
        return [Face((float(x0), float(y0), float(x1 - x0), float(y1 - y0)), lm, 0.99, raw=None)]

    def embed(self, frame, face):
        vec = np.zeros(EMBEDDING_DIM, np.float32)
        vec[self.identity % EMBEDDING_DIM] = 1.0
        vec += np.random.default_rng(0).normal(0, 0.02, EMBEDDING_DIM).astype(np.float32)
        return normalise(vec[None])[0]


class SceneCamera:
    camera_class = "ir"
    name = "scene"

    def __init__(self, scene, poses, engine, who=None, die_after=None):
        self.scene, self.engine, self.t = scene, engine, 0.0
        self.poses = settle(8) + list(poses)
        self.who, self.die_after, self.i = who or {}, die_after, 0
        self.rng = np.random.default_rng(5)
        self._cache = {}

    def open(self):
        pass

    def close(self):
        pass

    def read(self):
        if self.die_after is not None and self.i >= self.die_after:
            return None
        pose = self.poses[min(self.i, len(self.poses) - 1)]
        key = min(self.i, len(self.poses) - 1)
        if key not in self._cache or self.i < len(self.poses):
            self._cache[key] = self.scene.render(*pose, rng=self.rng)
        frame, lm = self._cache[key]
        self.engine.landmarks = lm
        self.engine.identity = self.who.get(self.i, 1)
        self.i += 1
        self.t += 1.0 / FPS
        return frame.copy()
