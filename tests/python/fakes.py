# SPDX-License-Identifier: MIT
"""Deterministic test doubles: a camera, an engine and synthetic "faces".

A synthetic face is a frame whose centre patch has a level that encodes the
identity.  FakeEngine "detects" the patch and embeds it as a one-hot-ish
vector, so same identity => cosine ~ 1, different identity => ~ 0.
"""
from __future__ import annotations

import numpy as np

from facial_auth.engine import EMBEDDING_DIM, Face
from facial_auth.store import normalise

W, H = 320, 240
RNG = np.random.default_rng(1234)


def face_frame(identity: int | None, size: int = 120, noise: float = 2.0,
               offset: tuple[int, int] = (0, 0), still: bool = False) -> np.ndarray:
    """A frame with a face of ``identity`` (None: empty scene).

    Identities must be >= 1 (level 100 would sit on the detection threshold).
    Sensor noise is added *after* painting, so even the face area changes
    from frame to frame like a real camera; ``still=True`` removes it.
    """
    base = np.full((H, W, 3), 30, np.uint8)
    if identity is not None:
        x, y = (W - size) // 2 + offset[0], (H - size) // 2 + offset[1]
        base[y:y + size, x:x + size] = 100 + 10 * identity
    if not still:
        base = np.clip(base + RNG.normal(0, noise, base.shape), 0, 255).astype(np.uint8)
    return base


class FakeEngine:
    """Detects every bright blob as a face (connected components)."""

    model_id = "fake"
    detector_id = "fake-detector"

    def __init__(self, min_size: int = 20) -> None:
        self.detect_calls = 0
        self.embed_calls = 0

    def detect(self, frame: np.ndarray) -> list[Face]:
        import cv2
        self.detect_calls += 1
        mask = (frame[:, :, 0] >= 100).astype(np.uint8)
        n, _labels, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)
        faces = []
        for i in range(1, n):
            x, y, w, h, area = (int(v) for v in stats[i])
            if area < 400:
                continue
            cx, cy = x + w / 2, y + h / 2
            lm = np.array([[cx - w / 4, cy - h / 6], [cx + w / 4, cy - h / 6], [cx, cy],
                           [cx - w / 5, cy + h / 4], [cx + w / 5, cy + h / 4]], np.float32)
            faces.append(Face((float(x), float(y), float(w), float(h)), lm, 0.99, raw=None))
        faces.sort(key=lambda f: f.area, reverse=True)
        return faces

    def embed(self, frame: np.ndarray, face: Face) -> np.ndarray:
        self.embed_calls += 1
        x, y, w, h = (int(v) for v in face.box)
        cy, cx = y + h // 2, x + w // 2
        level = float(np.median(frame[cy - 5:cy + 5, cx - 5:cx + 5, 0]))   # robust to noise
        identity = int(round((level - 100) / 10))
        vec = np.zeros(EMBEDDING_DIM, np.float32)
        vec[identity % EMBEDDING_DIM] = 1.0
        vec += RNG.normal(0, 0.02, EMBEDDING_DIM).astype(np.float32)
        return normalise(vec[None])[0]


def template(identity: int, n: int = 3) -> np.ndarray:
    eng = FakeEngine()
    out = []
    for _ in range(n):
        f = face_frame(identity)
        out.append(eng.embed(f, eng.detect(f)[0]))
    return np.stack(out)


class ScriptedCamera:
    """Frames from a function of the frame index; counts reads."""

    def __init__(self, make, camera_class="rgb", fps=400.0, fail_first=0):
        import time
        self._make, self.camera_class, self.name = make, camera_class, "scripted"
        self._period, self._i, self._fail_first = 1.0 / fps, 0, fail_first
        self._sleep = time.sleep
        self.reads, self.opened, self.closed = 0, False, False

    def open(self):
        self.opened = True

    def read(self):
        self._sleep(self._period)
        self.reads += 1
        i, self._i = self._i, self._i + 1
        if i < self._fail_first:
            return None
        return self._make(i)

    def close(self):
        self.closed = True
