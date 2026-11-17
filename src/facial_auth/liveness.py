# SPDX-License-Identifier: MIT
"""Presentation-attack heuristics - deliberately minimal and honest.

What is detected: a camera feed that repeats *byte-identical* frames (a replayed
still image, a virtual camera).  A real sensor never produces two identical
frames in a row, so this has practically no false positives.

What is NOT detected: a photograph held in the hand, a screen playing a video,
a mask.  Against those, only an infrared camera helps, which is why the default
policy requires one for sudo/su/polkit (see docs/SECURITY.md).  Heuristics such
as "landmark micro-motion" were tried and dropped: they reject very still
users while barely slowing an attacker down.
"""
from __future__ import annotations

import hashlib

import numpy as np


def frame_hash(frame: np.ndarray) -> bytes:
    return hashlib.blake2b(np.ascontiguousarray(frame).tobytes(), digest_size=8).digest()


def check(frame_hashes: list[bytes], mode: str = "basic") -> tuple[bool, str]:
    """Return (live, reason) for the frames that made up the match streak."""
    if mode == "off" or len(frame_hashes) < 2:
        return True, ""
    if len(set(frame_hashes)) == 1:
        return False, "frozen-frames"
    return True, ""
