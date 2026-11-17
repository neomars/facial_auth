# SPDX-License-Identifier: MIT
"""Face detection and embedding with OpenCV (YuNet + SFace).

The rest of the daemon only knows the small ``FaceEngine`` interface, which
keeps the matching / liveness / policy code testable without any model.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

from . import models
from .const import Paths
from .store import normalise

log = logging.getLogger(__name__)

EMBEDDING_DIM = 128


class EngineUnavailable(RuntimeError):
    pass


@dataclass
class Face:
    box: tuple[float, float, float, float]      # x, y, w, h (pixels)
    landmarks: np.ndarray                        # (5, 2): eyes, nose, mouth corners
    score: float
    raw: np.ndarray | None = None                # engine specific (YuNet row)

    @property
    def size(self) -> float:
        return min(self.box[2], self.box[3])

    @property
    def area(self) -> float:
        return self.box[2] * self.box[3]


class FaceEngine(Protocol):
    model_id: str          # identifies the embedding space (templates are tied to it)

    def detect(self, frame: np.ndarray) -> list[Face]: ...
    def embed(self, frame: np.ndarray, face: Face) -> np.ndarray: ...


def similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity of two L2-normalised vectors."""
    return float(np.dot(a, b))


class OpenCVEngine:
    """YuNet detector + SFace recognizer (``cv2.FaceDetectorYN`` / ``FaceRecognizerSF``).

    The two OpenCV objects are injected so the class can be tested with a
    stand-in model; ``from_files`` builds the real ones.
    """

    def __init__(self, detector, recognizer, model_id: str, detector_id: str = "") -> None:
        self._det, self._rec = detector, recognizer
        self.model_id = model_id          # embedding model: what templates depend on
        self.detector_id = detector_id
        self._lock = threading.RLock()    # cv2.dnn nets are not re-entrant
        self._size = (320, 240)

    @classmethod
    def from_files(cls, detector_path: Path, recognizer_path: Path, model_id: str,
                   detector_id: str = "", score_threshold: float = 0.9,
                   nms_threshold: float = 0.3, top_k: int = 20) -> "OpenCVEngine":
        import cv2
        try:
            det = cv2.FaceDetectorYN.create(str(detector_path), "", (320, 240),
                                            score_threshold, nms_threshold, top_k)
            rec = cv2.FaceRecognizerSF.create(str(recognizer_path), "")
        except cv2.error as exc:
            raise EngineUnavailable(f"OpenCV {cv2.__version__} cannot load the models: {exc}") from exc
        return cls(det, rec, model_id, detector_id)

    def detect(self, frame: np.ndarray) -> list[Face]:
        h, w = frame.shape[:2]
        with self._lock:
            if (w, h) != self._size:
                self._det.setInputSize((w, h))
                self._size = (w, h)
            _, rows = self._det.detect(frame)
        if rows is None:
            return []
        faces = []
        for row in rows:
            x, y, bw, bh = (float(v) for v in row[:4])
            faces.append(Face(box=(x, y, bw, bh),
                              landmarks=np.asarray(row[4:14], dtype=np.float32).reshape(5, 2),
                              score=float(row[14]), raw=np.asarray(row, dtype=np.float32)))
        faces.sort(key=lambda f: f.area, reverse=True)
        return faces

    def embed(self, frame: np.ndarray, face: Face) -> np.ndarray:
        if face.raw is None:
            raise ValueError("face was not produced by this engine")
        with self._lock:
            aligned = self._rec.alignCrop(frame, face.raw)
            feat = self._rec.feature(aligned)
        return normalise(np.asarray(feat, dtype=np.float32).reshape(1, -1))[0]


_engine: OpenCVEngine | None = None
_engine_lock = threading.Lock()


def load_engine(paths: Paths | None = None) -> OpenCVEngine:
    """Load (once) the models matching the installed OpenCV."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            return _engine
        paths = paths or Paths()
        try:
            import cv2
        except ImportError as exc:
            raise EngineUnavailable("python3-opencv is not installed") from exc
        if not hasattr(cv2, "FaceDetectorYN") or not hasattr(cv2, "FaceRecognizerSF"):
            raise EngineUnavailable(f"OpenCV {cv2.__version__} lacks FaceDetectorYN/FaceRecognizerSF (>= 4.5.4 needed)")
        det_spec, rec_spec = models.required(cv2.__version__)
        det, rec = models.locate(det_spec, paths), models.locate(rec_spec, paths)
        missing = [s.filename for s, p in ((det_spec, det), (rec_spec, rec)) if p is None]
        if missing:
            raise EngineUnavailable("model files missing or corrupted: " + ", ".join(missing)
                                    + " (run: sudo facial-auth fetch-models)")
        engine = OpenCVEngine.from_files(det, rec, rec_spec.key, det_spec.key)
        # Smoke test: a blank frame must run through the detector without error.
        engine.detect(np.zeros((240, 320, 3), dtype=np.uint8))
        log.info("face engine ready (%s + %s, OpenCV %s)", engine.detector_id, engine.model_id, cv2.__version__)
        _engine = engine
        return engine


def reset_engine() -> None:
    global _engine
    with _engine_lock:
        _engine = None
