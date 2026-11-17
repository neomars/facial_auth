# SPDX-License-Identifier: MIT
"""OpenCVEngine against the *real* cv2.FaceRecognizerSF (a stand-in ONNX model).

The detector is a stub returning rows in the documented YuNet layout; what is
verified for real is everything this project calls on OpenCV for embedding:
alignCrop(frame, row) + feature(aligned) on OpenCV 4.6.0.
"""
from pathlib import Path

import numpy as np
import pytest

cv2 = pytest.importorskip("cv2")

from facial_auth.engine import EMBEDDING_DIM, EngineUnavailable, OpenCVEngine, load_engine, reset_engine  # noqa: E402
from facial_auth.const import Paths  # noqa: E402

SURROGATE = Path(__file__).resolve().parents[1] / "fixtures" / "sface_surrogate.onnx"
pytestmark = pytest.mark.skipif(not hasattr(cv2, "FaceRecognizerSF"), reason="OpenCV >= 4.5.4 needed")


class StubDetector:
    """Mimics cv2.FaceDetectorYN.detect(): (retval, Nx15 float32 or None)."""

    def __init__(self, rows=None):
        self.rows, self.sizes = rows, []

    def setInputSize(self, size):
        self.sizes.append(size)

    def detect(self, frame):
        return 1, (None if self.rows is None else np.asarray(self.rows, np.float32))


def row(x=100, y=60, w=120, h=140, score=0.97):
    # x y w h | right eye, left eye, nose, right mouth corner, left mouth corner | score
    lm = [x + .30 * w, y + .35 * h, x + .70 * w, y + .35 * h, x + .50 * w, y + .55 * h,
          x + .33 * w, y + .78 * h, x + .67 * w, y + .78 * h]
    return [x, y, w, h, *lm, score]


@pytest.fixture(scope="module")
def recognizer():
    return cv2.FaceRecognizerSF.create(str(SURROGATE), "")


def textured(seed, shape=(240, 320, 3)):
    rng = np.random.default_rng(seed)
    return rng.integers(0, 256, shape, dtype=np.uint8)


def test_the_surrogate_is_a_valid_sface_interface(recognizer):
    frame = textured(1)
    aligned = recognizer.alignCrop(frame, np.asarray(row(), np.float32))
    assert aligned.shape == (112, 112, 3), "alignCrop must produce the 112x112 SFace input"
    feat = recognizer.feature(aligned)
    assert feat.shape == (1, EMBEDDING_DIM) and feat.dtype == np.float32


def test_embedding_is_normalised_deterministic_and_content_dependent(recognizer):
    eng = OpenCVEngine(StubDetector([row()]), recognizer, "sface-test")
    a, b = textured(1), textured(2)
    fa = eng.detect(a)[0]
    v1, v2 = eng.embed(a, fa), eng.embed(a, fa)
    assert v1.shape == (EMBEDDING_DIM,) and v1.dtype == np.float32
    assert abs(float(np.linalg.norm(v1)) - 1.0) < 1e-5, "templates rely on unit vectors (dot == cosine)"
    assert np.allclose(v1, v2), "same pixels, same embedding"
    noisy = np.clip(a.astype(np.int16) + np.random.default_rng(9).integers(-3, 4, a.shape), 0, 255).astype(np.uint8)
    assert float(v1 @ eng.embed(noisy, eng.detect(noisy)[0])) > 0.95, "tiny noise must not change identity"
    assert float(v1 @ eng.embed(b, eng.detect(b)[0])) < 0.5, "a different picture must differ"


def test_detect_parses_the_yunet_row_layout_and_sorts_by_size():
    small, big = row(x=10, y=10, w=40, h=50, score=0.91), row(x=120, y=40, w=150, h=170, score=0.99)
    eng = OpenCVEngine(StubDetector([small, big]), object(), "m")
    faces = eng.detect(textured(3))
    assert [round(f.box[2]) for f in faces] == [150, 40], "largest face first"
    f = faces[0]
    assert f.landmarks.shape == (5, 2) and abs(f.score - 0.99) < 1e-6 and f.raw.shape == (15,)
    assert f.size == 150 and f.area == 150 * 170
    assert OpenCVEngine(StubDetector(None), object(), "m").detect(textured(3)) == [], "no face -> empty list"


def test_input_size_follows_the_frame_size_only_when_it_changes():
    det = StubDetector([row()])
    eng = OpenCVEngine(det, object(), "m")
    eng.detect(textured(1, (240, 320, 3)))          # default size: nothing to do
    eng.detect(textured(1, (480, 640, 3)))
    eng.detect(textured(1, (480, 640, 3)))
    assert det.sizes == [(640, 480)], "setInputSize takes (width, height) and is not called redundantly"


def test_embedding_a_foreign_face_is_refused(recognizer):
    from facial_auth.engine import Face
    eng = OpenCVEngine(StubDetector([row()]), recognizer, "m")
    with pytest.raises(ValueError):
        eng.embed(textured(1), Face((0, 0, 10, 10), np.zeros((5, 2), np.float32), 0.9, raw=None))


def test_missing_models_give_an_actionable_error(tmp_path):
    reset_engine()
    with pytest.raises(EngineUnavailable) as e:
        load_engine(Paths(tmp_path))
    assert "fetch-models" in str(e.value)


def test_corrupted_model_files_are_refused_before_loading(tmp_path):
    reset_engine()
    p = Paths(tmp_path)
    p.models.mkdir(parents=True)
    for name in ("face_detection_yunet_2022mar.onnx", "face_recognition_sface_2021dec.onnx"):
        (p.models / name).write_bytes(b"not a model")
    with pytest.raises(EngineUnavailable):
        load_engine(p)


def test_the_real_opencv_rejects_a_non_model_file_cleanly(tmp_path):
    bad = tmp_path / "bad.onnx"
    bad.write_bytes(b"garbage")
    with pytest.raises(EngineUnavailable):
        OpenCVEngine.from_files(bad, bad, "m")
