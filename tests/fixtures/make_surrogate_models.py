# SPDX-License-Identifier: MIT
"""Generate a tiny stand-in for SFace, to exercise the real OpenCV API.

    python3 -m venv /tmp/v && /tmp/v/bin/pip install onnx numpy
    /tmp/v/bin/python tests/fixtures/make_surrogate_models.py

The real models (opencv_zoo) cannot be committed (38 MB, Git LFS).  This graph
has the same interface as SFace -- input "data" 1x3x112x112, output 1x128 --
with fixed random weights, so FaceRecognizerSF.alignCrop/feature can be run
for real.  It recognises nobody: it only proves the plumbing.
"""
import sys
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

rng = np.random.default_rng(20261117)
w_conv = rng.normal(0, 0.05, (4, 3, 28, 28)).astype(np.float32)
w_conv -= w_conv.mean(axis=(1, 2, 3), keepdims=True)   # zero-mean: ignore brightness, see structure
b_conv = rng.normal(0, 0.01, (4,)).astype(np.float32)
w_fc = rng.normal(0, 0.2, (128, 64)).astype(np.float32)   # [out, in]: PyTorch Linear layout
b_fc = np.zeros((128,), np.float32)

nodes = [
    helper.make_node("Conv", ["data", "Wc", "Bc"], ["c1"], kernel_shape=[28, 28], strides=[28, 28]),
    helper.make_node("Flatten", ["c1"], ["flat"], axis=1),
    helper.make_node("Gemm", ["flat", "Wf", "Bf"], ["fc1"], transB=1),
]
graph = helper.make_graph(
    nodes, "sface_surrogate",
    [helper.make_tensor_value_info("data", TensorProto.FLOAT, [1, 3, 112, 112])],
    [helper.make_tensor_value_info("fc1", TensorProto.FLOAT, [1, 128])],
    [numpy_helper.from_array(w_conv, "Wc"), numpy_helper.from_array(b_conv, "Bc"),
     numpy_helper.from_array(w_fc, "Wf"), numpy_helper.from_array(b_fc, "Bf")])
model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 11)])
model.ir_version = 7
onnx.checker.check_model(model)
out = Path(__file__).with_name("sface_surrogate.onnx")
out.write_bytes(model.SerializeToString())
print("wrote", out, out.stat().st_size, "bytes")
