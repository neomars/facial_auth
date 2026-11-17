# SPDX-License-Identifier: MIT
"""Shared pytest fixtures: builds the C module/helpers with meson once."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture(scope="session")
def build_dir():
    """Return the meson build directory, (re)building it if needed."""
    bdir = Path(os.environ.get("FA_BUILD_DIR", ROOT / "build"))
    if not (bdir / "build.ninja").exists():
        subprocess.run(["meson", "setup", str(bdir), str(ROOT), "--prefix=/usr",
                        "--libdir=lib/x86_64-linux-gnu"], check=True,
                       capture_output=True)
    subprocess.run(["ninja", "-C", str(bdir)], check=True, capture_output=True)
    return bdir
