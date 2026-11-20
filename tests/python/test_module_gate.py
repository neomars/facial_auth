# SPDX-License-Identifier: MIT
"""`facial-auth doctor` and the installer test the PAM module in a throw-away process.

A module that fails to load is ignored by PAM, but one that kills its host (a truncated
or corrupted file makes the dynamic loader die with SIGBUS) takes sudo, su and the login
screen down with it.  So the check must itself be able to survive that.
"""
import shutil
import struct

import pytest

from facial_auth.cli import pam_module_problem


@pytest.fixture(scope="module")
def good_module(build_dir):
    return build_dir / "pam" / "pam_facial_auth.so"


def cut_inside_loaded_segments(data: bytes) -> bytes:
    """Truncate so that the last loadable segment lies wholly beyond the end of the file.

    Cutting "in half" is not enough: an unstripped module ends with debug sections the loader
    never touches.  Pages mapped from beyond the end of a file raise SIGBUS when accessed.
    """
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    loads = []
    for i in range(phnum):
        p_type, _flags, p_offset, _va, _pa, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 1:                                    # PT_LOAD
            loads.append((p_offset, p_filesz))
    last_offset = max(off for off, _ in loads)
    return data[: (last_offset & ~0xFFF) - 1]


def test_a_healthy_module_loads(good_module):
    assert pam_module_problem((str(good_module),)) is None


def test_a_missing_module_is_reported(tmp_path):
    assert "not installed" in pam_module_problem((str(tmp_path / "nothing-*.so"),))


def test_a_truncated_module_is_reported_and_does_not_take_the_checker_down(good_module, tmp_path):
    data = good_module.read_bytes()
    broken = tmp_path / "pam_facial_auth.so"
    broken.write_bytes(cut_inside_loaded_segments(data))
    problem = pam_module_problem((str(broken),))
    assert problem is not None and ("crashed the loader" in problem or "cannot be loaded" in problem), problem


@pytest.mark.parametrize("content", [b"", b"not a library\n", b"\x7fELF" + b"\0" * 200])
def test_garbage_is_reported(tmp_path, content):
    broken = tmp_path / "pam_facial_auth.so"
    broken.write_bytes(content)
    assert "cannot be loaded" in pam_module_problem((str(broken),))


def test_a_library_that_is_not_a_pam_module_is_reported(tmp_path):
    libm = next(p for p in ("/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib/x86_64-linux-gnu/libm.so.6")
                if shutil.os.path.exists(p))
    other = tmp_path / "pam_facial_auth.so"
    shutil.copy(libm, other)
    assert "cannot be loaded" in pam_module_problem((str(other),))
