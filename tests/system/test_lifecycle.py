# SPDX-License-Identifier: MIT
"""Getting rid of the package must never cost the ability to log in.

Removing, purging and reinstalling the real .deb files, with the real sudo asked for the real
password after every step: if this program cannot be made to work, it can be taken away.

The packages come from $FA_DEB_DIR (default: ./dist, where scripts/build-deb.sh puts them); the
test is skipped when they are not there.  The installed package is put back at the end.
"""
import os
import subprocess
from pathlib import Path

import pytest

from .helpers import COMMON_AUTH, MARKER, MARKER_DIR, MODULE, box, drive, requires_installed  # noqa: F401

pytestmark = requires_installed

ROOT = Path(__file__).resolve().parents[2]
DEB_DIR = Path(os.environ.get("FA_DEB_DIR", ROOT / "dist"))
SECURITY_DIR = MODULE.parent


@pytest.fixture(scope="module")
def debs():
    main = sorted(DEB_DIR.glob("facial-auth_*_amd64.deb"))
    gtk = sorted(DEB_DIR.glob("facial-auth-gtk_*_all.deb"))
    if not (main and gtk):
        pytest.skip(f"no .deb files in {DEB_DIR} (set FA_DEB_DIR)")
    return [str(main[-1]), str(gtk[-1])]


def dpkg(*args):
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    r = subprocess.run(["dpkg", *args], capture_output=True, text=True, env=env, timeout=300)
    assert r.returncode == 0, f"dpkg {' '.join(args)} failed:\n{r.stdout}\n{r.stderr}"
    return r


def module_in_stack():
    return any("pam_facial_auth" in ln for ln in COMMON_AUTH.read_text().splitlines()
               if ln.strip() and not ln.startswith("#"))


@pytest.fixture
def lifecycle(debs, box):
    """Whatever happens in the test, the package is installed again afterwards."""
    stack_before = COMMON_AUTH.read_text()
    assert module_in_stack(), "the package must be installed and enabled before this test"
    yield debs
    dpkg("-i", *debs)
    COMMON_AUTH.write_text(stack_before)         # byte for byte what we found
    MARKER_DIR.mkdir(parents=True, exist_ok=True)


def test_removing_the_package_restores_the_stack_and_the_password_still_works(lifecycle):
    stack_with_module = COMMON_AUTH.read_text()
    MARKER_DIR.mkdir(parents=True, exist_ok=True)
    MARKER.touch()                               # a linked face: the most exposed account
    dpkg("-r", "facial-auth-gtk", "facial-auth")
    assert not module_in_stack(), "removal must take the module out of /etc/pam.d/common-auth"
    assert not MODULE.exists()
    assert stack_with_module != COMMON_AUTH.read_text()
    drive("lifecycle/removed", budget=0.5)

    dpkg("-i", *lifecycle)                       # and it comes back by itself
    assert module_in_stack(), "reinstalling must enable the module again"
    MARKER_DIR.mkdir(parents=True, exist_ok=True)
    MARKER.touch()
    drive("lifecycle/reinstalled", budget=0.5)


def test_purging_removes_the_biometric_data_and_the_password_still_works(lifecycle):
    MARKER_DIR.mkdir(parents=True, exist_ok=True)
    MARKER.touch()
    templates = Path("/var/lib/facial-auth/templates")
    templates.mkdir(parents=True, exist_ok=True)
    (templates / "stand-in.json").write_text("{}")
    dpkg("-P", "facial-auth-gtk", "facial-auth")
    assert not module_in_stack()
    assert not Path("/var/lib/facial-auth").exists(), "purge must delete the face data"
    assert not Path("/usr/share/facial-auth/models").exists()
    drive("lifecycle/purged", budget=0.5)

    dpkg("-i", *lifecycle)
    assert module_in_stack()
    drive("lifecycle/reinstalled-after-purge", budget=0.5)


def test_a_failed_upgrade_midway_does_not_leave_a_dangling_module_in_the_stack(lifecycle):
    """prerm runs pam-auth-update first: even when dpkg is interrupted after the files are gone,
    the stack no longer mentions the module (and PAM would ignore a missing module anyway)."""
    dpkg("-r", "facial-auth-gtk")
    r = subprocess.run(["/var/lib/dpkg/info/facial-auth.prerm", "remove"], capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    assert not module_in_stack()
    MODULE.unlink()                              # what dpkg would have done next
    drive("lifecycle/interrupted-removal", budget=0.5)
