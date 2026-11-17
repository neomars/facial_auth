# SPDX-License-Identifier: MIT
"""Release tooling: version stamping, model bundling helpers and the workflow.

The workflow cannot be run here, so its *structure* is pinned: least-privilege
permissions, no way for a tag name to reach a shell, nothing published unless a
release triggered the run.
"""
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from facial_auth import models

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "set-version.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "deb.yml"
STAMPED = ["meson.build", "src/facial_auth/const.py", "debian/changelog",
           "man/facial-auth.1", "man/facial-auth-settings.1", "man/pam_facial_auth.8",
           "scripts/set-version.sh"]


def run(args, cwd):
    return subprocess.run(["bash", *args], cwd=cwd, capture_output=True, text=True)


@pytest.fixture
def tree(tmp_path):
    for rel in STAMPED:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return tmp_path


# ------------------------------------------------------------ tag -> version
@pytest.mark.parametrize("tag, expected", [
    ("v1.2.3", "1.2.3"),
    ("1.2.3", "1.2.3"),
    ("v0.1.0", "0.1.0"),
    ("v1.2.3-rc1", "1.2.3~rc1"),            # a Debian pre-release sorts BEFORE the release
    ("v2.0.0-beta.2", "2.0.0~beta.2"),
    ("v1.2.3+build5", "1.2.3+build5"),
    ("v10.20", "10.20"),
])
def test_tags_become_debian_versions(tree, tag, expected):
    r = run(["scripts/set-version.sh", "--print", "--from-tag", tag], tree)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == expected


@pytest.mark.parametrize("hostile", [
    "", "v", "latest", "release-1", "v1.2.3; touch pwned", "v1.2.3$(touch pwned)", "v1.2.3`touch pwned`",
    "v1.2.3 && touch pwned", "v1.2.3\ntouch pwned", "../../etc/passwd", "v1.2.3|x", "v1.2.3'x",
    'v1.2.3"x', "v1:2.3", "v1.2.3 ", " v1.2.3",
])
def test_hostile_or_malformed_tags_are_refused_and_never_executed(tree, hostile):
    """The tag name is typed by a human on a web page: it must never reach sed/sh unchecked."""
    r = run(["scripts/set-version.sh", "--from-tag", hostile], tree)
    assert r.returncode != 0
    assert not (tree / "pwned").exists()
    assert (tree / "debian/changelog").read_text() == (ROOT / "debian/changelog").read_text(), \
        "a refused version must not touch any file"


def test_a_plain_version_does_not_accept_a_hyphen(tree):
    """Native Debian packages cannot have '-' in their version: ask for '~rc1'."""
    assert run(["scripts/set-version.sh", "--print", "0.2.0-rc1"], tree).returncode != 0
    assert run(["scripts/set-version.sh", "--print", "0.2.0~rc1"], tree).stdout.strip() == "0.2.0~rc1"


# ------------------------------------------------------------------ stamping
def test_stamping_updates_every_place_that_carries_the_version(tree):
    before = {rel: (tree / rel).read_text() for rel in STAMPED}
    r = run(["scripts/set-version.sh", "1.2.3"], tree)
    assert r.returncode == 0, r.stderr

    assert "  version: '1.2.3'," in (tree / "meson.build").read_text()
    assert 'VERSION = "1.2.3"' in (tree / "src/facial_auth/const.py").read_text()
    for man in ("man/facial-auth.1", "man/facial-auth-settings.1", "man/pam_facial_auth.8"):
        th = [ln for ln in (tree / man).read_text().splitlines() if ln.startswith(".TH ")]
        assert th and '"facial-auth 1.2.3"' in th[0], man

    changelog = (tree / "debian/changelog").read_text()
    assert changelog.startswith("facial-auth (1.2.3) unstable; urgency=medium\n")
    assert before["debian/changelog"] in changelog, "history is kept below the new entry"
    assert run(["scripts/set-version.sh", "--current"], tree).stdout.strip() == "1.2.3"

    # nothing else changed in the stamped files: a version bump is a one-line diff
    for rel in ("meson.build", "src/facial_auth/const.py"):
        old, new = before[rel].splitlines(), (tree / rel).read_text().splitlines()
        assert len(old) == len(new) and sum(a != b for a, b in zip(old, new)) == 1, rel


def test_the_stamped_changelog_is_valid_for_dpkg(tree):
    if not shutil.which("dpkg-parsechangelog"):
        pytest.skip("dpkg-dev not installed")
    run(["scripts/set-version.sh", "1.2.3~rc1"], tree)
    run(["scripts/set-version.sh", "1.2.3"], tree)
    out = subprocess.run(["dpkg-parsechangelog", "-l", str(tree / "debian/changelog"), "--all"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr          # the whole file parses: format and dates are valid
    # --all merges the entries into one record whose "Changes" lists them, newest first
    assert re.findall(r"^ facial-auth \((.+?)\) unstable", out.stdout, re.M) == ["1.2.3", "1.2.3~rc1", "0.1.0"]
    assert re.search(r"^Version: 1\.2\.3$", out.stdout, re.M)
    top = subprocess.run(["dpkg-parsechangelog", "-l", str(tree / "debian/changelog"), "-S", "Maintainer"],
                         capture_output=True, text=True).stdout.strip()
    assert top.startswith("facial-auth maintainers <")


def test_the_repository_itself_is_consistent_about_its_version():
    """The unstamped sources must all agree (CI only stamps the release number)."""
    meson = re.search(r"^  version: '([^']+)',", (ROOT / "meson.build").read_text(), re.M).group(1)
    const = re.search(r'^VERSION = "([^"]+)"', (ROOT / "src/facial_auth/const.py").read_text(), re.M).group(1)
    current = run(["scripts/set-version.sh", "--current"], ROOT).stdout.strip()
    assert meson == const == current


# ------------------------------------------------------- models for packaging
def spec_for(name, payload):
    return models.ModelSpec(name, f"{name}.onnx", hashlib.sha256(payload).hexdigest(), len(payload),
                            (f"https://example.invalid/{name}",), "MIT", "detector")


class FakeResponse:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, n):
        chunk, self.pos = self.data[self.pos:self.pos + n], self.pos + n
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_all_downloads_every_model_and_check_dir_agrees(tmp_path):
    payloads = {"a": b"alpha" * 50, "b": b"beta" * 70}
    specs = tuple(spec_for(n, p) for n, p in payloads.items())
    served = {f"https://example.invalid/{n}": p for n, p in payloads.items()}
    files = models.fetch_all(tmp_path, opener=lambda url, timeout=0: FakeResponse(served[url]), specs=specs)
    assert sorted(f.name for f in files) == ["a.onnx", "b.onnx"]
    assert models.check_dir(tmp_path, specs) == []


def test_check_dir_reports_missing_truncated_and_tampered_files(tmp_path):
    specs = (spec_for("ok", b"x" * 100), spec_for("missing", b"y" * 100),
             spec_for("short", b"z" * 100), spec_for("tampered", b"w" * 100))
    (tmp_path / "ok.onnx").write_bytes(b"x" * 100)
    (tmp_path / "short.onnx").write_bytes(b"z" * 10)
    (tmp_path / "tampered.onnx").write_bytes(b"W" * 100)        # right size, wrong content
    problems = models.check_dir(tmp_path, specs)
    assert sorted(p.split(":")[0] for p in problems) == ["missing.onnx", "short.onnx", "tampered.onnx"]
    assert "ok.onnx" not in " ".join(problems)


def test_every_pinned_model_is_fetched_by_the_packaging_script_set():
    """The package must work on any OpenCV: it bundles the detector of each generation."""
    names = {s.filename for s in models.ALL}
    assert {"face_detection_yunet_2022mar.onnx", "face_detection_yunet_2023mar.onnx",
            "face_recognition_sface_2021dec.onnx"} <= names
    rules = (ROOT / "debian/rules").read_text()
    assert "data/models" in rules and "usr/share/facial-auth/models" in rules


# ------------------------------------------------------------------ workflow
yaml = pytest.importorskip("yaml")


@pytest.fixture(scope="module")
def wf():
    return yaml.safe_load(WORKFLOW.read_text())


def steps(wf):
    for name, job in wf["jobs"].items():
        for step in job["steps"]:
            yield name, step


def test_workflow_triggers(wf):
    on = wf.get("on", wf.get(True))            # PyYAML parses a bare `on` key as True
    assert on["release"]["types"] == ["published"]
    assert "pull_request" in on and "workflow_dispatch" in on
    assert "push" not in on, "a tag push AND a release would build twice"


def test_least_privilege_permissions(wf):
    assert wf["permissions"] == {"contents": "read"}
    writers = [n for n, job in wf["jobs"].items() if job.get("permissions", {}).get("contents") == "write"]
    assert writers == ["publish"], "only the publishing job may write to the repository"


def test_nothing_is_published_unless_a_release_triggered_the_run(wf):
    pub = wf["jobs"]["publish"]
    assert pub["if"] == "github.event_name == 'release'"
    assert set(pub["needs"]) == {"build", "verify"}, "publish only after build AND clean-machine verification"
    script = "\n".join(s["run"] for s in pub["steps"] if "run" in s)
    assert "gh release upload" in script and "--clobber" in script and "SHA256SUMS" in script


def test_event_data_never_reaches_a_shell_directly(wf):
    """Script injection: ${{ github.event.* }} / inputs must go through env: only."""
    pattern = re.compile(r"\$\{\{\s*(github\.event|github\.head_ref|inputs|github\.ref_name)")
    for job, step in steps(wf):
        if "run" in step:
            assert not pattern.search(step["run"]), f"{job}: '{step.get('name')}' interpolates event data in a script"


def test_only_official_actions_are_used(wf):
    uses = [s["uses"] for _, s in steps(wf) if "uses" in s]
    assert uses and all(u.startswith("actions/") for u in uses), uses


def test_release_builds_must_bundle_verified_models_and_pass_lintian(wf):
    build = "\n".join(s["run"] for s in wf["jobs"]["build"]["steps"] if "run" in s)
    assert "scripts/fetch-models.py data/models" in build
    assert "scripts/build-deb.sh --require-models" in build
    assert "lintian --fail-on error" in build


def test_the_package_is_verified_on_a_machine_that_did_not_build_it(wf):
    verify = wf["jobs"]["verify"]
    assert verify["needs"] == "build" and verify["runs-on"] == "ubuntu-24.04"
    uses = [s["uses"] for s in verify["steps"] if "uses" in s]
    assert any(u.startswith("actions/download-artifact") for u in uses)
    script = "\n".join(s["run"] for s in verify["steps"] if "run" in s)
    assert "apt-get install" in script and "./dist/facial-auth_" in script
    assert "tests/system" in script


def test_run_scripts_are_valid_shell(wf, tmp_path):
    for i, (job, step) in enumerate(s for s in steps(wf) if "run" in s[1]):
        f = tmp_path / f"step{i}.sh"
        f.write_text(step["run"])
        r = subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, f"{job}/{step.get('name')}: {r.stderr}"


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
def test_scripts_pass_shellcheck():
    r = subprocess.run(["shellcheck", "-x", *map(str, (ROOT / "scripts").glob("*.sh"))],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
