# SPDX-License-Identifier: MIT
"""The daemon against a *real* polkitd (the authorizer was only ever tested with a fake one).

A private D-Bus bus hosts the installed polkitd, the installed facial-authd (started as
the unprivileged facial-auth user, with the real polkit authorizer) and an ordinary user
playing the graphical application.  What is checked:

* polkitd accepts the questions asked by the daemon about *another* user's process:
  that needs the "owner" annotation of the packaged policy (a missing annotation made
  every camera / face-linking request fail with "Not authorized");
* the same question without the annotation is refused, so this test would catch the
  regression, and the explanation stays documented by a running example.
"""
import contextlib
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from .helpers import PYTHON, requires_installed

pytestmark = requires_installed

POLKITD = "/usr/lib/polkit-1/polkitd"
DAEMON = "/usr/libexec/facial-auth/facial-authd"
POLICY_DIR = Path("/usr/share/polkit-1/actions")
RULES_DIR = Path("/etc/polkit-1/rules.d")
BUS_NAME = "io.github.neomars.FacialAuth1"
CLIENT = "fapkclient"
ACTION_CAMERA = "io.github.neomars.FacialAuth1.use-camera"

needs_polkit = pytest.mark.skipif(
    not (Path(POLKITD).exists() and shutil.which("dbus-daemon") and shutil.which("setpriv")
         and subprocess.run(["id", "polkitd"], capture_output=True).returncode == 0
         and Path(DAEMON).exists()),
    reason="needs polkitd (and its user), dbus-daemon, setpriv and the installed package")

BUS_CONF = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path={sock}</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow own="*"/><allow send_type="method_call"/>
<allow send_type="signal"/><allow send_requested_reply="true" send_type="method_return"/>
<allow send_requested_reply="true" send_type="error"/><allow receive_type="method_call"/>
<allow receive_type="method_return"/><allow receive_type="error"/><allow receive_type="signal"/>
</policy></busconfig>"""

# Run as some user, on the private bus: ask the daemon for a camera preview.
ASK_DAEMON = r"""
import sys
from gi.repository import Gio, GLib
conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
def call(method, params):
    return conn.call_sync("io.github.neomars.FacialAuth1", "/io/github/neomars/FacialAuth1",
                          "io.github.neomars.FacialAuth1.Manager", method, params, None,
                          Gio.DBusCallFlags.NONE, 30000, None)
try:
    call("StartPreview", GLib.Variant("(s)", ("",)))
    call("StopPreview", None)
    print("GRANTED")
except GLib.Error as exc:
    print("ERROR", exc.message)
"""

# Run as facial-auth: exactly the question PolkitAuthorizer asks, about another user's process.
ASK_POLKIT = r"""
import sys
from gi.repository import Gio, GLib
pid, start, action = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
subject = ("unix-process", {"pid": GLib.Variant("u", pid), "start-time": GLib.Variant("t", start)})
try:
    res = conn.call_sync("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                         "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization",
                         GLib.Variant("((sa{sv})sa{ss}us)", (subject, action, {}, 0, "")),
                         GLib.VariantType("((bba{ss}))"), Gio.DBusCallFlags.NONE, 30000, None)
    print("ANSWERED", res.unpack()[0][0])
except GLib.Error as exc:
    print("ERROR", exc.message)
"""


# Run as an ordinary user: hand the daemon pictures of every kind and print what each one gets.
ANALYZE = r"""
import cv2, numpy as np
from gi.repository import Gio, GLib
conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
def analyse(data):
    try:
        conn.call_sync("io.github.neomars.FacialAuth1", "/io/github/neomars/FacialAuth1",
                       "io.github.neomars.FacialAuth1.Manager", "AnalyzeImage", GLib.Variant("(ay)", (data,)), None,
                       Gio.DBusCallFlags.NONE, 30000, None)
        return "ANALYSED"
    except GLib.Error as exc:
        return "ERROR " + Gio.DBusError.get_remote_error(exc) + " " + exc.message
head = b'<VRTDataset rasterXSize="4" rasterYSize="4"><!--'
blobs = {
    "jpeg": cv2.imencode(".jpg", np.zeros((120, 160, 3), np.uint8))[1].tobytes(),
    "png": cv2.imencode(".png", np.zeros((120, 160, 3), np.uint8))[1].tobytes(),
    "radiance-hdr": b"#?RADIANCE\nFORMAT=32-bit_rle_rgbe\n\n-Y 8 +X 8\n" + bytes(200),
    "sun-raster": b"\x59\xa6\x6a\x95" + bytes(200),
    "jpeg2000": b"\0\0\0\x0cjP  \r\n\x87\n" + bytes(200),
    "openexr": b"v/1\x01\x02\0\0\0" + bytes(200),
    "dicom": bytes(128) + b"DICM" + bytes(200),
    "nitf": b"NITF02.10" + bytes(200),
    "gdal-vrt": head + b"x" * (140 - len(head)) + b"DTED--><VRTRasterBand/></VRTDataset>",
}
for name, blob in blobs.items():
    print(name, analyse(blob))
"""

# Run as an ordinary user: test one's own account's recognition (it switches the camera on).
TEST_OWN_ACCOUNT = r"""
import sys
from gi.repository import Gio, GLib
conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
try:
    conn.call_sync("io.github.neomars.FacialAuth1", "/io/github/neomars/FacialAuth1",
                   "io.github.neomars.FacialAuth1.Manager", "TestRecognition", GLib.Variant("(ss)", (sys.argv[1], "")),
                   None, Gio.DBusCallFlags.NONE, 30000, None)
    print("RAN")
except GLib.Error as exc:
    print("ERROR", Gio.DBusError.get_remote_error(exc), exc.message)
"""


def as_user(user, code, *args, env=None, timeout=60):
    cmd = ["setpriv", f"--reuid={user}", f"--regid={user}", "--clear-groups", PYTHON, "-c", code, *args]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
    return (r.stdout + r.stderr).strip()


def wait_for_name(address, name, timeout=15):
    code = ("from gi.repository import Gio, GLib\n"
            "c = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)\n"
            f"r = c.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner',"
            f" GLib.Variant('(s)', ('{name}',)), GLib.VariantType('(b)'), Gio.DBusCallFlags.NONE, 2000, None)\n"
            "print(r.unpack()[0])")
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = subprocess.run([PYTHON, "-c", code], capture_output=True, text=True,
                           env={**os.environ, "DBUS_SYSTEM_BUS_ADDRESS": address})
        if r.stdout.strip() == "True":
            return True
        time.sleep(0.2)
    return False


def start_time(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


@pytest.fixture(scope="module")
def rig():
    work = Path(tempfile.mkdtemp(prefix="fa-polkit-"))
    work.chmod(0o777)                              # the daemon (user facial-auth) binds its PAM socket here
    address = f"unix:path={work}/bus.sock"
    (work / "bus.conf").write_text(BUS_CONF.format(sock=work / "bus.sock"))
    bus_pid = int(subprocess.run(["dbus-daemon", f"--config-file={work / 'bus.conf'}", "--fork", "--print-pid"],
                                 capture_output=True, text=True, check=True).stdout.split()[0])
    if subprocess.run(["id", CLIENT], capture_output=True).returncode != 0:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", CLIENT], check=True)
    env = {**os.environ, "DBUS_SYSTEM_BUS_ADDRESS": address}
    procs = []
    logs = {}

    def launch(name, *cmd):
        logs[name] = work / f"{name}.log"
        procs.append(subprocess.Popen(list(cmd), env=env, stdout=open(logs[name], "wb"), stderr=subprocess.STDOUT))

    launch("polkitd", "setpriv", "--reuid=polkitd", "--regid=polkitd", "--clear-groups", POLKITD, "--no-debug")
    assert wait_for_name(address, "org.freedesktop.PolicyKit1"), logs["polkitd"].read_text()
    launch("daemon", "setpriv", "--reuid=facial-auth", "--regid=facial-auth", "--groups=video",
           PYTHON, DAEMON, "--dev", "--socket", str(work / "pam.sock"), "--debug")
    assert wait_for_name(address, BUS_NAME), logs["daemon"].read_text()
    yield {"env": env, "logs": logs, "work": work}
    for p in procs:
        p.terminate()
    for p in procs:
        with contextlib.suppress(subprocess.TimeoutExpired):
            p.wait(5)
    with contextlib.suppress(ProcessLookupError):
        os.kill(bus_pid, signal.SIGTERM)
    subprocess.run(["userdel", "-r", CLIENT], capture_output=True)
    shutil.rmtree(work, ignore_errors=True)


@contextlib.contextmanager
def rule(text):
    """A polkit rule for the duration of a with-block (polkitd reloads rules on change)."""
    path = RULES_DIR / "49-facial-auth-test.rules"
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o644)
    time.sleep(1.0)
    try:
        yield
    finally:
        path.unlink(missing_ok=True)
        time.sleep(1.0)


GRANT_TO_CLIENT = f"""polkit.addRule(function(action, subject) {{
    if (action.id.indexOf("io.github.neomars.FacialAuth1.") == 0 && subject.user == "{CLIENT}")
        return polkit.Result.YES;
}});
"""


@needs_polkit
def test_the_packaged_policy_lets_polkit_answer_the_daemon(rig):
    """With a rule granting the action, the request gets past polkit and reaches the daemon's own
    logic (no camera in a container: NoCamera is the proof; with a camera it is GRANTED).
    Before the annotation it was "not authorized (...use-camera)" whatever the policy said."""
    with rule(GRANT_TO_CLIENT):
        out = as_user(CLIENT, ASK_DAEMON, env=rig["env"])
    assert "AccessDenied" not in out and "not authorized" not in out, \
        f"polkit refused the daemon's question:\n{out}\n{rig['logs']['daemon'].read_text()[-1500:]}"
    assert out.startswith("GRANTED") or "NoCamera" in out, out
    assert "Only trusted callers" not in rig["logs"]["daemon"].read_text()


@needs_polkit
def test_without_a_granting_rule_the_policy_decides_and_polkit_does_not_error(rig):
    """No session in this container, so allow_active=yes cannot apply: a plain 'no' from the policy.
    That is a decision, not the 'Only trusted callers' failure."""
    out = as_user(CLIENT, ASK_DAEMON, env=rig["env"])
    assert "not authorized" in out, out
    assert "Only trusted callers" not in rig["logs"]["daemon"].read_text()


@needs_polkit
def test_polkitd_refuses_unowned_actions_which_is_what_the_annotation_fixes(rig):
    """The mechanism itself: a non-root caller may not ask about another user's process,
    unless it owns the action."""
    unowned = POLICY_DIR / "io.github.neomars.FacialAuth1.selftest.policy"
    unowned.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="io.github.neomars.FacialAuth1.selftest-unowned">
    <description>self test</description><message>self test</message>
    <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>no</allow_active></defaults>
  </action>
  <action id="io.github.neomars.FacialAuth1.selftest-owned">
    <description>self test</description><message>self test</message>
    <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>no</allow_active></defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:facial-auth</annotate>
  </action>
</policyconfig>
""")
    victim = subprocess.Popen(["setpriv", f"--reuid={CLIENT}", f"--regid={CLIENT}", "--clear-groups", "sleep", "60"])
    try:
        time.sleep(1.5)                                    # polkitd notices the new policy file
        args = (str(victim.pid), str(start_time(victim.pid)))
        refused = as_user("facial-auth", ASK_POLKIT, *args, "io.github.neomars.FacialAuth1.selftest-unowned",
                          env=rig["env"])
        accepted = as_user("facial-auth", ASK_POLKIT, *args, "io.github.neomars.FacialAuth1.selftest-owned",
                           env=rig["env"])
    finally:
        victim.kill()
        victim.wait()
        unowned.unlink(missing_ok=True)
    assert refused.startswith("ERROR") and "Only trusted callers" in refused, refused
    assert accepted.startswith("ANSWERED"), accepted


@needs_polkit
def test_an_ordinary_user_can_have_the_daemon_open_nothing_but_jpeg_and_png(rig):
    """AnalyzeImage needs only use-camera, which polkit gives without a password to the active local
    session (a rule stands for it here: a container has no session).  What that user sends is read by
    the process that answers PAM, so only JPEG and PNG may reach OpenCV, which also decodes GDAL, GDCM,
    OpenEXR, JPEG 2000...  This is the audited path, end to end: real polkitd, real packaged daemon."""
    with rule(GRANT_TO_CLIENT):
        out = as_user(CLIENT, ANALYZE, env=rig["env"], timeout=120)
    answers = dict(line.split(" ", 1) for line in out.splitlines() if " " in line)
    assert set(answers) >= {"jpeg", "png", "radiance-hdr", "sun-raster", "jpeg2000", "openexr", "dicom", "nitf",
                            "gdal-vrt"}, out
    for name in ("jpeg", "png"):
        assert answers[name].startswith("ANALYSED") or "EngineUnavailable" in answers[name], (name, answers[name])
    for name in ("radiance-hdr", "sun-raster", "jpeg2000", "openexr", "dicom", "nitf", "gdal-vrt"):
        assert "BadImage" in answers[name] and "only JPEG and PNG" in answers[name], (name, answers[name])
    log = rig["logs"]["daemon"].read_text()
    assert "Traceback" not in log or "BadImage" not in log


@needs_polkit
def test_testing_ones_own_recognition_needs_use_camera_like_a_preview(rig):
    """It switches the camera on: from a session that polkit does not consider an active local one
    (ssh, a background job) it used to work, for any account's own sessions."""
    refused = as_user(CLIENT, TEST_OWN_ACCOUNT, CLIENT, env=rig["env"])
    assert "AccessDenied" in refused and "use-camera" in refused, refused
    with rule(GRANT_TO_CLIENT):
        allowed = as_user(CLIENT, TEST_OWN_ACCOUNT, CLIENT, env=rig["env"])
    assert "AccessDenied" not in allowed, allowed              # it gets as far as "no face linked to this account"
