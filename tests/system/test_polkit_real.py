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
