# SPDX-License-Identifier: MIT
"""Fixtures shared by the Python tests.

The D-Bus environment is *session* scoped: GLib keeps one process-wide session
bus connection, so a second private bus created by another module would leave
the second service attached to the first (terminated) daemon.
"""
import os
import subprocess
import threading

import pytest

gi = pytest.importorskip("gi")
from gi.repository import Gio, GLib  # noqa: E402

from facial_auth import v4l2  # noqa: E402
from facial_auth.const import BUS_NAME, IFACE, OBJECT_PATH, Paths  # noqa: E402
from facial_auth.core import Core  # noqa: E402
from facial_auth.dbus_service import DBusService  # noqa: E402

from .fakes import FakeEngine, ScriptedCamera, face_frame  # noqa: E402

USER = "fadbus"


class Polkit:
    def __init__(self):
        self.grants, self.asked, self.unavailable = set(), [], None
        self.interactive = []                      # whether the caller allowed polkit to ask for a password
        self.hold = None                           # an Event: checks wait for it (a person typing a password)

    def check(self, sender, action):
        from facial_auth.dbus_service import call_is_interactive
        self.asked.append(action)
        self.interactive.append(call_is_interactive())
        if self.hold is not None:
            self.hold.wait(30)
        if self.unavailable:                      # polkit cannot be asked at all
            from facial_auth.dbus_service import PolkitUnavailable
            raise PolkitUnavailable(self.unavailable)
        return action in self.grants


@pytest.fixture(scope="session")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dbus")
    if os.geteuid() == 0 and subprocess.run(["id", USER], capture_output=True).returncode != 0:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", USER], check=True)
    import pwd
    uid = pwd.getpwnam(USER).pw_uid
    bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"],
                           stdout=subprocess.PIPE, text=True)
    address = bus.stdout.readline().strip()
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = address

    paths = Paths(tmp / "root")
    # These tests are about the API, not about liveness: the synthetic frames cannot turn their head.
    # The head-turn test has its own end-to-end tests (test_challenge*.py).
    paths.config.parent.mkdir(parents=True, exist_ok=True)
    paths.config.write_text("[liveness]\nmode = basic\n")
    e = type("Env", (), {})()
    e.scene = {"identity": 1}
    e.polkit = Polkit()
    e.uid = uid
    cam = v4l2.CameraInfo("/dev/video0", "Fake", "uvcvideo", "", ["MJPG"], "rgb", True)
    e.core = Core(paths=paths, engine_loader=lambda: FakeEngine(),
                  camera_factory=lambda info, cls: ScriptedCamera(lambda i: face_frame(e.scene["identity"]), cls),
                  camera_lister=lambda: [cam], lid_probe=lambda: False,
                  models_probe=lambda: {"ok": True, "missing": []})
    e.service = DBusService(e.core, Gio.BusType.SESSION, e.polkit)
    ready = threading.Event()
    e.service._on_ready = ready.set
    e.loop = GLib.MainLoop()
    def run():
        e.service.start()
        e.loop.run()
    threading.Thread(target=run, daemon=True).start()
    assert ready.wait(10), "service did not acquire its bus name"
    e.conn = Gio.DBusConnection.new_for_address_sync(
        address, Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None, None)
    e.signals = []
    e.conn.signal_subscribe(BUS_NAME, IFACE, "FacesChanged", OBJECT_PATH, None, Gio.DBusSignalFlags.NONE,
                            lambda *a: e.signals.append(a[5].unpack()[0]), None)
    yield e
    e.service.stop_preview(force=True)
    e.loop.quit()
    bus.terminate()
    bus.wait(5)
    subprocess.run(["userdel", "-r", USER], capture_output=True)


