# SPDX-License-Identifier: MIT
"""Drive the settings app under Xvfb with a fake daemon and save screenshots.

    xvfb-run -a python3 tests/gui/shoot.py OUTDIR

Not a pytest test (needs a display): it prints PASS/FAIL checks and writes PNGs.
"""
import os
import pwd
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("GSK_RENDERER", "cairo")
os.environ["FACIAL_AUTH_LOCALEDIR"] = str(ROOT / "build" / "po")

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Graphene", "1.0")
from gi.repository import Adw, Gio, GLib, Graphene, Gtk  # noqa: E402

out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fa-shots")
out.mkdir(parents=True, exist_ok=True)

bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"], stdout=subprocess.PIPE, text=True)
os.environ["DBUS_SESSION_BUS_ADDRESS"] = bus.stdout.readline().strip()
os.environ["FACIAL_AUTH_BUS"] = "session"

import tempfile  # noqa: E402

from python.fakes import FakeEngine, ScriptedCamera, face_frame  # noqa: E402

from facial_auth import v4l2  # noqa: E402
from facial_auth.const import Paths  # noqa: E402
from facial_auth.core import Core  # noqa: E402
from facial_auth.dbus_service import DBusService  # noqa: E402
from facial_auth.store import FaceStore  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="fa-gui-"))
names = {1000: "alice", 1001: "bob"}
real = {1000: "Alice Martin", 1001: "Bob Durand"}
paths = Paths(tmp)
cam = v4l2.CameraInfo("/dev/video0", "Integrated Camera", "uvcvideo", "", ["MJPG"], "rgb", True)
core = Core(paths=paths, store=FaceStore(paths, name_of=lambda u: names.get(u, "")),
            engine_loader=lambda: FakeEngine(),
            camera_factory=lambda info, cls: ScriptedCamera(lambda i: face_frame(2), cls, fps=30),
            camera_lister=lambda: [cam], lid_probe=lambda: False,
            models_probe=lambda: {"ok": True, "missing": []})
core.human_users = lambda: [pwd.struct_passwd((n, "x", u, u, real[u] + ",,,", f"/home/{n}", "/bin/bash")) for u, n in names.items()]
core.uid_of = lambda name: {v: k for k, v in names.items()}[name]
GLib.get_user_name = lambda: "alice"


class Allow:
    def check(self, sender, action):
        return True


service = DBusService(core, Gio.BusType.SESSION, Allow())
service.start()

from facial_auth.gui.app import Window  # noqa: E402
from facial_auth.client import Client  # noqa: E402

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)


def shot(win, name, tries=6):
    """Save a PNG of the window; an empty snapshot (window mid-redraw) is retried."""
    w, h = win.get_width(), win.get_height()
    snap = Gtk.Snapshot()
    Gtk.WidgetPaintable.new(win).snapshot(snap, w, h)
    node = snap.to_node()
    if node is None:
        if tries > 0:
            GLib.timeout_add(250, lambda: (shot(win, name, tries - 1), False)[1])
        else:
            print("WARN could not render", name, flush=True)
        return
    tex = win.get_native().get_renderer().render_texture(node, Graphene.Rect().init(0, 0, w, h))
    tex.save_to_png(str(out / f"{name}.png"))
    print("saved", name, flush=True)


def later(ms, fn):
    GLib.timeout_add(ms, lambda: (fn(), False)[1])


app = Adw.Application(application_id="io.github.neomars.FacialAuth.test")
state = {}


def activate(app):
    win = Window(app, client=Client("session"))
    win.present()
    state["win"] = win
    later(1800, step1)


def step1():
    win = state["win"]
    shot(win, "01-main-empty")
    check("camera row shows the camera", "Integrated Camera" in win.camera_row.get_title())
    check("two accounts listed", len(win._rows) == 2)
    page = win.open_enrollment("alice")
    state["page"] = page
    later(2500, step2)


def step2():
    win, page = state["win"], state["page"]
    shot(win, "02-capture-camera")
    check("preview running with a camera class", page.camera_class == "rgb" and page._last is not None)
    check("face detected in preview", page._last[1]["faces"] == 1)
    check("shutter enabled when a face is framed", page.shutter.get_sensitive())
    for _ in range(3):
        page.take_photo()
    check("3 photos captured", len(page.photos) == 3)
    check("continue enabled at 3 photos", page.next_btn.get_sensitive())
    later(500, step3)


def step3():
    shot(state["win"], "03-photos-taken")
    state["page"].go_link()
    later(1200, step4)


def step4():
    win, page = state["win"], state["page"]
    shot(win, "04-link-account")
    check("account list filled", page.account_row.get_model().get_n_items() == 2)
    page.link()
    later(2500, step5)


def step5():
    win = state["win"]
    shot(win, "05-main-linked")
    faces = core.store.load(1000).faces
    check("face stored for alice", len(faces) == 1 and faces[0].camera_class == "rgb")
    check("bob untouched", core.store.load(1001).faces == [])
    check("summary updated", "1 face" in win._rows[0].get_subtitle())
    win._rows[0].set_expanded(True)
    later(600, step6)


def step6():
    shot(state["win"], "06-main-expanded")
    state["win"].close()
    app.quit()


app.connect("activate", activate)
GLib.timeout_add_seconds(45, lambda: (print('WATCHDOG: aborting'), app.quit())[1])
code = app.run([])
bus.terminate()
failed = [n for n, ok in checks if not ok]
print(f"{len(checks) - len(failed)}/{len(checks)} checks passed", flush=True)
sys.exit(1 if failed else 0)
