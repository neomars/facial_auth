# SPDX-License-Identifier: MIT
"""facial-auth: command line management (the howdy-style entry point)."""
from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import models
from .client import Client, ClientError
from .const import Paths, VERSION
from .i18n import _

POSES = [_("Look straight at the camera"), _("Turn your head slightly to the left"),
         _("Turn your head slightly to the right"), _("Tilt your head slightly up"),
         _("Tilt your head slightly down"), _("Look straight again, smile")]
HINTS = {
    "no-face": _("no face visible"), "multiple-faces": _("several faces visible"),
    "too-small": _("too far: come closer"), "too-dark": _("too dark"),
    "too-bright": _("too bright"), "blurry": _("blurry: stay still"),
}


def default_user() -> str:
    for var in ("SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(var)
        if val:
            return pwd.getpwuid(int(val)).pw_name if val.isdigit() else val
    return getpass.getuser()


def say(msg: str = "", **kw) -> None:
    print(msg, **kw)


@contextlib.contextmanager
def polkit_text_agent():
    """Let polkit ask for the administrator password in this terminal."""
    proc = None
    if sys.stdin.isatty() and shutil.which("pkttyagent"):
        proc = subprocess.Popen(["pkttyagent", "--process", str(os.getpid()), "--fallback"])
        time.sleep(0.2)
    try:
        yield
    finally:
        if proc:
            proc.terminate()
            with contextlib.suppress(Exception):
                proc.wait(2)


def explain(err: ClientError) -> str:
    table = {
        "access-denied": _("Not authorized (an administrator must approve this action)."),
        "polkit-unavailable": _("Cannot ask polkit whether you may do this (is polkitd installed and running?)."),
        "daemon-unavailable": _("The facial-authd service is not running (try: sudo systemctl start facial-authd)."),
        "no-camera": _("No suitable camera found."),
        "camera-busy": _("The camera is in use by another application."),
        "engine-unavailable": _("Face models are missing: run 'sudo facial-auth fetch-models'."),
        "not-enough-faces": _("Not enough usable photos."),
        "inconsistent": _("The photos do not all show the same person."),
        "not-enrolled": _("No face is linked to this account."),
    }
    base = table.get(err.code, "")
    return f"{base} [{err}]" if base and str(err) and err.code in ("not-enough-faces", "inconsistent", "polkit-unavailable") else (base or str(err))


# ------------------------------------------------------------------ commands
def cmd_status(args, c: Client) -> int:
    s = c.status()
    say(_("Face authentication: %s") % (_("enabled") if s["enabled"] else _("disabled")))
    say(_("Camera: %s") % (f"{s['camera_name']} ({s['camera_class'].upper()}, {s['camera']})" if s["camera"] else _("none")))
    say(_("Models: %s") % (_("ok") if s["models_ok"] else _("missing: %s") % s["models_missing"]))
    say(_("Lid: %s") % (_("closed") if s["lid_closed"] else _("open")))
    say(_("Accounts:"))
    for u in c.users():
        mark = (_("%d face(s), %s") % (u["faces"], _("on") if u["enabled"] else _("off"))) if u["faces"] else _("no face")
        lock = _(" [locked out for %ds]") % u["locked_out"] if u["locked_out"] else ""
        say(f"  {u['name']:<16} {mark}{lock}")
    return 0


def cmd_cameras(args, c: Client) -> int:
    for cam in c.cameras():
        flags = ("" if cam["usable"] else _(" (not a capture device)")) + (_(" (virtual)") if cam["virtual"] else "")
        say(f"{cam['path']:<14} {cam['class']:<8} {cam['name']} [{cam['formats']}]{flags}")
    return 0


def cmd_list(args, c: Client) -> int:
    users = [args.user] if args.user else [u["name"] for u in c.users() if u["faces"]]
    if not users:
        say(_("No face is linked to any account."))
    for name in users:
        say(f"{name}:")
        for f in c.faces(name):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(f["created"]))
            say(f"  {f['id']}  {f['label']:<20} {f['camera_class'].upper():<4} {f['samples']} samples  {when}")
    return 0


def _capture(c: Client, camera: str, count: int) -> tuple[list[bytes], str]:
    cls = c.start_preview("" if camera == "auto" else camera)
    say(_("Using the %s camera.") % cls.upper())
    frames: list[bytes] = []
    last, pose = 0.0, 0
    say(_("Taking %d photos. %s...") % (count, POSES[0]))
    deadline = time.monotonic() + 90
    try:
        while len(frames) < count and time.monotonic() < deadline:
            jpeg, a = c.grab()
            problems = [HINTS.get(h, h) for h in a["hints"] if h in ("no-face", "multiple-faces", "too-small")]
            soft = [HINTS.get(h, h) for h in a["hints"] if h in ("too-dark", "too-bright", "blurry")]
            if problems:                      # blocking: no usable face in the picture
                say("  " + ", ".join(problems) + " " * 20, end="\r")
                time.sleep(0.2)
                continue
            if soft:                          # advice only: never prevents the capture
                say("  " + ", ".join(soft) + " " * 20, end="\r")
            if time.monotonic() - last < 1.2:
                time.sleep(0.1)
                continue
            frames.append(jpeg)
            last = time.monotonic()
            say(_("  photo %d/%d taken") % (len(frames), count) + " " * 30)
            if len(frames) < count:
                pose = (pose + 1) % len(POSES)
                say(f"  {POSES[pose]}...")
    finally:
        with contextlib.suppress(ClientError):
            c.stop_preview()
    return frames, cls


def _link(c: Client, user: str, label: str, frames: list[bytes], cls: str, source: str) -> int:
    say(_("Linking this face to the account '%s' (administrator approval required)...") % user)
    with polkit_text_agent():
        face = c.add_face(user, label, frames, cls, source)
    say(_("Done: face '%s' (%s) is now linked to %s.") % (face["label"], face["id"], user))
    say(_("You can now sign in with your face; the password always remains available."))
    return 0


def cmd_add(args, c: Client) -> int:
    user = args.user or default_user()
    frames, cls = _capture(c, args.camera, args.photos)
    if len(frames) < 3:
        say(_("Not enough good photos were captured."), file=sys.stderr)
        return 1
    return _link(c, user, args.label or _("Face"), frames, cls, "camera")


def cmd_import(args, c: Client) -> int:
    user = args.user or default_user()
    images = []
    for p in args.photos:
        try:
            images.append(Path(p).read_bytes())
        except OSError as exc:
            say(f"{p}: {exc}", file=sys.stderr)
            return 1
    return _link(c, user, args.label or _("Face"), images, args.camera if args.camera != "auto" else "rgb", "import")


def cmd_remove(args, c: Client) -> int:
    c.remove_face(args.user or default_user(), args.id)
    say(_("Face removed."))
    return 0


def cmd_clear(args, c: Client) -> int:
    user = args.user or default_user()
    if not args.yes and sys.stdin.isatty() and input(_("Remove every face of %s? [y/N] ") % user).lower() not in ("y", "o"):
        return 1
    say(_("%d face(s) removed.") % c.clear(user))
    return 0


def cmd_toggle(enabled: bool):
    def run(args, c: Client) -> int:
        c.set_enabled(args.user or default_user(), enabled)
        say(_("Face authentication enabled for this account.") if enabled else _("Face authentication disabled for this account."))
        return 0
    return run


def challenge_text(seq: str) -> str:
    if seq == "rl":
        return _("Slowly turn your head to your right, then to your left, then look at the camera.")
    return _("Slowly turn your head to your left, then to your right, then look at the camera.")


def run_with_signals(c: Client, method: str, sig: str, args: tuple, handlers: dict, timeout_ms: int = 120000):
    """A D-Bus call whose progress signals are delivered while it runs (needs a main loop)."""
    from gi.repository import GLib
    loop, box = GLib.MainLoop(), {}
    subs = [c.subscribe(name, callback) for name, callback in handlers.items()]

    def done(out, err):
        box["out"], box["err"] = out, err
        loop.quit()

    c.call_async(method, sig, args, done, timeout_ms)
    loop.run()
    for sub in subs:
        c.conn.signal_unsubscribe(sub)
    if box["err"]:
        raise box["err"]
    return box["out"][0]


def run_test(c: Client, user: str, camera_class: str, on_progress) -> dict:
    return run_with_signals(c, "TestRecognition", "ss", (user, camera_class), {"RecognitionProgress": on_progress})


def cmd_test(args, c: Client) -> int:
    user = args.user or default_user()
    say(_("Look at the camera..."))

    def progress(phase: str, detail: str) -> None:
        if phase == "challenge":
            say(challenge_text(detail))

    r = run_test(c, user, "" if args.camera == "auto" else args.camera, progress)
    if r["ok"]:
        say(_("Recognised (%s camera, similarity %.2f, %.1fs).") % (r["camera_class"].upper(), r["score"], r["duration"]))
    else:
        say(_("Not recognised (%s).") % r["reason"])
    if args.liveness and r.get("head_turn"):
        say(_("Head-turn measurements: %s") % r["head_turn"])
    return 0 if r["ok"] else 1


def cmd_check_camera(args, c: Client) -> int:
    """Show the "infrared" camera a phone screen: a real infrared camera does not see it."""
    say(_("Infrared camera check: first look at the camera, with nothing in front of it..."))

    def progress(phase: str) -> None:
        if phase == "show-screen":
            say(_("Now hold a phone close to the lens, screen on, showing a bright white page, "
                  "for about 5 seconds."))

    with polkit_text_agent():
        r = run_with_signals(c, "VerifyInfrared", "", (), {"CameraCheckProgress": progress})
    what = r.get("camera", "")
    if r["verdict"] == "infrared":
        say(_("✔ %s does not see the phone screen: it is a real infrared camera.") % what)
        say(_("Services that require infrared accept it from now on."))
        return 0
    if r["verdict"] == "sees-visible-light":
        say(_("✘ %s saw the phone screen: it is not an infrared camera, a photograph shown on a phone "
              "would fool it.") % what)
        say(_("Services that require infrared will not accept it. Use another camera, or allow the "
              "colour webcam knowingly (docs/SECURITY.md)."))
        return 1
    reason = {"nothing-shown": _("Nothing seems to have been held in front of the camera."),
              "too-few-frames": _("The camera gave too few pictures.")}.get(r.get("reason", ""), _("The result is ambiguous."))
    say(_("? %s Try again, with the screen close to the lens and at full brightness.") % reason)
    return 2


def cmd_service(args, c: Client) -> int:
    cfg = c.config()
    if not args.name:
        for name, cls in sorted(cfg["services"].items()):
            mode = cfg["interaction"].get(name, cfg["interaction"]["default"])
            say(f"{name:<22} camera={cls:<4} interaction={mode}")
        return 0
    if not args.value:
        say(f"{args.name}: {cfg['services'].get(args.name, 'off')}")
        return 0
    with polkit_text_agent():
        c.set_config({f"services.{args.name}": args.value})
    say(_("Service %s: %s") % (args.name, args.value))
    return 0


def cmd_config(args, c: Client) -> int:
    cfg = c.config()
    if not args.key:
        for sec, vals in cfg.items():
            if sec in ("services", "interaction"):
                continue
            for k, v in vals.items():
                say(f"{sec}.{k} = {v}")
        return 0
    sec, _sep, key = args.key.partition(".")
    if args.value is None:
        say(str(cfg.get(sec, {}).get(key, "")))
        return 0
    value: object = args.value
    for conv in (int, float):
        try:
            value = conv(args.value)
            break
        except ValueError:
            continue
    if args.value.lower() in ("true", "false"):
        value = args.value.lower() == "true"
    with polkit_text_agent():
        c.set_config({args.key: value})
    say(f"{args.key} = {value}")
    return 0


def cmd_fetch_models(args) -> int:
    if os.geteuid() != 0:
        say(_("Run this command as root: sudo facial-auth fetch-models"), file=sys.stderr)
        return 1
    paths = Paths()
    try:
        if args.source:
            files = models.install_from(Path(args.source), paths)
        else:
            def progress(spec, done):
                say(f"  {spec.filename}: {done // 1024} KiB", end="\r")
            files = models.fetch_required(paths, progress=progress)
    except (RuntimeError, OSError) as exc:
        say(_("Download failed: %s") % exc, file=sys.stderr)
        return 1
    for f in files:
        say(_("installed %s") % f)
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "try-restart", "facial-authd.service"], check=False)
    return 0


PAM_MODULE_GLOBS = ("/usr/lib/*/security/pam_facial_auth.so", "/lib/*/security/pam_facial_auth.so",
                    "/usr/lib/security/pam_facial_auth.so")
_LOAD_PROBE = ("import ctypes, sys\n"
               "lib = ctypes.CDLL(sys.argv[1])\n"
               "lib.pam_sm_authenticate, lib.pam_sm_setcred\n")


def pam_module_problem(globs=PAM_MODULE_GLOBS) -> str | None:
    """Why the PAM module cannot be used, or None when it loads.

    The module is loaded in a throw-away process: a damaged file can kill whoever
    loads it (SIGBUS), which must never be the doctor itself - nor sudo.
    """
    import glob
    found = [p for pattern in globs for p in sorted(glob.glob(pattern))]
    if not found:
        return _("not installed")
    r = subprocess.run([sys.executable, "-c", _LOAD_PROBE, found[0]], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        return None
    if r.returncode < 0:
        return _("%s crashed the loader (signal %d)") % (found[0], -r.returncode)
    return _("%s cannot be loaded") % found[0]


def cmd_doctor(args) -> int:
    bad = 0

    def line(ok: bool | None, text: str, hint: str = "") -> None:
        nonlocal bad
        mark = {True: "✔", False: "✘", None: "!"}[ok]
        say(f" {mark} {text}" + (f"\n     → {hint}" if hint and ok is not True else ""))
        bad += ok is False

    say(f"facial-auth {VERSION}")
    try:
        import cv2
        line(True, f"OpenCV {cv2.__version__}")
        det, rec = models.required(cv2.__version__)
        st = models.status()
        line(st["ok"], _("Models (%s + %s) in %s") % (det.key, rec.key, st["directory"]),
             _("sudo facial-auth fetch-models   (offline: --from DIR)"))
    except ImportError:
        line(False, "OpenCV", "sudo apt install python3-opencv")
    sock = Paths().socket
    line(sock.exists(), _("PAM socket %s") % sock, _("sudo systemctl enable --now facial-authd.socket"))
    stack = Path("/etc/pam.d/common-auth")
    integrated = stack.exists() and "pam_facial_auth" in stack.read_text()
    problem = pam_module_problem()
    line(problem is None, _("PAM module loads") if problem is None else _("PAM module: %s") % problem,
         _("sudo apt install --reinstall facial-auth"))
    line(integrated, _("PAM stack integration (common-auth)"), _("sudo pam-auth-update --enable facial-auth"))
    if integrated and problem is not None:
        line(False, _("The damaged module is in the authentication stack"),
             _("sudo pam-auth-update --package --remove facial-auth   (password login is unaffected)"))
    line(Path("/usr/share/polkit-1/actions/io.github.neomars.FacialAuth1.policy").exists(), _("polkit policy installed"))
    try:
        c = Client()
        s = c.status()
        line(True, _("Daemon reachable (up %ds)") % s["uptime"])
        line(bool(s["camera"]), _("Camera: %s") % (f"{s['camera_name']} [{s['camera_class'].upper()}]" if s["camera"] else _("none")),
             _("Plug a camera, or check that the 'facial-auth' user is in the 'video' group"))
        if s["camera"] and s["camera_class"] == "rgb":
            line(None, _("Only a colour webcam: a photograph shown on a phone fools it, so by default no "
                         "service uses the face."),
                 _("An infrared camera is recommended (see docs/SECURITY.md)"))
        if s["camera"] and s["camera_class"] == "ir" and s["require_ir_check"]:
            check = s["camera_ir_check"]
            if check == "failed":
                line(False, _("This \"infrared\" camera sees a phone screen: a photograph on a phone would fool it"),
                     _("Use another camera, or set camera.require_ir_check = false knowingly"))
            else:
                line(check == "verified", _("Infrared camera verified"),
                     _("facial-auth check-camera   (until then, no service that needs infrared uses the face)"))
        line(s["models_ok"], _("Daemon sees the models"))
        enrolled = [u["name"] for u in c.users() if u["faces"]]
        line(bool(enrolled), _("Linked accounts: %s") % (", ".join(enrolled) or _("none")),
             _("facial-auth add --user NAME   (or open the 'Face Login' settings app)"))
    except ClientError as exc:
        line(False, _("Daemon reachable"), explain(exc))
    return 1 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="facial-auth", description=_("Face authentication for Ubuntu"))
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_, user=True):
        p = sub.add_parser(name, help=help_)
        if user:
            p.add_argument("-u", "--user", help=_("account (default: you)"))
        p.set_defaults(fn=fn)
        return p

    add("status", cmd_status, _("show the state of the service"), user=False)
    add("cameras", cmd_cameras, _("list detected cameras"), user=False)
    add("list", cmd_list, _("list linked faces"))
    p = add("add", cmd_add, _("take photos with the camera and link the face to an account"))
    p.add_argument("-l", "--label")
    p.add_argument("-c", "--camera", choices=("auto", "ir", "rgb"), default="auto")
    p.add_argument("-n", "--photos", type=int, default=5, choices=range(3, 13), metavar="3-12")
    p = add("import", cmd_import, _("link a face from photos (e.g. taken with the Camera app)"))
    p.add_argument("photos", nargs="+")
    p.add_argument("-l", "--label")
    p.add_argument("-c", "--camera", choices=("auto", "ir", "rgb"), default="auto")
    p = add("remove", cmd_remove, _("remove one face"))
    p.add_argument("id")
    p = add("clear", cmd_clear, _("remove every face of an account"))
    p.add_argument("-y", "--yes", action="store_true")
    add("enable", cmd_toggle(True), _("enable face authentication for an account"))
    add("disable", cmd_toggle(False), _("disable face authentication for an account"))
    add("check-camera", cmd_check_camera, _("check that the infrared camera does not see a phone screen"), user=False)
    p = add("test", cmd_test, _("check that the camera recognises you"))
    p.add_argument("-c", "--camera", choices=("auto", "ir", "rgb"), default="auto")
    p.add_argument("--liveness", action="store_true",
                   help=_("also print the head-turn measurements (to tune liveness.challenge_turn)"))
    p = add("service", cmd_service, _("show or set where the face may be used (sudo, gdm-password...)"), user=False)
    p.add_argument("name", nargs="?")
    p.add_argument("value", nargs="?", choices=("any", "ir", "off"))
    p = add("config", cmd_config, _("show or change a setting (e.g. recognition.threshold 0.5)"), user=False)
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    p = sub.add_parser("fetch-models", help=_("download the face models (root)"))
    p.add_argument("--from", dest="source", metavar="DIR", help=_("install from a directory (offline)"))
    p.set_defaults(fn=None, local=cmd_fetch_models)
    p = sub.add_parser("doctor", help=_("diagnose the installation"))
    p.set_defaults(fn=None, local=cmd_doctor)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if getattr(args, "local", None):
            return args.local(args)
        return args.fn(args, Client())
    except ClientError as exc:
        say(_("Error: %s") % explain(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
