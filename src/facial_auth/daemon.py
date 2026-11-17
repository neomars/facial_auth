# SPDX-License-Identifier: MIT
"""facial-authd: the long-running (socket/D-Bus activated) daemon."""
from __future__ import annotations

import argparse
import logging
import os
import pwd
import signal
import socket
import sys
import threading
from pathlib import Path

# Untrusted images are decoded by OpenCV: cap the decoded size (default 1 Gpixel).
os.environ.setdefault("OPENCV_IO_MAX_IMAGE_PIXELS", str(32 * 1024 * 1024))

from .const import SERVICE_USER, VERSION, Paths  # noqa: E402

log = logging.getLogger("facial-authd")
SD_LISTEN_FDS_START = 3


def systemd_listener() -> socket.socket | None:
    """The socket passed by facial-authd.socket (socket activation), if any."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    if int(os.environ.get("LISTEN_FDS", "0")) < 1:
        return None
    for var in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(var, None)
    return socket.socket(fileno=SD_LISTEN_FDS_START)


def own_listener(path: Path) -> socket.socket:
    """Bind the socket ourselves (development, or started without systemd)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, 0o666)
    sock.listen(16)
    return sock


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="facial-authd", description=__doc__)
    ap.add_argument("--version", action="version", version=VERSION)
    ap.add_argument("--debug", action="store_true", help="verbose logging")
    ap.add_argument("--bus", choices=("system", "session"), default="system")
    ap.add_argument("--dev", action="store_true",
                    help="development mode: honours --root/--fake-camera, never use in production")
    ap.add_argument("--root", help="(dev) filesystem root for config/state/models")
    ap.add_argument("--socket", help="(dev) PAM socket path")
    ap.add_argument("--fake-camera", metavar="DIR", help="(dev) play the images of DIR instead of a camera")
    ap.add_argument("--no-polkit", action="store_true", help="(dev) authorise every D-Bus call")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    if (args.root or args.fake_camera or args.socket or args.no_polkit) and not args.dev:
        log.error("--root/--socket/--fake-camera/--no-polkit are development options: add --dev")
        return 2

    from gi.repository import GLib, Gio

    from .core import Core
    from .dbus_service import DBusService
    from .server import PamServer

    paths = Paths(Path(args.root)) if args.root else Paths()
    owner = None
    if os.geteuid() == 0 and not args.dev:
        log.warning("running as root: prefer the unprivileged %s user", SERVICE_USER)
    try:
        if os.geteuid() == 0 and args.dev:
            pw = pwd.getpwnam(SERVICE_USER)
            owner = (pw.pw_uid, pw.pw_gid)
    except KeyError:
        pass

    camera_factory = None
    if args.fake_camera:
        camera_factory = _folder_camera(Path(args.fake_camera))
    from .system import LogindProbe
    core = Core(paths=paths, camera_factory=camera_factory, owner=owner,
                session_probe=LogindProbe() if not args.dev else None)
    logging.getLogger().setLevel(logging.DEBUG if args.debug else
                                 getattr(logging, core.cfg["core", "log_level"].upper()))
    for w in core.cfg.warnings:
        log.warning("configuration: %s", w)
    try:
        core.store.sync_markers()
    except OSError as exc:
        log.warning("cannot refresh enrollment markers: %s", exc)

    # PAM socket --------------------------------------------------------
    listener = systemd_listener() or own_listener(Path(args.socket) if args.socket else paths.socket)
    pam = PamServer(core, listener)
    threading.Thread(target=pam.serve_forever, name="pam-server", daemon=True).start()

    # D-Bus + main loop -----------------------------------------------
    loop = GLib.MainLoop()
    authorizer = _AllowAll() if args.no_polkit else None
    service = DBusService(core, Gio.BusType.SYSTEM if args.bus == "system" else Gio.BusType.SESSION,
                          authorizer, on_lost=loop.quit)
    service.start()

    def idle_check() -> bool:
        if core.idle_for() > core.cfg["core", "idle_timeout"]:
            log.info("idle for %.0fs: exiting (socket/D-Bus activation restarts me)", core.idle_for())
            loop.quit()
            return False
        service.reap_previews()
        return True

    GLib.timeout_add_seconds(5, idle_check)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, lambda: loop.quit() or False)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, lambda: loop.quit() or False)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGHUP, lambda: (core.reload(), log.info("configuration reloaded"), True)[-1])
    log.info("facial-authd %s ready (bus=%s)", VERSION, args.bus)
    try:
        loop.run()
    finally:
        service.stop_preview(force=True)
        pam.stop()
    return 0


class _AllowAll:
    def check(self, sender: str, action: str) -> bool:
        return True


def _folder_camera(folder: Path):
    """(dev) a camera that plays the image files of a folder in a loop."""
    import cv2

    from .camera import FakeCamera

    def factory(info, camera_class):
        files = sorted(p for p in folder.iterdir() if p.suffix.lower() in (".jpg", ".jpeg", ".png"))
        frames = [cv2.imread(str(f)) for f in files]
        return FakeCamera([f for f in frames if f is not None], camera_class, fps=15)
    return factory


if __name__ == "__main__":
    sys.exit(main())
