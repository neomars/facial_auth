# SPDX-License-Identifier: MIT
"""Enrollment wizard: capture (camera preview or imported photos) -> link."""
from __future__ import annotations

import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Adw, Gdk, GdkPixbuf, Gio, GLib, Gtk  # noqa: E402

from ..cli import HINTS, POSES  # noqa: E402
from ..client import ClientError  # noqa: E402
from ..i18n import _  # noqa: E402

MIN_PHOTOS, MAX_PHOTOS = 3, 12
GUIDED_PHOTOS = 5
PREVIEW_PERIOD_MS = 120
GUIDED_PERIOD_S = 1.3
BLOCKING = ("no-face", "multiple-faces", "too-small")
CAMERA_APP_FOLDERS = ("Camera", "Caméra", "Webcam", "Cheese")


def pictures_folder() -> Gio.File:
    """Where the Camera app saves its photos (Snapshot: Camera, Cheese: Webcam)."""
    base = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_PICTURES) or os.path.expanduser("~")
    for sub in CAMERA_APP_FOLDERS:
        if os.path.isdir(os.path.join(base, sub)):
            return Gio.File.new_for_path(os.path.join(base, sub))
    return Gio.File.new_for_path(base)


def downscale_jpeg(path: str, max_side: int = 1280) -> bytes:
    pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(path, max_side, max_side, True)
    pb = pb.apply_embedded_orientation() or pb
    ok, data = pb.save_to_bufferv("jpeg", ["quality"], ["90"])
    if not ok:
        raise ValueError("cannot convert the image")
    return bytes(data)


class EnrollPage(Adw.NavigationPage):
    def __init__(self, window, user: str) -> None:
        super().__init__(title=_("Add a face"), tag="enroll")
        self.win, self.client, self.user = window, window.client, user
        self._ir_offered = False
        self.photos: list[tuple[bytes, Gdk.Texture]] = []
        self.kind: tuple[str, str] | None = None        # (camera_class, source) of the photos taken
        self.camera_class = ""
        self._preview_on = False
        self._inflight = False
        self._last: tuple[bytes, dict] | None = None
        self._texture: Gdk.Texture | None = None
        self._guided = False
        self._guided_last = 0.0
        self._users: list[dict] = []

        self.next_btn = Gtk.Button(label=_("Continue"), css_classes=["suggested-action"], sensitive=False)
        self.next_btn.connect("clicked", lambda *_a: self.go_link())
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.stack.add_named(self._build_capture(), "capture")
        self.stack.add_named(self._build_link(), "link")
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.pack_end(self.next_btn)
        view.add_top_bar(header)
        view.set_content(self.stack)
        self.set_child(view)
        self.connect("shown", lambda *_a: self.start_preview())
        self.connect("hidden", lambda *_a: self.stop_preview())

    # ------------------------------------------------------------- capture
    def _build_capture(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                      margin_start=16, margin_end=16)
        self.vstack = Adw.ViewStack()
        self.vstack.add_titled_with_icon(self._build_camera(), "camera", _("Camera"), "camera-web-symbolic")
        self.vstack.add_titled_with_icon(self._build_import(), "import", _("Import photos"), "folder-pictures-symbolic")
        self.vstack.connect("notify::visible-child-name", self._on_tab)
        switcher = Adw.ViewSwitcher(stack=self.vstack, policy=Adw.ViewSwitcherPolicy.WIDE, halign=Gtk.Align.CENTER)
        box.append(switcher)
        self.vstack.set_vexpand(True)
        box.append(self.vstack)

        self.thumbs = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=12,
                                  min_children_per_line=1, homogeneous=False, column_spacing=6, row_spacing=6,
                                  halign=Gtk.Align.START)
        scroll = Gtk.ScrolledWindow(child=self.thumbs, min_content_height=84, vscrollbar_policy=Gtk.PolicyType.NEVER)
        box.append(scroll)
        self.counter = Gtk.Label(css_classes=["dim-label"])
        box.append(self.counter)
        self._refresh_photos()
        return box

    def _build_camera(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.picture = Gtk.Picture(content_fit=Gtk.ContentFit.CONTAIN, can_shrink=True, hexpand=True, vexpand=True,
                                   css_classes=["card"])
        self.picture.set_size_request(320, 240)
        self.area = Gtk.DrawingArea(can_target=False)
        self.area.set_draw_func(self._draw_box)
        overlay = Gtk.Overlay(child=self.picture)
        overlay.add_overlay(self.area)
        box.append(overlay)
        self.guidance = Gtk.Label(label=_("Starting the camera..."), css_classes=["title-4"], wrap=True)
        box.append(self.guidance)
        self.hint = Gtk.Label(css_classes=["dim-label"], wrap=True)
        box.append(self.hint)
        row = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        self.shutter = Gtk.Button(label=_("Take photo"), css_classes=["suggested-action", "pill"], sensitive=False)
        self.shutter.connect("clicked", lambda *_a: self.take_photo())
        self.guided_btn = Gtk.Button(label=_("Guided capture"), css_classes=["pill"], sensitive=False)
        self.guided_btn.connect("clicked", lambda *_a: self.start_guided())
        row.append(self.shutter)
        row.append(self.guided_btn)
        box.append(row)
        self.cam_error = Adw.StatusPage(icon_name="camera-disabled-symbolic", title=_("No camera available"),
                                        visible=False, vexpand=True)
        box.append(self.cam_error)
        return box

    def _build_import(self) -> Gtk.Widget:
        page = Adw.StatusPage(
            icon_name="folder-pictures-symbolic", title=_("Use photos from the Camera app"),
            description=_("Take at least %d photos of your face with the Camera app (front view, slightly left, "
                          "slightly right), then choose them here.") % MIN_PHOTOS)
        btn = Gtk.Button(label=_("Choose photos..."), css_classes=["suggested-action", "pill"], halign=Gtk.Align.CENTER)
        btn.connect("clicked", lambda *_a: self.choose_photos())
        page.set_child(btn)
        return page

    # ---------------------------------------------------------- preview
    def start_preview(self) -> None:
        if self._preview_on or self.stack.get_visible_child_name() != "capture":
            return
        self.guidance.set_label(_("Starting the camera..."))
        self.client.call_async("StartPreview", "s", ("",), self._on_preview_started, 20000)

    def _on_preview_started(self, out, err) -> None:
        if err:
            self.cam_error.set_description(self._explain(err))
            self.cam_error.set_visible(True)
            self.picture.set_visible(False)
            self.guidance.set_label(_("The camera could not be started"))
            return
        self.cam_error.set_visible(False)
        self.picture.set_visible(True)
        self.camera_class = out[0]
        self._preview_on = True
        GLib.timeout_add(PREVIEW_PERIOD_MS, self._tick)
        status = getattr(self.win, "status", None) or {}
        if (self.camera_class == "ir" and status.get("require_ir_check", True)
                and status.get("camera_ir_check") not in ("verified", "n/a") and not self._ir_offered):
            self._ir_offered = True
            self._offer_ir_check()

    def _offer_ir_check(self) -> None:
        """An "infrared" camera is only a guess from its pixel formats: before a face is enrolled with
        it, check that it does not see a phone screen (otherwise a photo on a phone would unlock)."""
        dlg = Adw.AlertDialog(
            heading=_("Verify the infrared camera"),
            body=_("This camera looks like an infrared one, but only an infrared camera ignores a phone "
                   "screen. Until it is verified, services that need infrared will not use your face. "
                   "You will need a phone showing a bright white page, held close to the lens for a "
                   "few seconds."))
        dlg.add_response("later", _("Later"))
        dlg.add_response("verify", _("Verify now"))
        dlg.set_response_appearance("verify", Adw.ResponseAppearance.SUGGESTED)
        dlg.connect("response", lambda _d, response: self._ir_check_chosen(response))
        dlg.present(self.win)

    def _ir_check_chosen(self, response: str) -> None:
        if response != "verify":
            return
        self.stop_preview()                       # the check needs the camera for itself
        self.win._verify_infrared()
        GLib.timeout_add(9000, self._restart_preview_later)

    def _restart_preview_later(self) -> bool:
        self.start_preview()
        return False

    def stop_preview(self) -> None:
        was = self._preview_on
        self._preview_on = False
        self._guided = False
        if was and self.client:
            self.client.call_async("StopPreview", "", (), lambda *_a: None, 5000)

    def _tick(self) -> bool:
        if not self._preview_on:
            return False
        if not self._inflight:
            self._inflight = True
            self.client.call_async("GrabFrame", "", (), self._on_frame, 8000)
        return True

    def _on_frame(self, out, err) -> None:
        self._inflight = False
        if err or not self._preview_on:
            if err and err.code in ("no-preview", "camera-error"):
                self._preview_on = False
                self.guidance.set_label(self._explain(err))
            return
        jpeg, analysis = bytes(out[0]), out[1]
        try:
            self._texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(jpeg))
        except GLib.Error:
            return
        self.picture.set_paintable(self._texture)
        self._last = (jpeg, analysis)
        self.area.queue_draw()
        blocking = [HINTS.get(h, h) for h in analysis["hints"] if h in BLOCKING]
        advice = [HINTS.get(h, h) for h in analysis["hints"] if h not in BLOCKING]
        usable = analysis["ok"] and analysis["faces"] == 1
        self.shutter.set_sensitive(usable and len(self.photos) < MAX_PHOTOS)
        self.guided_btn.set_sensitive(len(self.photos) < MAX_PHOTOS and not self._guided)
        if self._guided:
            idx = min(len(self.photos), len(POSES) - 1)
            self.guidance.set_label(POSES[idx])
        else:
            self.guidance.set_label(_("Position your face in the frame") if blocking else _("Ready"))
        self.hint.set_label(", ".join(blocking + advice))
        if self._guided and usable:
            now = GLib.get_monotonic_time() / 1e6
            if now - self._guided_last >= GUIDED_PERIOD_S:
                self._guided_last = now
                self.take_photo()
                if len(self.photos) >= GUIDED_PHOTOS:
                    self._guided = False

    def _draw_box(self, _area, cr, w, h) -> None:
        if not self._texture or not self._last:
            return
        box = self._last[1]["box"]
        if len(box) != 4:
            return
        tw, th = self._texture.get_width(), self._texture.get_height()
        scale = min(w / tw, h / th)
        ox, oy = (w - tw * scale) / 2, (h - th * scale) / 2
        ok = self._last[1]["ok"]
        cr.set_source_rgba(0.2, 0.8, 0.4, 0.95) if ok else cr.set_source_rgba(0.95, 0.6, 0.1, 0.95)
        cr.set_line_width(3)
        cr.rectangle(ox + box[0] * scale, oy + box[1] * scale, box[2] * scale, box[3] * scale)
        cr.stroke()

    # ------------------------------------------------------------ photos
    def _on_tab(self, *_a) -> None:
        if self.vstack.get_visible_child_name() == "camera":
            self.start_preview()
        else:
            self.stop_preview()

    def take_photo(self) -> None:
        if not self._last or len(self.photos) >= MAX_PHOTOS:
            return
        if not self._accept_kind((self.camera_class or "rgb", "camera")):
            return
        jpeg = self._last[0]
        self.photos.append((jpeg, Gdk.Texture.new_from_bytes(GLib.Bytes.new(jpeg))))
        self._refresh_photos()

    def start_guided(self) -> None:
        self._guided = True
        self._guided_last = 0.0
        self.guided_btn.set_sensitive(False)

    def _accept_kind(self, kind: tuple[str, str]) -> bool:
        """One face = one camera and one source (colour/infrared must not be mixed)."""
        if self.kind and self.kind != kind:
            self.win.toast(_("Remove the current photos before using another source"))
            return False
        self.kind = kind
        return True

    def _refresh_photos(self) -> None:
        child = self.thumbs.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.thumbs.remove(child)
            child = nxt
        for i, (_jpeg, tex) in enumerate(self.photos):
            ov = Gtk.Overlay(child=Gtk.Picture(paintable=tex, content_fit=Gtk.ContentFit.COVER, css_classes=["card"]))
            ov.set_size_request(72, 72)
            ov.set_halign(Gtk.Align.START)
            ov.set_hexpand(False)
            rm = Gtk.Button(icon_name="window-close-symbolic", css_classes=["circular", "osd"],
                            halign=Gtk.Align.END, valign=Gtk.Align.START, tooltip_text=_("Remove"))
            rm.connect("clicked", lambda *_a, idx=i: self._remove_photo(idx))
            ov.add_overlay(rm)
            self.thumbs.append(ov)
        n = len(self.photos)
        self.counter.set_label(_("%d photo(s): at least %d are needed") % (n, MIN_PHOTOS) if n < MIN_PHOTOS
                               else _("%d photo(s): ready") % n)
        self.next_btn.set_sensitive(n >= MIN_PHOTOS)

    def _remove_photo(self, idx: int) -> None:
        del self.photos[idx]
        if not self.photos:
            self.kind = None
        self._refresh_photos()

    # ------------------------------------------------------------ import
    def choose_photos(self) -> None:
        dialog = Gtk.FileDialog(title=_("Choose photos of your face"), modal=True)
        flt = Gtk.FileFilter(name=_("Images"))
        flt.add_mime_type("image/jpeg")
        flt.add_mime_type("image/png")
        store = Gio.ListStore.new(Gtk.FileFilter)
        store.append(flt)
        dialog.set_filters(store)
        dialog.set_initial_folder(pictures_folder())
        dialog.open_multiple(self.win, None, self._on_files)

    def _on_files(self, dialog, result) -> None:
        try:
            files = dialog.open_multiple_finish(result)
        except GLib.Error:
            return                               # cancelled
        for i in range(files.get_n_items()):
            if len(self.photos) >= MAX_PHOTOS:
                break
            path = files.get_item(i).get_path()
            self._import_one(path)

    def _import_one(self, path: str) -> None:
        if not self._accept_kind(("rgb", "import")):
            return
        try:
            jpeg = downscale_jpeg(path)
        except (GLib.Error, ValueError) as exc:
            self.win.toast(_("%s: cannot read this image") % os.path.basename(path))
            return

        def analysed(out, err):
            if err:
                self.win.toast(self._explain(err))
                return
            a = out[0]
            if a["faces"] != 1 or not a["ok"]:
                why = ", ".join(HINTS.get(h, h) for h in a["hints"] if h in BLOCKING) or _("no usable face")
                self.win.toast(f"{os.path.basename(path)}: {why}")
                if not self.photos:
                    self.kind = None
                return
            self.photos.append((jpeg, Gdk.Texture.new_from_bytes(GLib.Bytes.new(jpeg))))
            self._refresh_photos()
        self.client.call_async("AnalyzeImage", "ay", (jpeg,), analysed, 30000)

    # ----------------------------------------------------------------- link
    def _build_link(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(
            title=_("Link this face to an account"),
            description=_("Only an administrator can link a face to an account. You will be asked for "
                          "an administrator's password."))
        self.account_row = Adw.ComboRow(title=_("Account"))
        self.label_row = Adw.EntryRow(title=_("Name of this face"), text=_("My face"))
        self.summary = Adw.ActionRow(title=_("Photos"))
        g.add(self.account_row)
        g.add(self.label_row)
        g.add(self.summary)
        page.add(g)
        g2 = Adw.PreferencesGroup()
        self.link_btn = Gtk.Button(label=_("Link this face to the account"),
                                   css_classes=["suggested-action", "pill"], halign=Gtk.Align.CENTER)
        self.link_btn.connect("clicked", lambda *_a: self.link())
        self.spinner = Gtk.Spinner()
        row = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        row.append(self.link_btn)
        row.append(self.spinner)
        g2.add(row)
        page.add(g2)
        return page

    def go_link(self) -> None:
        self.stop_preview()
        self.client.call_async("ListUsers", "", (), self._fill_accounts, 10000)

    def _fill_accounts(self, out, err) -> None:
        if err:
            self.win.toast(self._explain(err))
            return
        self._users = out[0]
        model = Gtk.StringList.new([f"{u['realname']} ({u['name']})" for u in self._users])
        self.account_row.set_model(model)
        names = [u["name"] for u in self._users]
        self.account_row.set_selected(names.index(self.user) if self.user in names else 0)
        cls, src = self.kind or ("rgb", "import")
        kind = _("infrared camera") if cls == "ir" else _("colour camera")
        self.summary.set_subtitle(_("%d photos from the %s") % (len(self.photos), kind))
        self.stack.set_visible_child_name("link")
        self.next_btn.set_visible(False)

    def link(self) -> None:
        if not self._users:
            return
        user = self._users[self.account_row.get_selected()]["name"]
        label = self.label_row.get_text().strip() or _("My face")
        cls, src = self.kind or ("rgb", "import")
        self.link_btn.set_sensitive(False)
        self.spinner.start()

        def done(out, err):
            self.spinner.stop()
            self.link_btn.set_sensitive(True)
            if err:
                heading = _("Authentication required") if err.code == "access-denied" else _("Could not link the face")
                self.win.alert(heading, self._explain(err))
                return
            self.win.toast(_("The face is now linked to %s") % user)
            self.win.nav.pop_to_tag("main")
            self.win.reload()
        self.client.call_async("AddFace", "ssaayss", (user, label, [p[0] for p in self.photos], cls, src),
                               done, 600000)

    @staticmethod
    def _explain(err: ClientError) -> str:
        from .app import format_error
        return format_error(err)
