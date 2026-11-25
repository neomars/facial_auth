# SPDX-License-Identifier: MIT
"""Face Login settings: GTK 4 + libadwaita application."""
from __future__ import annotations

import sys
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from ..client import Client, ClientError  # noqa: E402
from ..const import VERSION  # noqa: E402
from ..i18n import _  # noqa: E402
from .enroll import EnrollPage  # noqa: E402

APP_ID = "io.github.neomars.FacialAuth"

# PAM service -> (label, subtitle)
SERVICES = [
    ("gdm-password", _("Login screen and lock screen"), _("Sign in and unlock your session")),
    ("login", _("Text console login"), _("Login on a virtual terminal (Ctrl+Alt+F3)")),
    ("sudo", _("Terminal commands (sudo)"), _("Run commands as administrator")),
    ("su", _("Switch user (su)"), _("Become another user in a terminal")),
    ("polkit-1", _("Administrator prompts"), _("Installing software, changing system settings...")),
]
# Short labels: a closed drop-down ellipsizes its value (the group's description says why "any" is less safe).
CAMERA_CHOICES = [("any", _("Any camera (less safe)")),
                  ("ir", _("Verified infrared only")), ("off", _("Password only"))]
SECURITY_LEVELS = [(0.45, _("Standard")), (0.55, _("Strict (fewer false accepts, more retries)"))]
# A directory can hold thousands of accounts: the window shows the ones that matter (yours, the ones
# that have faces), then others up to this number.  The account chooser of the enrolment page lists
# all of them, with a search field, and any other account can be typed there.
MAX_ACCOUNT_ROWS = 100


def format_error(err: ClientError) -> str:
    from ..cli import explain
    return explain(err)


class Window(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application, client: Client | None = None) -> None:
        super().__init__(application=app, title=_("Face Login"), default_width=760, default_height=720)
        self.client: Client | None = client
        self.status: dict = {}
        self.config: dict = {}
        self._rows: list[Gtk.Widget] = []
        self._more_row: Gtk.Widget | None = None
        self._building = False

        self.toasts = Adw.ToastOverlay()
        self.nav = Adw.NavigationView()
        self.toasts.set_child(self.nav)
        self.set_content(self.toasts)

        self.banner = Adw.Banner(revealed=False, button_label=None)
        self.page = Adw.PreferencesPage()
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Refresh"))
        refresh.connect("clicked", lambda *_a: self.reload())
        header.pack_end(refresh)
        view.add_top_bar(header)
        view.add_top_bar(self.banner)
        view.set_content(self.page)
        self.main_page = Adw.NavigationPage(title=_("Face Login"), child=view, tag="main")
        self.nav.add(self.main_page)

        self.camera_row = Adw.ActionRow(title=_("Camera"), subtitle=_("Looking for a camera..."))
        self.camera_row.add_prefix(Gtk.Image.new_from_icon_name("camera-web-symbolic"))
        self.verify_btn = Gtk.Button(label=_("Verify"), valign=Gtk.Align.CENTER, visible=False)
        self.verify_btn.set_tooltip_text(_("Show the camera a phone screen: an infrared camera does not see it"))
        self.verify_btn.connect("clicked", lambda *_a: self._verify_infrared())
        self.camera_row.add_suffix(self.verify_btn)
        self.master = Adw.SwitchRow(title=_("Sign in with my face"),
                                    subtitle=_("The password always remains available"))
        self.master.connect("notify::active", self._on_master)
        g = Adw.PreferencesGroup(title=_("Camera"))
        g.add(self.camera_row)
        g.add(self.master)
        self.page.add(g)

        self.accounts = Adw.PreferencesGroup(
            title=_("Accounts"),
            description=_("Linking a face to an account requires an administrator's password."))
        self.page.add(self.accounts)

        self.where = Adw.PreferencesGroup(
            title=_("Where can the face be used?"),
            description=_("A colour webcam is fooled by a photograph shown on a phone: by default every "
                          "service needs a verified infrared camera. Allowing any camera is your call."))
        self.page.add(self.where)
        self.service_rows: dict[str, Adw.ComboRow] = {}
        for name, title, sub in SERVICES:
            row = Adw.ComboRow(title=title, subtitle=sub, model=Gtk.StringList.new([c[1] for c in CAMERA_CHOICES]))
            row.connect("notify::selected", self._on_service, name)
            self.where.add(row)
            self.service_rows[name] = row

        self.advanced = Adw.PreferencesGroup(title=_("Security level"))
        self.level = Adw.ComboRow(title=_("Recognition strictness"),
                                  model=Gtk.StringList.new([s[1] for s in SECURITY_LEVELS]))
        self.level.connect("notify::selected", self._on_level)
        self.advanced.add(self.level)
        self.page.add(self.advanced)

        if client is None:
            GLib.idle_add(self._connect)
        else:
            GLib.idle_add(self.reload)

    # ---------------------------------------------------------- connection
    def _connect(self) -> bool:
        try:
            self.client = Client()
            self.client.subscribe("FacesChanged", lambda *_a: self.reload())
            self.client.subscribe("ConfigChanged", lambda *_a: self.reload())
        except ClientError as exc:
            self._show_banner(format_error(exc))
            return False
        self.reload()
        return False

    def _show_banner(self, text: str) -> None:
        self.banner.set_title(text)
        self.banner.set_revealed(bool(text))

    def toast(self, text: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=text, timeout=4))

    def alert(self, heading: str, body: str) -> None:
        dlg = Adw.AlertDialog(heading=heading, body=body)
        dlg.add_response("ok", _("OK"))
        dlg.present(self)

    # -------------------------------------------------------------- refresh
    def reload(self) -> bool:
        if self.client is None:
            return False
        self.client.call_async("GetStatus", "", (), self._on_status, 10000)
        return False

    def _on_status(self, out, err) -> None:
        if err:
            self._show_banner(format_error(err))
            return
        self.status = out[0]
        s = self.status
        notes = []
        if not s["models_ok"]:
            notes.append(_("Face models are missing: run 'sudo facial-auth fetch-models'."))
        if not s["camera"]:
            notes.append(_("No usable camera was found."))
        self._show_banner(" ".join(notes))
        self._building = True
        if s["camera"]:
            self.camera_row.set_title(s["camera_name"] or _("Camera"))
            check = s.get("camera_ir_check", "n/a")
            if s["camera_class"] != "ir":
                kind = _("Colour webcam: a photograph shown on a phone fools it")
            elif not s.get("require_ir_check", True) or check == "verified":
                kind = _("Infrared camera: robust against photographs")
            elif check == "failed":
                kind = _("This \"infrared\" camera sees a phone screen: a photograph would fool it")
            else:
                kind = _("Infrared camera not verified yet: face login waits for the check")
            self.camera_row.set_subtitle(kind)
            self.verify_btn.set_visible(s["camera_class"] == "ir" and s.get("require_ir_check", True)
                                        and check != "verified")
        else:
            self.camera_row.set_title(_("No camera"))
            self.camera_row.set_subtitle(_("Plug in a webcam or check the 'video' group"))
        self.master.set_active(bool(s["enabled"]))
        self._building = False
        self.client.call_async("GetConfig", "", (), self._on_config, 10000)
        self.client.call_async("ListUsers", "", (), self._on_users, 10000)

    def _on_config(self, out, err) -> None:
        if err:
            return
        import json
        self.config = json.loads(out[0])
        self._building = True
        order = [c[0] for c in CAMERA_CHOICES]
        for name, row in self.service_rows.items():
            row.set_selected(order.index(self.config["services"].get(name, "off")))
        thr = self.config["recognition"]["threshold"]
        self.level.set_selected(0 if thr < 0.5 else 1)
        self._building = False

    def _on_users(self, out, err) -> None:
        if err:
            return
        for row in self._rows:
            self.accounts.remove(row)
        self._rows.clear()
        if self._more_row is not None:
            self.accounts.remove(self._more_row)
            self._more_row = None
        me = GLib.get_user_name()
        # you first, then the accounts that have faces, then the others by name
        users = sorted(out[0], key=lambda u: (u["name"] != me, not u["faces"], u["name"].casefold()))
        for u in users[:MAX_ACCOUNT_ROWS]:
            row = self._account_row(u, u["name"] == me)
            self.accounts.add(row)
            self._rows.append(row)
            # The faces of an account are fetched when its row is opened: for somebody else's account
            # that is an administrator's request (polkit asks for a password), which must not happen
            # for every account of the machine as soon as the window opens.
            if u["faces"] and u["name"] == me:
                self._load_faces(u["name"])
        hidden = len(users) - MAX_ACCOUNT_ROWS
        note = (_("%d more accounts are not shown. ") % hidden) if hidden > 0 else ""
        self._more_row = Adw.ActionRow(
            title=_("Another account?"), css_classes=["dim-label"],
            subtitle=note + _("Add a face, then choose the account in the next step: the list there can be "
                              "searched, and the login of an account that is not listed can be typed."))
        self.accounts.add(self._more_row)

    def _load_faces(self, name: str) -> None:
        row = next((r for r in self._rows if r._user["name"] == name), None)
        if row is None or row._faces_state != "idle":
            return
        row._faces_state = "loading"
        self.client.call_async("ListFaces", "s", (name,), lambda o, e: self._on_faces(name, o, e), 600000)

    def _on_row_expanded(self, row, _pspec) -> None:
        if row.get_expanded() and row._user["faces"]:
            self._load_faces(row._user["name"])

    def _account_row(self, u: dict, mine: bool) -> Adw.ExpanderRow:
        row = Adw.ExpanderRow(title=u["realname"] + (_(" (you)") if mine else ""))
        row.set_subtitle(self._summary(u))
        avatar = Adw.Avatar(size=36, text=u["realname"], show_initials=True)
        row.add_prefix(avatar)
        add = Gtk.Button(label=_("Add a face"), valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        add.connect("clicked", lambda *_a, name=u["name"]: self.open_enrollment(name))
        row.add_suffix(add)
        row._user = u
        row._face_rows = []
        row._faces_state = "idle"          # idle -> loading -> loaded (back to idle when refused)
        row.connect("notify::expanded", self._on_row_expanded)
        return row

    @staticmethod
    def _summary(u: dict) -> str:
        if not u["faces"]:
            return f"{u['name']} — " + _("no face linked")
        lock = _(" — locked for %d s") % u["locked_out"] if u["locked_out"] else ""
        return f"{u['name']} — " + (_("%d face(s)") % u["faces"]) + ("" if u["enabled"] else _(" (disabled)")) + lock

    def _on_faces(self, name: str, out, err) -> None:
        row = next((r for r in self._rows if r._user["name"] == name), None)
        if row is None:
            return
        if err:
            row._faces_state = "idle"
            row.set_expanded(False)
            self.toast(format_error(err))
            return
        row._faces_state = "loaded"
        for r in row._face_rows:
            row.remove(r)
        row._face_rows.clear()
        faces = out[0]
        for f in faces:
            fr = Adw.ActionRow(title=f["label"], subtitle="%s — %s — %s" % (
                _("Infrared") if f["camera_class"] == "ir" else _("Colour camera"),
                _("%d photos") % f["samples"], time.strftime("%x", time.localtime(f["created"]))))
            rm = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"],
                            tooltip_text=_("Remove this face"))
            rm.connect("clicked", lambda *_a, n=name, fid=f["id"]: self._remove(n, fid))
            fr.add_suffix(rm)
            row.add_row(fr)
            row._face_rows.append(fr)
        if faces:
            ctl = Adw.ActionRow(title=_("Use the face for this account"))
            sw = Gtk.Switch(valign=Gtk.Align.CENTER, active=row._user["enabled"])
            sw.connect("notify::active", lambda s, *_a, n=name: self._set_enabled(n, s.get_active()))
            ctl.add_suffix(sw)
            test = Gtk.Button(label=_("Test"), valign=Gtk.Align.CENTER)
            test.connect("clicked", lambda *_a, n=name: self._test(n))
            ctl.add_suffix(test)
            row.add_row(ctl)
            row._face_rows.append(ctl)

    # -------------------------------------------------------------- actions
    def _guarded(self, out, err, ok_text: str = "") -> bool:
        if err:
            if err.code != "access-denied" or True:
                self.toast(format_error(err))
            return False
        if ok_text:
            self.toast(ok_text)
        return True

    def _remove(self, user: str, face_id: str) -> None:
        dlg = Adw.AlertDialog(heading=_("Remove this face?"),
                              body=_("You will no longer be able to sign in with it."))
        dlg.add_response("cancel", _("Cancel"))
        dlg.add_response("remove", _("Remove"))
        dlg.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)

        def answered(d, res):
            if d.choose_finish(res) == "remove":
                self.client.call_async("RemoveFace", "ss", (user, face_id),
                                       lambda o, e: self._guarded(o, e, _("Face removed")) and self.reload())
        dlg.choose(self, None, answered)

    def _set_enabled(self, user: str, enabled: bool) -> None:
        self.client.call_async("SetUserEnabled", "sb", (user, enabled), lambda o, e: self._guarded(o, e))

    def _verify_infrared(self) -> None:
        self.verify_btn.set_sensitive(False)
        self.toast(_("Infrared camera check: first look at the camera, with nothing in front of it..."))
        sub = self.client.subscribe(
            "CameraCheckProgress",
            lambda phase: self.toast(_("Now hold a phone close to the lens, screen on, showing a bright "
                                       "white page, for about 5 seconds.")) if phase == "show-screen" else None)

        def done(out, err):
            self.client.conn.signal_unsubscribe(sub)
            self.verify_btn.set_sensitive(True)
            if err:
                self.toast(format_error(err))
                return
            verdict = out[0]["verdict"]
            self.toast({"infrared": _("The camera does not see the phone screen: it is infrared."),
                        "sees-visible-light": _("The camera saw the phone screen: it is not infrared.")}
                       .get(verdict, _("Inconclusive: hold the screen close to the lens and try again.")))
            self.reload()
        self.client.call_async("VerifyInfrared", "", (), done, 120000)

    def _test(self, user: str) -> None:
        from ..cli import challenge_text, head_turn_advice, turned_text

        def progress(phase: str, detail: str) -> None:
            if phase == "challenge":
                self.toast(challenge_text(detail))
            elif phase == "turned":
                self.toast(turned_text(detail))

        self.toast(_("Look at the camera..."))
        sub = self.client.subscribe("RecognitionProgress", progress)

        def done(out, err):
            self.client.conn.signal_unsubscribe(sub)
            if err:
                self.toast(format_error(err))
                return
            r = out[0]
            advice = "" if r["ok"] or not r.get("head_turn") else head_turn_advice(r["head_turn"])
            if advice:      # a toast is too short to read what to change
                self.alert(_("Not recognised (%s)") % r["reason"], advice)
                return
            self.toast(_("Recognised (similarity %.2f)") % r["score"] if r["ok"]
                       else _("Not recognised (%s)") % r["reason"])
        self.client.call_async("TestRecognition", "ss", (user, ""), done, 120000)

    def _set_config(self, changes: dict) -> None:
        def done(out, err):
            if err:
                self.toast(format_error(err))
            self.reload()
        self.client.call_async("SetConfig", "a{sv}",
                               ({k: GLib.Variant("b" if isinstance(v, bool) else "d" if isinstance(v, float) else "s", v)
                                 for k, v in changes.items()},), done, 600000)

    def _on_master(self, row, _p) -> None:
        if not self._building:
            self._set_config({"core.enabled": row.get_active()})

    def _on_service(self, row, _p, name: str) -> None:
        if not self._building:
            self._set_config({f"services.{name}": CAMERA_CHOICES[row.get_selected()][0]})

    def _on_level(self, row, _p) -> None:
        if not self._building:
            self._set_config({"recognition.threshold": float(SECURITY_LEVELS[row.get_selected()][0])})

    def open_enrollment(self, user: str | None = None) -> EnrollPage:
        page = EnrollPage(self, user or GLib.get_user_name())
        self.nav.push(page)
        return page


class Application(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.set_resource_base_path(None)

    def do_activate(self) -> None:
        win = self.props.active_window or Window(self)
        win.present()


def main() -> int:
    return Application().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
