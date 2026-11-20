# SPDX-License-Identifier: MIT
"""Static checks of the polkit policy and of the files that must agree with it.

Why the "owner" annotation matters (found with a real polkitd, see
tests/system/test_polkit_real.py): the daemon runs as the unprivileged user
facial-auth and asks polkit about the application that called it, which belongs
to another user.  polkitd only allows that to root or to an owner of the action;
anybody else gets "Only trusted callers (e.g. uid 0 or an action owner) can use
CheckAuthorization() for subjects belonging to other identities", which the
daemon reports as "not authorized".  Without the annotation nobody could ever
link a face, whatever administrator password was typed.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from facial_auth import const

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "data/polkit/io.github.neomars.FacialAuth1.policy"
OWNER = "org.freedesktop.policykit.owner"


def actions():
    tree = ET.parse(POLICY)
    return {a.get("id"): a for a in tree.getroot().iter("action")}


def test_the_policy_defines_exactly_the_actions_the_daemon_asks_for():
    assert set(actions()) == {const.ACTION_MANAGE, const.ACTION_CONFIGURE, const.ACTION_CAMERA}


def test_every_action_names_the_daemon_user_as_its_owner():
    for action_id, node in actions().items():
        owners = [n.text.split() for n in node.findall("annotate") if n.get("key") == OWNER]
        assert owners == [[f"unix-user:{const.SERVICE_USER}"]], \
            f"{action_id}: without this owner polkitd refuses every check made by the daemon"


def test_the_owner_is_the_user_the_service_really_runs_as():
    unit = (ROOT / "data/systemd/facial-authd.service").read_text()
    assert re.search(rf"^User={re.escape(const.SERVICE_USER)}$", unit, re.M)
    sysusers = (ROOT / "data/sysusers/facial-auth.conf").read_text()
    assert re.search(rf"^u {re.escape(const.SERVICE_USER)} ", sysusers, re.M)


def test_the_camera_stays_usable_without_a_password_but_only_from_the_local_session():
    defaults = {n.tag: n.text for n in actions()[const.ACTION_CAMERA].find("defaults")}
    assert defaults == {"allow_any": "no", "allow_inactive": "no", "allow_active": "yes"}


def test_linking_a_face_needs_an_administrator_everywhere():
    for action_id in (const.ACTION_MANAGE, const.ACTION_CONFIGURE):
        defaults = {n.tag: n.text for n in actions()[action_id].find("defaults")}
        assert set(defaults.values()) <= {"auth_admin", "auth_admin_keep"}, action_id
