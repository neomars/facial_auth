# SPDX-License-Identifier: MIT
"""gettext helpers: source strings are English, catalogues live in po/."""
from __future__ import annotations

import gettext
import os

DOMAIN = "facial-auth"
_LOCALEDIRS = [os.environ.get("FACIAL_AUTH_LOCALEDIR", ""), "/usr/share/locale",
               os.path.join(os.path.dirname(__file__), "..", "..", "build", "po")]


def _translation() -> gettext.NullTranslations:
    """First catalogue found for the user's language (English when none)."""
    for d in _LOCALEDIRS:
        if d and os.path.isdir(d):
            t = gettext.translation(DOMAIN, localedir=d, fallback=True)
            if type(t) is not gettext.NullTranslations:   # a real catalogue was loaded
                return t
    return gettext.NullTranslations()


_t = _translation()
_ = _t.gettext
ngettext = _t.ngettext
