#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Put one version number everywhere it is written, or normalise a git tag.
#
#   scripts/set-version.sh VERSION           stamp VERSION (a Debian version)
#   scripts/set-version.sh --from-tag TAG    stamp the version of a git tag
#   scripts/set-version.sh --print [--from-tag] VALUE
#                                            print the normalised version only
#   scripts/set-version.sh --current         print the version of debian/changelog
#
# Tags: v1.2.3 -> 1.2.3,  v1.2.3-rc1 -> 1.2.3~rc1 (a Debian pre-release sorts
# before the final release).  Anything else is refused: the value comes from a
# human typing a tag name, it must never reach sed or a shell unchecked.
#
# Files stamped: meson.build, src/facial_auth/const.py, man pages and a new
# entry on top of debian/changelog.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
    sed -n '4,13p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

normalise() { # $1 = value, $2 = 1 when it is a git tag
    local v="$1"
    if [ "$2" = 1 ]; then
        v="${v#v}"
        v="$(printf '%s' "$v" | tr '-' '~')"
    fi
    if [[ ! "$v" =~ ^[0-9][0-9A-Za-z.+~]*$ ]]; then
        echo "invalid version '$1' (expected 1.2.3 or 1.2.3~rc1; from a tag: v1.2.3 or v1.2.3-rc1)" >&2
        exit 1
    fi
    printf '%s\n' "$v"
}

stamp() { # $1 = validated version
    local ver="$1"
    sed -i "s|^  version: '[^']*',|  version: '${ver}',|" meson.build
    sed -i "s|^VERSION = \".*\"|VERSION = \"${ver}\"|" src/facial_auth/const.py
    local f
    for f in man/*.1 man/*.8; do
        [ -e "$f" ] && sed -i -E "/^\.TH /s|\"facial-auth [^\"]*\"|\"facial-auth ${ver}\"|" "$f"
    done
    {
        printf 'facial-auth (%s) unstable; urgency=medium\n\n  * Release %s.\n\n' "$ver" "$ver"
        printf ' -- facial-auth maintainers <facial-auth@users.noreply.github.com>  %s\n\n' "$(date -R -u)"
        cat debian/changelog
    } >debian/changelog.new
    mv debian/changelog.new debian/changelog
}

mode=stamp
from_tag=0
while [ $# -gt 0 ]; do
    case "$1" in
    --print) mode=print; shift ;;
    --current) mode=current; shift ;;
    --from-tag) from_tag=1; shift ;;
    -h | --help) usage ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
    esac
done

if [ "$mode" = current ]; then
    # first line of the changelog: "facial-auth (VERSION) unstable; ..."
    sed -n '1s/^[^(]*(\([^)]*\)).*/\1/p' debian/changelog
    exit 0
fi
[ $# -eq 1 ] || usage
version="$(normalise "$1" "$from_tag")"
if [ "$mode" = print ]; then
    printf '%s\n' "$version"
else
    stamp "$version"
    echo "version $version stamped"
fi
