#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Build the Debian packages into dist/.  The working tree is never modified:
# the build happens in a temporary copy, where the version is stamped.
#
#   scripts/build-deb.sh [--require-models] [VERSION]
#
# VERSION      Debian version to give the packages (default: the one of
#              debian/changelog).  See scripts/set-version.sh.
# --require-models
#              fail unless data/models/ holds the verified face models (the
#              release workflow does this).  Without the flag, a package
#              without models is built and downloads them at install time.
#
# Models are bundled when present in data/models/ (scripts/fetch-models.py
# fills it), so the .deb then works offline.  Result: dist/*.deb + SHA256SUMS.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

require_models=0
if [ "${1:-}" = "--require-models" ]; then
    require_models=1
    shift
fi
version="${1:-}"

have_models=0
if compgen -G "data/models/*.onnx" >/dev/null; then
    have_models=1
    if ! python3 scripts/fetch-models.py --check data/models; then
        if [ "$require_models" = 1 ]; then
            echo "ERROR: data/models/ does not hold the verified models" >&2
            exit 1
        fi
        echo "WARNING: some bundled models do not verify; the daemon will refuse them" >&2
    fi
elif [ "$require_models" = 1 ]; then
    echo "ERROR: data/models/ is empty: run scripts/fetch-models.py data/models" >&2
    exit 1
else
    echo "WARNING: building a package WITHOUT the models (downloaded at install time)" >&2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/facial-auth"
mkdir -p "$tree"
# Tracked and untracked-but-not-ignored files, skipping those deleted on disk.
git ls-files -z --cached --others --exclude-standard |
    while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done |
    xargs -0 -r cp --parents -t "$tree"
if [ "$have_models" = 1 ]; then
    mkdir -p "$tree/data/models"
    cp data/models/*.onnx "$tree/data/models/"
fi

if [ -n "$version" ]; then
    (cd "$tree" && scripts/set-version.sh "$version")
fi
version="$(cd "$tree" && scripts/set-version.sh --current)"
echo "==> building facial-auth $version"
(cd "$tree" && dpkg-buildpackage -us -uc -b)

rm -rf dist
mkdir -p dist
for f in "$work/facial-auth_${version}"_*.deb "$work/facial-auth-gtk_${version}"_*.deb; do
    # Release hosts rewrite some characters in file names: keep names stable
    # ('~' and '+' only appear in pre-release / development versions).
    cp "$f" "dist/$(basename "$f" | tr '~+' '-.')"
done
(cd dist && sha256sum -- *.deb >SHA256SUMS)
echo "==> dist/"
ls -l dist
