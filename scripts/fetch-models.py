#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Download the face models into a directory, or verify one.

    scripts/fetch-models.py DEST          download every model (SHA-256 verified)
    scripts/fetch-models.py --check DIR   only verify what is in DIR

Needs nothing but the Python standard library.  Used by scripts/build-deb.sh
and by the release workflow to bundle the models in the .deb.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from facial_auth import models  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory", type=Path)
    ap.add_argument("--check", action="store_true", help="verify only, download nothing")
    args = ap.parse_args(argv)

    if args.check:
        problems = models.check_dir(args.directory)
        for p in problems:
            print(f"ERROR {p}", file=sys.stderr)
        if not problems:
            print(f"OK: {len(models.ALL)} models present and verified in {args.directory}")
        return 1 if problems else 0

    try:
        files = models.fetch_all(args.directory, progress=lambda spec, done: print(
            f"  {spec.filename}: {done // 1024} KiB", end="\r", flush=True))
    except RuntimeError as exc:
        print(f"\nERROR {exc}", file=sys.stderr)
        return 1
    print()
    for f in files:
        print(f"OK {f.name}  {f.stat().st_size} bytes  sha256 verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
