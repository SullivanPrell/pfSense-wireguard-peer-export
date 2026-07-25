#!/usr/bin/env python3
"""
Extract one of the upstream packages in upstream/ to a directory.

Used by `make check` to produce a pristine baseline for comparison, and
useful on its own for diffing this fork against what upstream actually ships.

Usage:
    tools/extract-upstream.py 1.1.0 [destdir]
    tools/extract-upstream.py --manifest 1.0.9    # dump +MANIFEST as JSON
"""

from __future__ import annotations

import json
import lzma
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UPSTREAM = REPO / "upstream"


def open_pkg(version: str):
    path = UPSTREAM / f"pfSense-pkg-wg-export-{version}.pkg"
    if not path.exists():
        available = sorted(p.name for p in UPSTREAM.glob("*.pkg"))
        sys.exit(f"error: {path} not found. Available:\n  "
                 + "\n  ".join(available))
    return path


def main() -> int:
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__.strip())

    if args[0] == "--manifest":
        pkg = open_pkg(args[1])
        with lzma.open(pkg) as fh, tarfile.open(fileobj=fh) as tar:
            data = json.load(tar.extractfile("+MANIFEST"))
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0

    version = args[0]
    dest = Path(args[1]) if len(args) > 1 else Path(
        tempfile.mkdtemp(prefix=f"wgx-upstream-{version}-"))
    dest.mkdir(parents=True, exist_ok=True)

    pkg = open_pkg(version)
    with lzma.open(pkg) as fh, tarfile.open(fileobj=fh) as tar:
        for m in tar.getmembers():
            if m.name.startswith("+"):
                continue
            # Members are stored with a leading slash; strip it and refuse
            # anything that would escape the destination.
            rel = Path(m.name.lstrip("/"))
            if rel.is_absolute() or ".." in rel.parts:
                print(f"skipping unsafe member: {m.name}", file=sys.stderr)
                continue
            target = dest / rel
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif m.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(m) as src:
                    target.write_bytes(src.read())

    print(dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
