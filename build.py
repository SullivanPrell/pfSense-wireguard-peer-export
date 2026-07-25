#!/usr/bin/env python3
"""
Build a pfSense/FreeBSD .pkg from the src/ tree.

A pfSense package is an xz-compressed tar containing, in order:

    +COMPACT_MANIFEST   package metadata (no file list)
    +MANIFEST           metadata + {path: "1$<sha256>"} for every file
    /absolute/paths...  the payload, stored with a leading slash
    /directories/       directory entries the package owns

No FreeBSD tooling is required -- everything here is Python stdlib, so the
package can be built on macOS or Linux and installed with `pkg add` on the
firewall.

Builds are deterministic: fixed mtime, uid/gid 0, normalised modes. Two builds
of the same source tree produce byte-identical output, so anyone can rebuild
and confirm a shipped .pkg matches this repository.

Usage:
    ./build.py                 build dist/<name>-<version>.pkg
    ./build.py --list          show what would be packaged, with hashes
    ./build.py --verify FILE   check a built .pkg against the src/ tree
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parent
SRC = REPO / "src"
DIST = REPO / "dist"
METADATA = REPO / "pkg" / "metadata.json"

# Reproducible builds: honour SOURCE_DATE_EPOCH, else pin to the epoch.
MTIME = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))

# Directories the package owns and should remove on deinstall. pkg deletes
# these only when empty, so listing a shared dir such as /usr/local/pkg is
# harmless -- but we list only dirs this package actually creates.
OWNED_DIRS = [
    "/usr/local/www/wgx",
    "/usr/local/share/pfSense-pkg-wg-export",
    "/usr/local/share/pfSense/priv",
]

# Upstream shipped a mix of 0600, 0644 and 0711 -- artifacts of the author's
# build box rather than intent. Normalise: executables 0755, everything else
# 0644. pfSense serves the WebGUI as root, so 0600 worked but was arbitrary.
EXECUTABLE_PREFIXES = ("/usr/local/etc/rc.d/",)
EXECUTABLE_SUFFIXES = ("wgx_expire.php",)


def file_mode(install_path: str) -> int:
    if install_path.startswith(EXECUTABLE_PREFIXES):
        return 0o755
    if install_path.endswith(EXECUTABLE_SUFFIXES):
        return 0o755
    return 0o644


def collect() -> list[tuple[str, Path]]:
    """Map every file under src/ to its absolute install path."""
    if not SRC.is_dir():
        sys.exit(f"error: source tree not found: {SRC}")
    out = []
    for path in sorted(SRC.rglob("*")):
        if path.is_file() and not path.name.startswith("."):
            out.append(("/" + str(path.relative_to(SRC)), path))
    if not out:
        sys.exit(f"error: no files found under {SRC}")
    return out


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifests(files: list[tuple[str, Path]]) -> tuple[bytes, bytes]:
    meta = json.loads(METADATA.read_text())
    meta["flatsize"] = sum(p.stat().st_size for _, p in files)

    compact = json.dumps(meta, separators=(",", ":")).encode()

    full = dict(meta)
    full["files"] = {install: "1$" + sha256(p) for install, p in files}
    full["directories"] = {d: "y" for d in OWNED_DIRS}
    return compact, json.dumps(full, separators=(",", ":")).encode()


def _entry(name: str, size: int, mode: int, typeflag: bytes) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.size = size
    ti.mode = mode
    ti.mtime = MTIME
    ti.uid = ti.gid = 0
    ti.uname, ti.gname = "root", "wheel"
    ti.type = typeflag
    return ti


def build(output: Path | None = None) -> Path:
    files = collect()
    compact, full = build_manifests(files)

    meta = json.loads(METADATA.read_text())
    output = output or DIST / f"{meta['name']}-{meta['version']}.pkg"
    output.parent.mkdir(parents=True, exist_ok=True)

    raw = io.BytesIO()
    # format=GNU_FORMAT matches what FreeBSD's pkg(8) emits for these archives.
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, blob in (("+COMPACT_MANIFEST", compact), ("+MANIFEST", full)):
            tar.addfile(_entry(name, len(blob), 0o644, tarfile.REGTYPE),
                        io.BytesIO(blob))

        for install, path in files:
            with path.open("rb") as fh:
                tar.addfile(
                    _entry(install, path.stat().st_size,
                           file_mode(install), tarfile.REGTYPE),
                    fh,
                )

        for d in OWNED_DIRS:
            tar.addfile(_entry(d + "/", 0, 0o755, tarfile.DIRTYPE))

    # CHECK_CRC64 is what FreeBSD's pkg writes, and what `file` reports for
    # the upstream packages.
    output.write_bytes(
        lzma.compress(raw.getvalue(), format=lzma.FORMAT_XZ,
                      check=lzma.CHECK_CRC64, preset=6)
    )
    return output


def cmd_list() -> None:
    files = collect()
    for install, path in files:
        print(f"{file_mode(install):04o} {path.stat().st_size:>9} "
              f"{sha256(path)[:16]}  {install}")
    print(f"\n{len(files)} files, "
          f"{sum(p.stat().st_size for _, p in files):,} bytes")


def cmd_verify(pkg: Path) -> int:
    """Confirm a built package's payload matches the current src/ tree."""
    with lzma.open(pkg) as fh, tarfile.open(fileobj=fh) as tar:
        members = {m.name: m for m in tar.getmembers()}
        manifest_member = members.get("+MANIFEST")
        if manifest_member is None:
            print("FAIL: no +MANIFEST in archive")
            return 1
        with lzma.open(pkg) as fh2, tarfile.open(fileobj=fh2) as tar2:
            manifest = json.load(tar2.extractfile("+MANIFEST"))

    expected = {install: "1$" + sha256(p) for install, p in collect()}
    declared = manifest.get("files", {})

    problems = 0
    for path in sorted(set(expected) | set(declared)):
        if path not in declared:
            print(f"MISSING FROM PKG: {path}")
            problems += 1
        elif path not in expected:
            print(f"NOT IN SOURCE:    {path}")
            problems += 1
        elif declared[path] != expected[path]:
            print(f"HASH MISMATCH:    {path}")
            problems += 1

    for path in declared:
        if path not in members:
            print(f"DECLARED BUT ABSENT FROM ARCHIVE: {path}")
            problems += 1

    print(f"\nchecked {len(declared)} files against src/: "
          f"{problems} problem(s)")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true",
                    help="list files that would be packaged")
    ap.add_argument("--verify", metavar="FILE",
                    help="verify a built .pkg against src/")
    ap.add_argument("-o", "--output", metavar="FILE", help="output path")
    args = ap.parse_args()

    if args.list:
        cmd_list()
        return 0
    if args.verify:
        return cmd_verify(Path(args.verify))

    out = build(Path(args.output) if args.output else None)
    print(f"built {out}  ({out.stat().st_size:,} bytes)")
    print(f"sha256 {sha256(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
