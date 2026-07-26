#!/usr/bin/env python3
"""Render every WGX page in the fork and in upstream 1.1.0, then diff.

Fixture thinness, stub inaccuracy and pre-existing upstream sloppiness all
show up identically in both trees, so only the DELTA is attributable to this
fork's edits.
"""
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
RENDER = HERE / "render.php"

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr", "!doctype"}
STRUCTURAL = {"div", "table", "thead", "tbody", "tr", "td", "th", "form",
              "ul", "ol", "li", "section", "span", "select", "nav", "button",
              "label", "fieldset", "a", "p", "h1", "h2", "h3", "h4", "pre", "code"}

TAG_RE = re.compile(r"<(/?)([a-zA-Z!][a-zA-Z0-9-]*)\b[^>]*?(/?)>", re.S)
# script/style bodies contain '<' in JS that is not markup
BLOCK_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.S | re.I)


def tag_balance(html: str) -> Counter:
    html = BLOCK_RE.sub("", html)
    bal = Counter()
    for closing, name, selfclose in TAG_RE.findall(html):
        n = name.lower()
        if n in VOID or selfclose or n not in STRUCTURAL:
            continue
        bal[n] += -1 if closing else 1
    return Counter({k: v for k, v in bal.items() if v != 0})


def render(page: Path):
    p = subprocess.run(["php", str(RENDER), str(page)],
                       capture_output=True, text=True, timeout=120)
    try:
        return json.loads(p.stdout or "{}")
    except json.JSONDecodeError:
        return {"output": "", "diags": [], "fatal": {
            "msg": f"harness could not parse render output; stderr={p.stderr[:400]}",
            "file": page.name, "line": 0}}


def diag_key(d):
    # Compare by message shape, not line number — line numbers legitimately
    # shift when code is removed.
    msg = re.sub(r"\d+", "N", d["msg"])
    return (d["file"], msg)


def main(fork_root: str, up_root: str) -> int:
    fork_root, up_root = Path(fork_root), Path(up_root)
    pages = sorted(p.name for p in (fork_root / "usr/local/www/wgx").glob("*.php"))

    print("=" * 74)
    print(" RENDER CHECK — pages executed against a stub pfSense, fork vs upstream")
    print("=" * 74)

    problems = 0
    for name in pages:
        fpage = fork_root / "usr/local/www/wgx" / name
        upage = up_root / "usr/local/www/wgx" / name

        f = render(fpage)
        u = render(upage) if upage.is_file() else None

        fbal = tag_balance(f.get("output", ""))
        fdiags = Counter(diag_key(d) for d in f.get("diags", []))
        nbytes = len(f.get("output", ""))

        status, notes = "OK", []

        if f.get("fatal"):
            status = "FAIL"
            notes.append(f'fatal: {f["fatal"]["msg"]} ({f["fatal"]["file"]}:{f["fatal"]["line"]})')

        if u is None:
            notes.append("no upstream counterpart (fork-only file)")
            if fbal:
                status = "FAIL" if status == "OK" else status
                notes.append(f"unbalanced tags: {dict(fbal)}")
        else:
            ubal = tag_balance(u.get("output", ""))
            udiags = Counter(diag_key(d) for d in u.get("diags", []))

            delta = Counter(fbal)
            delta.subtract(ubal)
            delta = {k: v for k, v in delta.items() if v != 0}
            if delta:
                status = "FAIL"
                notes.append(f"tag-balance regression vs upstream: {delta}")
            elif fbal:
                notes.append(f"unbalanced in both (pre-existing): {dict(fbal)}")

            new = fdiags - udiags
            if new:
                status = "FAIL" if status == "OK" else status
                for (fl, msg), cnt in new.most_common(6):
                    notes.append(f"new diagnostic x{cnt}: {fl}: {msg[:90]}")

            if u.get("fatal") and not f.get("fatal"):
                notes.append("upstream fatals here but fork does not")

        if status != "OK":
            problems += 1
        print(f"\n  [{status}] {name}  ({nbytes:,} bytes rendered)")
        for n in notes:
            print(f"          {n}")
        if not notes:
            print("          balanced, no diagnostics upstream does not also emit")

    print()
    print("-" * 74)
    print(f"  {len(pages)} page(s) rendered, {problems} with regressions")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
