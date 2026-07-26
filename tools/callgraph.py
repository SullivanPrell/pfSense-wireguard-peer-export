#!/usr/bin/env python3
"""Call-graph regression check: fork vs the upstream package it forked from.

`php -l` proves a file parses. It says nothing about whether a function that
was deleted is still being called — that only shows up when the branch runs,
which may be never on a test box and always on someone's firewall.

This walks both trees with PHP's own lexer (tools/symbols.php) and answers one
question: does the fork call anything it no longer defines but upstream did?

Names undefined in BOTH trees are supplied by pfSense at runtime
(config.inc, util.inc, guiconfig.inc, the WireGuard package) and are reported
as informational only.

    usage: callgraph.py <fork-src-dir> <upstream-dir>
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYMBOLS = HERE / "symbols.php"

# PHP language constructs the lexer emits as T_STRING followed by '('
CONSTRUCTS = {
    "array", "isset", "unset", "empty", "list", "echo", "print", "exit", "die",
    "include", "include_once", "require", "require_once", "eval", "match", "fn",
}


def php(*args: str) -> str:
    try:
        p = subprocess.run(["php", *args], capture_output=True, text=True, check=True)
    except FileNotFoundError:
        sys.exit("php not installed; cannot run the call-graph check")
    except subprocess.CalledProcessError as e:
        sys.exit(f"php failed: {e.stderr.strip()[:500]}")
    return p.stdout


def symbols(tree: Path) -> dict:
    return json.loads(php(str(SYMBOLS), str(tree)))


def main(fork_dir: str, up_dir: str) -> int:
    fork = symbols(Path(fork_dir))
    up = symbols(Path(up_dir))
    builtins = {
        n.lower()
        for n in json.loads(php("-r", 'echo json_encode(get_defined_functions()["internal"]);'))
    }

    fork_def = {k.lower() for k in fork["defined"]}
    up_def = {k.lower() for k in up["defined"]}

    def unresolved(sym, defined):
        out = {}
        for c in sym["called"]:
            n = c["name"]
            if n in defined or n in builtins or n in CONSTRUCTS:
                continue
            out.setdefault(n, []).append(f'{c["file"]}:{c["line"]}')
        return out

    fork_un = unresolved(fork, fork_def)
    up_un = set(unresolved(up, up_def))

    # Deleted the definition, kept a caller.
    broken = {n: s for n, s in fork_un.items() if n in up_def}
    # Called a name upstream neither defined nor called — i.e. we invented it.
    invented = {n: s for n, s in fork_un.items() if n not in up_def and n not in up_un}
    external = [n for n in fork_un if n not in broken and n not in invented]

    print("=" * 70)
    print(" CALL-GRAPH REGRESSION CHECK")
    print("=" * 70)
    print(f"  defined in fork:   {len(fork_def)}")
    print(f"  defined upstream:  {len(up_def)}")
    print(f"  removed by fork:   {len(up_def - fork_def)}")
    print()

    if broken:
        print(f"  [FAIL] {len(broken)} call(s) to function(s) this fork deleted:")
        for n, sites in sorted(broken.items()):
            print(f"      {n}()  was defined at {up['defined'][n]}")
            for s in sites:
                print(f"          still called at {s}")
    else:
        print("  [OK]   no call site references a function this fork removed")

    if invented:
        print(f"  [FAIL] {len(invented)} call(s) to name(s) unknown to upstream:")
        for n, sites in sorted(invented.items()):
            print(f"      {n}()  {', '.join(sites[:4])}")
    else:
        print("  [OK]   no calls to names upstream did not also call")

    print(f"  [INFO] {len(external)} name(s) supplied by pfSense at runtime")
    return 1 if (broken or invented) else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
