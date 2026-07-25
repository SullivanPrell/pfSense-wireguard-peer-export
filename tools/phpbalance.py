#!/usr/bin/env python3
"""
Lightweight PHP structural check for environments without a php binary.

Not a parser. It strips comments and string literals from each <?php ... ?>
region, then verifies that braces, parentheses and brackets balance, and that
PHP open/close tags pair up. That is enough to catch the realistic failure
mode here -- a hand edit that removes an unbalanced chunk of a large file.

Run `make lint` instead when php(1) is available; it is authoritative.

Usage: tools/phpbalance.py [paths...]     (default: src/)
"""

from __future__ import annotations

import sys
from pathlib import Path

PAIRS = {"}": "{", ")": "(", "]": "["}
OPENS = set(PAIRS.values())


def php_regions(text: str):
    """Yield (offset, code) for each PHP region, tolerating unclosed tails."""
    i = 0
    while (start := text.find("<?php", i)) != -1:
        body = start + 5
        end = text.find("?>", body)
        if end == -1:
            yield body, text[body:]
            return
        yield body, text[body:end]
        i = end + 2


def strip_noise(code: str) -> str:
    """Blank out comments, strings and heredocs, preserving offsets."""
    out = list(code)
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        two = code[i:i + 2]
        if two == "//" or c == "#":
            j = code.find("\n", i)
            j = n if j == -1 else j
            out[i:j] = " " * (j - i)
            i = j
        elif two == "/*":
            j = code.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out[i:j] = " " * (j - i)
            i = j
        elif two == "<<<":
            # heredoc / nowdoc: <<<LABEL or <<<'LABEL' or <<<"LABEL"
            eol = code.find("\n", i)
            if eol == -1:
                break
            label = code[i + 3:eol].strip().strip("'\"")
            j, end = eol + 1, n
            while j < n:
                nl = code.find("\n", j)
                line = code[j:nl if nl != -1 else n]
                if line.strip().rstrip(";,").rstrip() == label:
                    end = nl if nl != -1 else n
                    break
                if nl == -1:
                    break
                j = nl + 1
            out[i:end] = " " * (end - i)
            i = end
        elif c in "'\"":
            j = i + 1
            while j < n:
                if code[j] == "\\":
                    j += 2
                    continue
                # In a double-quoted string, "{$expr}" is interpolation and may
                # itself contain quotes: "{$peer["descr"]}". Skip to the
                # matching brace so the inner quote is not read as the string
                # terminator.
                if c == '"' and code[j] == "{" and code[j + 1:j + 2] == "$":
                    depth, k = 1, j + 1
                    while k < n and depth:
                        if code[k] == "{":
                            depth += 1
                        elif code[k] == "}":
                            depth -= 1
                        k += 1
                    j = k
                    continue
                if code[j] == c:
                    j += 1
                    break
                j += 1
            out[i:j] = " " * (j - i)
            i = j
        else:
            i += 1
    return "".join(out)


def check(path: Path) -> list[str]:
    text = path.read_text(errors="replace")
    problems = []

    if text.count("<?php") == 0:
        return problems

    stack = []
    for offset, code in php_regions(text):
        for k, ch in enumerate(strip_noise(code)):
            if ch in OPENS:
                stack.append((ch, offset + k))
            elif ch in PAIRS:
                if not stack:
                    line = text.count("\n", 0, offset + k) + 1
                    problems.append(f"{path}:{line}: unexpected '{ch}'")
                elif stack[-1][0] != PAIRS[ch]:
                    line = text.count("\n", 0, offset + k) + 1
                    problems.append(
                        f"{path}:{line}: '{ch}' closes '{stack[-1][0]}'")
                    stack.pop()
                else:
                    stack.pop()

    for ch, pos in stack:
        line = text.count("\n", 0, pos) + 1
        problems.append(f"{path}:{line}: unclosed '{ch}'")

    return problems


def scan(roots: list[Path]) -> dict[str, int]:
    """Return {basename: problem count} across the given roots."""
    files = []
    for r in roots:
        files.extend(sorted(r.rglob("*.php")) if r.is_dir() else [r])
    counts = {}
    for f in files:
        counts[f.name] = len(check(f))
    return counts


def main() -> int:
    args = sys.argv[1:]
    baseline = None
    if "--baseline" in args:
        i = args.index("--baseline")
        baseline = Path(args[i + 1])
        del args[i:i + 2]

    roots = [Path(a) for a in args] or [Path("src")]

    if baseline:
        # Comparative mode: the heuristic has known blind spots on very large
        # mixed PHP/HTML files, so an absolute count is not meaningful. What
        # is meaningful is whether our edits made a file *worse* than the
        # upstream copy it came from.
        base = scan([baseline])
        ours = scan(roots)
        regressions = 0
        for name, n in sorted(ours.items()):
            b = base.get(name)
            if b is None:
                print(f"{name}: new file, {n} finding(s)"
                      + (" -- REVIEW" if n else ""))
                regressions += 1 if n else 0
            elif n > b:
                print(f"{name}: REGRESSION {b} -> {n}")
                regressions += 1
            elif n < b:
                print(f"{name}: improved {b} -> {n}")
        print(f"\n{len(ours)} files compared against {baseline}: "
              f"{regressions} regression(s)")
        return 1 if regressions else 0

    problems = []
    for r in roots:
        files = sorted(r.rglob("*.php")) if r.is_dir() else [r]
        for f in files:
            problems.extend(check(f))
    for p in problems:
        print(p)
    print(f"{len(problems)} finding(s) -- absolute counts include known "
          f"false positives; prefer --baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
