"""Build the bug pool for one language of the non-Python set: operator swaps that break its tests.

    CIGAR_GAUNTLET_WORK=... python3 -I lang_prep.py <go|rust|ts> [--max 24]

Writes references/pools/lang-<lang>.json. Each candidate is one operator swap on a line that
appears once in its file. A candidate is kept only when the suite still builds, fails, and names
the tests that fail; the swap is undone before the next one.
"""

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lang_rig import LANG, LANGS, enclosing, run_tests
from rig import REFS

SWAPS = [
    (" <= ", " < "),
    (" < ", " <= "),
    (" >= ", " > "),
    (" > ", " >= "),
    (" == ", " != "),
    (" != ", " == "),
    (" && ", " || "),
    (" || ", " && "),
    (" + 1", " - 1"),
    (" - 1", " + 1"),
]
# A failure that only shows the suite no longer builds is a compile error, not a bug to track down.
# cargo ends a run with failing tests with `error: test failed`; that one is a bug, not a build error.
BUILD_ERROR = re.compile(r"\[build failed\]|^error(\[E\d+\])?:(?! test failed)|could not compile|SyntaxError|Transform failed", re.M)
COMMENT = re.compile(r"^\s*(//|/\*|\*)")


def candidates(lang, root):
    spec = LANGS[lang]
    out = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        if "node_modules" in rel.parts or "target" in rel.parts or not spec["src"](rel):
            continue
        text = path.read_text()
        lines = text.splitlines(keepends=True)
        for i, line in enumerate(lines):
            if COMMENT.match(line) or "=>" in line or text.count(line) != 1:
                continue
            for orig, new in SWAPS:
                if line.count(orig) == 1 and line.count('"') == 0:
                    qual = enclosing(lang, lines, i)
                    if qual:
                        out.append({"path": str(rel), "line": i + 1, "qual": qual, "orig": line, "new": line.replace(orig, new)})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lang", choices=sorted(LANGS))
    ap.add_argument("--max", type=int, default=24)
    a = ap.parse_args()
    spec = LANGS[a.lang]
    root = LANG / spec["repo"]
    code, out = run_tests(a.lang, root)
    if code != 0:
        raise SystemExit(f"{spec['repo']} suite fails before any change:\n{out[-800:]}")
    pool, cands = [], candidates(a.lang, root)
    random.Random(f"lang-{a.lang}").shuffle(cands)
    print(len(cands), "candidates", flush=True)
    per_func = {}
    for c in cands:
        if len(pool) >= a.max:
            break
        if per_func.get((c["path"], c["qual"]), 0) >= 2:
            continue
        f = root / c["path"]
        text = f.read_text()
        f.write_text(text.replace(c["orig"], c["new"], 1))
        try:
            code, out = run_tests(a.lang, root)
        finally:
            f.write_text(text)
        failing = sorted(set(spec["failing"].findall(out)))
        if BUILD_ERROR.search(out):
            verdict = "build"
        elif code == 0:
            verdict = "pass"
        elif failing:
            verdict = "keep"
        else:
            verdict = "noname"
        print(c["path"], c["line"], c["qual"], verdict, len(failing), flush=True)
        if verdict == "keep":
            pool.append(dict(c, failing=failing[:6]))
            per_func[(c["path"], c["qual"])] = per_func.get((c["path"], c["qual"]), 0) + 1
    code, out = run_tests(a.lang, root)
    if code != 0:
        raise SystemExit("suite fails after prep; the repo was left changed")
    dest = REFS / "pools" / f"lang-{a.lang}.json"
    dest.write_text(json.dumps({"repo": spec["repo"], "mutations": pool}, indent=1) + "\n")
    print("wrote", dest, len(pool), "mutations")


if __name__ == "__main__":
    main()
