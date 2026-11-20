"""Build verified task pools per repo: mutations (bug fixes), stubs (implement), renames, doc and question targets.

Usage: prep.py [repo ...]   writes r/<repo>/pool.json
"""

import ast
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tokenize
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import REFS, REPOS_DIR

REPOS = json.loads((REFS / "repos.json").read_text())
SWAP = {
    "<": "<=",
    "<=": "<",
    ">": ">=",
    ">=": ">",
    "==": "!=",
    "!=": "==",
    "+": "-",
    "-": "+",
    "and": "or",
    "or": "and",
    "is": "is not",
    "in": "not in",
    "True": "False",
    "False": "True",
    "*": "//",
}


def pytest(py, root, tests, deselect=(), extra=(), timeout=90):
    args = [str(py), "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=no", "--color=no", "-rfE", tests, *extra]
    for d in deselect:
        args += ["--deselect", d]
    try:
        done = subprocess.run(
            args,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=dict(os.environ, PYTHONPATH=str(root / "src"), NO_COLOR="1"),
        )
    except subprocess.TimeoutExpired:
        return -1, [], "timeout"
    out = done.stdout + done.stderr
    failed = sorted(set(re.findall(r"^(?:FAILED|ERROR) (\S+)", out, re.M)))
    return done.returncode, failed, out


def module_of(rel, src):
    parts = Path(rel).with_suffix("").parts
    if parts[0] == "src":
        parts = parts[1:]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def defs(root, src, tests):
    out = []
    for path in sorted((root / src).rglob("*.py")):
        rel = str(path.relative_to(root))
        if rel.startswith(tests) or "/tests/" in rel or "_compat" in rel or "_version" in rel:
            continue
        text = path.read_text()
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue

        def walk(node, prefix, top):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    q = prefix + child.name
                    out.append(
                        {
                            "path": rel,
                            "module": module_of(rel, src),
                            "qual": q,
                            "name": child.name,
                            "line": child.lineno,
                            "end": child.end_lineno,
                            "doc": ast.get_docstring(child) or "",
                            "top": top,
                            "body_start": child.body[1].lineno
                            if (ast.get_docstring(child) and len(child.body) > 1)
                            else child.body[0].lineno,
                            "stmts": sum(1 for _ in ast.walk(child) if isinstance(_, ast.stmt)) - 1,
                            "indent": child.body[0].col_offset,
                        }
                    )
                    walk(child, q + ".<locals>.", False)
                elif isinstance(child, ast.ClassDef):
                    walk(child, prefix + child.name + ".", False)

        walk(tree, "", True)
    return out


def op_tokens(line):
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(line.strip() + "\n").readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    return [
        t
        for t in toks
        if (t.type == tokenize.OP and t.string in SWAP) or (t.type == tokenize.NAME and t.string in SWAP)
    ]


def mutate_line(line, rng):
    toks = op_tokens(line)
    if not toks:
        return None
    t = rng.choice(toks)
    lead = len(line) - len(line.lstrip())
    s, e = t.start[1] + lead, t.end[1] + lead
    if t.string == "-" and (s == lead or line[s - 1] in "([,=:" or line[s - 2 : s] in ("= ", "( ", ", ")):
        return None  # unary minus
    if t.string == "*" and (line[s + 1 : s + 2] == "*" or line[s - 1 : s] == "*" or line[s - 1] in "(,"):
        return None
    if t.string == "in" and line[:s].rstrip().endswith("for") is False and re.search(r"\bfor\b[^:]*$", line[:s]):
        return None  # for x in y
    if t.string == "is" and line[e:].lstrip().startswith("not"):
        return line[:s] + "is" + line[e:].replace("not ", "", 1)
    new = line[:s] + SWAP[t.string] + line[e:]
    return new


def main():
    names = sys.argv[1:] or list(REPOS)
    for name in names:
        r = REPOS[name]
        base = REPOS_DIR / name
        pristine, py = base / "pristine", base / "venv" / "bin" / "python"
        rng = random.Random(name)
        code, failed, _ = pytest(py, pristine, r["tests"], timeout=600)
        deselect = failed
        work = base / "scratch"
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(pristine, work, symlinks=True)
        ds = defs(work, r["src"], r["tests"])
        pool = {"deselect": deselect, "mutations": [], "stubs": [], "renames": [], "docs": [], "questions": []}

        # Mutations: random line inside a function body, verified to fail 1..25 tests.
        cands = [d for d in ds if d["stmts"] >= 2]
        tries = 0
        while len(pool["mutations"]) < 12 and tries < 700:
            tries += 1
            d = rng.choice(cands)
            path = work / d["path"]
            lines = path.read_text().splitlines(keepends=True)
            idx = rng.randrange(d["body_start"] - 1, d["end"])
            orig = lines[idx]
            if orig.strip().startswith(("#", '"', "'")) or len(orig.strip()) < 6:
                continue
            new = mutate_line(orig, rng)
            if not new or new == orig:
                continue
            if sum(1 for l in lines if l == orig) != 1:
                continue
            try:
                ast.parse("".join(lines[:idx] + [new] + lines[idx + 1 :]))
            except SyntaxError:
                continue
            path.write_text("".join(lines[:idx] + [new] + lines[idx + 1 :]))
            code, fails, out = pytest(py, work, r["tests"], deselect)
            path.write_text("".join(lines))
            # --deselect does not always take; a test that fails on the pristine copy names no bug.
            fails = [f for f in fails if f not in deselect]
            if code == 1 and 1 <= len(fails) <= 25 and "error" not in out.splitlines()[-1].lower():
                pool["mutations"].append(
                    {"path": d["path"], "qual": d["qual"], "line": idx + 1, "orig": orig, "new": new, "failing": fails}
                )
                print(name, "mut", d["qual"], len(fails), flush=True)

        # Stubs: documented functions with real bodies; replacing the body fails 1..30 tests.
        cands = [
            d
            for d in ds
            if len(d["doc"]) > 40
            and 4 <= d["stmts"] <= 30
            and not d["name"].startswith("__")
            and "<locals>" not in d["qual"]
        ]
        rng.shuffle(cands)
        for d in cands:
            if len(pool["stubs"]) >= 8:
                break
            path = work / d["path"]
            lines = path.read_text().splitlines(keepends=True)
            if d["body_start"] - 1 >= d["end"]:
                continue
            body = lines[d["body_start"] - 1 : d["end"]]
            stub = [" " * d["indent"] + "raise NotImplementedError\n"]
            path.write_text("".join(lines[: d["body_start"] - 1] + stub + lines[d["end"] :]))
            code, fails, out = pytest(py, work, r["tests"], deselect)
            path.write_text("".join(lines))
            fails = [f for f in fails if f not in deselect]
            if code == 1 and 1 <= len(fails) <= 30:
                pool["stubs"].append(
                    {
                        "path": d["path"],
                        "qual": d["qual"],
                        "body_start": d["body_start"],
                        "end": d["end"],
                        "body": "".join(body),
                        "indent": d["indent"],
                        "failing": fails,
                    }
                )
                print(name, "stub", d["qual"], len(fails), flush=True)

        # Renames: private helpers used at least three times across library and tests.
        texts = {str(p.relative_to(work)): p.read_text() for p in work.rglob("*.py")}
        seen = set()
        for d in ds:
            n = d["name"]
            if not re.fullmatch(r"_[a-z][a-z0-9_]{3,}", n) or n in seen or n.endswith("_"):
                continue
            seen.add(n)
            if sum(1 for x in ds if x["name"] == n) != 1:
                continue
            hits = {p: len(re.findall(rf"\b{re.escape(n)}\b", t)) for p, t in texts.items()}
            total = sum(hits.values())
            files = [p for p, c in hits.items() if c]
            new = n + "_impl"
            if total >= 3 and len(files) >= 1 and not any(re.search(rf"\b{new}\b", t) for t in texts.values()):
                pool["renames"].append({"old": n, "new": new, "count": total, "files": files, "path": d["path"]})
        rng.shuffle(pool["renames"])
        pool["renames"] = pool["renames"][:8]

        # Doc targets: public top-level functions without examples.
        docs = [
            d for d in ds if d["top"] and not d["name"].startswith("_") and ">>>" not in d["doc"] and d["stmts"] >= 2
        ]
        rng.shuffle(docs)
        pool["docs"] = [{"path": d["path"], "module": d["module"], "qual": d["qual"]} for d in docs[:8]]

        # Questions: a function's unique first docstring sentence.
        firsts = {}
        for d in ds:
            s = d["doc"].strip().split("\n\n")[0].replace("\n", " ")
            s = re.split(r"(?<=\.)\s", s)[0]
            if 25 <= len(s) <= 160 and d["name"].lower() not in s.lower():
                firsts.setdefault(s, []).append(d)
        qs = [(s, v[0]) for s, v in firsts.items() if len(v) == 1 and "<locals>" not in v[0]["qual"]]
        rng.shuffle(qs)
        pool["questions"] = [
            {"sentence": s, "path": d["path"], "qual": d["qual"], "name": d["name"]} for s, d in qs[:8]
        ]

        shutil.rmtree(work)
        (base / "pool.json").write_text(json.dumps(pool, indent=1))
        print(name, {k: len(v) for k, v in pool.items()}, flush=True)


main()
