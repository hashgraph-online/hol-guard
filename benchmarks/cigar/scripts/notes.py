"""Fast check, no model calls: replay CIGAR's prompt hook on every seeded step and diff the notes.

Usage: notes.py [--seeds 68,...] [--config <codex config.toml>] [--save DIR] [--against DIR]
For each seed it copies the pristine repo, applies each step's teammate change in order (without any
agent edits), and sends the step's prompt to the CIGAR prompt hook of the cigar arm, one session per
seed. --save writes the notes; --against compares with stored notes (default references/notes).
A changed note is not a regression by itself: it tells you which task kinds the live run will move.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as R
from rig import ARMS, REFS, REPOS_DIR, SEEDS, WORK

ap = argparse.ArgumentParser()
ap.add_argument("--seeds", default=",".join(map(str, SEEDS)))
ap.add_argument("--config", default=str(ARMS / "cigar" / "codex_home" / "config.toml"))
ap.add_argument("--save")
ap.add_argument("--against", default=str(REFS / "notes"))
a = ap.parse_args()
# Fixed commit dates give the same commit ids on every replay, so equal notes compare equal.
os.environ.update(GIT_AUTHOR_DATE="2026-01-01T00:00:00Z", GIT_COMMITTER_DATE="2026-01-01T00:00:00Z")
hook = tomllib.load(open(a.config, "rb"))["hooks"]["UserPromptSubmit"][0]["hooks"][0]


HEX = re.compile(r"\b[0-9a-f]{7,40}\b")


def note(project, prompt, session):
    payload = {
        "session_id": session,
        "turn_id": str(uuid.uuid4()),
        "transcript_path": None,
        "cwd": str(project),
        "hook_event_name": "UserPromptSubmit",
        "model": "gpt-6-luna",
        "permission_mode": "default",
        "prompt": prompt,
    }
    out = subprocess.run(
        hook["command"],
        shell=True,
        input=json.dumps(payload),
        cwd=project,
        capture_output=True,
        text=True,
        timeout=90,
        env=dict(os.environ, **hook.get("env", {})),
    )
    try:
        o = json.loads(out.stdout or "{}")
    except ValueError:
        return f"<<hook output not JSON: {out.stdout[:200]!r} {out.stderr[-200:]!r}>>"
    return (o.get("hookSpecificOutput") or {}).get("additionalContext") or ""


def replay(seed):
    repo, pool, tasks = R.plan(seed, 6)
    project = WORK / "notes" / f"s{seed}"
    if project.exists():
        shutil.rmtree(project)
    project.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        REPOS_DIR / repo / "pristine",
        project,
        symlinks=True,
        # Bytecode compiled in the pristine copy names its paths, so an assertion
        # on a code object's file name fails in the copy.
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    # A new session each replay: CIGAR leaves out what it already showed in a session.
    session = str(uuid.uuid4())
    out = []
    for n, task in enumerate(tasks, 1):
        if task["kind"] in ("bug", "bug2", "stub"):
            R.commit_all(project, f"work through step {n - 1}")
        R.apply_setup(project, task)
        out.append((f"s{seed}-{n}-{task['kind']}.txt", n, task["kind"], note(project, task["prompt"], session)))
    shutil.rmtree(project)
    return out


def stored(name):
    path = Path(a.against) / name
    return path.read_text() if path.exists() else None


def same(old, new):
    # Commit ids depend on when the rig's repos were cloned, so they are compared as placeholders.
    return old is not None and HEX.sub("<id>", old) == HEX.sub("<id>", new)


rows, changed, empty = [], 0, 0
for seed in map(int, a.seeds.split(",")):
    notes = replay(seed)
    if any(not same(stored(name), text) for name, _, _, text in notes):
        # CIGAR works to a time budget, so a busy machine can cut one note short; a change has to repeat.
        again = {name: text for name, _, _, text in replay(seed)}
        notes = [
            (name, n, kind, text if not same(stored(name), again[name]) else again[name])
            for name, n, kind, text in notes
        ]
    for name, n, kind, text in notes:
        if a.save:
            Path(a.save).mkdir(parents=True, exist_ok=True)
            (Path(a.save) / name).write_text(text)
        old = stored(name)
        kept = same(old, text)
        changed += not kept
        empty += not text.strip()
        rows.append((seed, n, kind, len(old) if old is not None else None, len(text), kept))
print(f"{'seed':>4} {'step':>4} {'kind':9} {'ref chars':>9} {'now chars':>9}  same")
for seed, n, kind, lo, ln, same in rows:
    print(f"{seed:>4} {n:>4} {kind:9} {lo if lo is not None else '-':>9} {ln:>9}  {'yes' if same else 'CHANGED'}")
ref_total = sum(r[3] or 0 for r in rows)
now_total = sum(r[4] for r in rows)
print(
    f"notes {len(rows)}  changed {changed}  empty {empty}  chars ref {ref_total} now {now_total}"
    f" ({100 * (now_total - ref_total) / ref_total:+.1f}%)"
    if ref_total
    else f"notes {len(rows)} empty {empty} chars {now_total}"
)
