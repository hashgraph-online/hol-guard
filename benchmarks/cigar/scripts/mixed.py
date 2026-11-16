"""Mixed-prompt precision check, no model calls.

Usage: mixed.py [--config <codex config.toml>] [--prompts FILE] [--save FILE] [--kinds a,b] [--show]
                [--swap OLD=NEW]... [--rescore FILE]

Replays CIGAR's prompt hook of the cigar arm on references/mixed_prompts.json: follow-up questions,
planning, chat, explain, pasted traces and logs, renames, fixes. Each prompt runs in a fresh session
against a pristine copy of its repo. A prompt labelled code=false should get no code ranges; one
labelled code=true should get ranges and at least one in its listed files.

Prints, per kind and overall: silent (no code), right (code naming a listed file), wrong (code, none
in the listed files, or any code on a code=false prompt), and note size in characters. --save writes
every note as JSON for later diffing.
"""

import argparse
import json
import re
import shutil
import sys
import uuid
from collections import defaultdict
from pathlib import Path

import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import notes_hook
from rig import ARMS, REFS, REPOS_DIR, WORK

ap = argparse.ArgumentParser()
ap.add_argument("--config", default=str(ARMS / "cigar" / "codex_home" / "config.toml"))
ap.add_argument("--prompts", default=str(REFS / "mixed_prompts.json"))
ap.add_argument("--save")
ap.add_argument("--kinds")
ap.add_argument("--show", action="store_true", help="print each wrong note's first lines")
ap.add_argument("--swap", action="append", default=[], metavar="OLD=NEW",
                help="replace OLD with NEW in the hook command and env, to replay another Guard venv or home")
ap.add_argument("--rescore", help="score notes saved by an earlier --save instead of replaying")
a = ap.parse_args()
hook = None
if not a.rescore:
    hook = tomllib.load(open(a.config, "rb"))["hooks"]["UserPromptSubmit"][0]["hooks"][0]
    for pair in a.swap:
        old, new = pair.split("=", 1)
        hook = {**hook, "command": hook["command"].replace(old, new),
                "env": {k: v.replace(old, new) for k, v in hook.get("env", {}).items()}}

# Code in a note: a mapped range "path/to/file.py:12-30", a line "path/to/file.py:12:", or a pasted
# excerpt "path/to/file.md (lines 1-112)".
RANGE = re.compile(r"(?m)^\s*([\w./-]+\.[A-Za-z0-9]+)(?::\d+[-:]| \(lines \d+-\d+\))")

prompts = json.load(open(a.prompts))["prompts"]
if a.kinds:
    keep = set(a.kinds.split(","))
    prompts = [p for p in prompts if p["kind"] in keep]

projects = {}
RUN = uuid.uuid4().hex[:12]


def project(repo):
    if repo not in projects:
        # Each run copies into its own folder, so runs side by side never share a project.
        dest = WORK / "notes" / f"mixed-{RUN}" / repo
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(REPOS_DIR / repo / "pristine", dest, symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
        projects[repo] = dest
    return projects[repo]


def verdict(p, text):
    files = sorted(set(RANGE.findall(text)))
    if not files:
        return "silent", files
    if not p["code"]:
        return "wrong", files
    hit = any(f.endswith(want) or want.endswith(f) for f in files for want in p["files"])
    return ("right" if hit else "wrong"), files


rows = []
saved = {(r["repo"], r["prompt"]): r["note"] for r in json.load(open(a.rescore))} if a.rescore else None
try:
    for p in prompts:
        if saved is not None:
            text = saved[(p["repo"], p["prompt"])]
        else:
            text = notes_hook.note(hook, project(p["repo"]), p["prompt"], str(uuid.uuid4()))
        v, files = verdict(p, text)
        rows.append({**p, "verdict": v, "files_named": files, "chars": len(text), "note": text})
finally:
    # A failed hook or Ctrl-C still removes this run's copies; the hook error is what surfaces.
    if projects:
        shutil.rmtree(WORK / "notes" / f"mixed-{RUN}", ignore_errors=True)

if a.save:
    Path(a.save).write_text(json.dumps(rows, indent=1))

by = defaultdict(list)
for r in rows:
    by[(r["code"], r["kind"])].append(r)


def line(label, rs):
    n = len(rs)
    c = {k: sum(r["verdict"] == k for r in rs) for k in ("silent", "right", "wrong")}
    chars = sum(r["chars"] for r in rs) / max(n, 1)
    return f"{label:<22} {n:>3}  silent {c['silent']:>3}  right {c['right']:>3}  wrong {c['wrong']:>3}  avg chars {chars:>6.0f}"


print("code wanted = no (a good note carries no code):")
for (code, kind), rs in sorted(by.items()):
    if not code:
        print("  " + line(kind, rs))
print("code wanted = yes (a good note names a listed file):")
for (code, kind), rs in sorted(by.items()):
    if code:
        print("  " + line(kind, rs))
no = [r for r in rows if not r["code"]]
yes = [r for r in rows if r["code"]]
print(line("ALL code=no", no))
print(line("ALL code=yes", yes))
wrong = sum(r["verdict"] == "wrong" for r in rows)
noted = sum(r["verdict"] != "silent" for r in rows)
print(f"wrong-note rate {wrong}/{noted} notes with code ({100 * wrong / max(noted, 1):.1f}%); "
      f"non-coding prompts left silent {sum(r['verdict'] == 'silent' for r in no)}/{len(no)}; "
      f"coding prompts right {sum(r['verdict'] == 'right' for r in yes)}/{len(yes)}")
if a.show:
    for r in rows:
        if r["verdict"] == "wrong":
            print(f"\n-- {r['repo']} {r['kind']}: {r['prompt'][:70]!r} -> {r['files_named'][:4]}")
