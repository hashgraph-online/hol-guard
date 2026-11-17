"""Load arm, no model calls: how many prompt notes a busy machine drops.

Usage: load.py --base FILE [--config <codex config.toml>] [--jobs 4] [--burn 4] [--rounds 1]
               [--swap OLD=NEW]... [--save FILE]

Replays the prompts saved by `mixed.py --save` through the same prompt hook, `--jobs` at once, while
`--burn` processes keep that many CPU cores busy. A prompt whose note carried text when the machine
was idle (the --base file) and comes back empty now was dropped: the hook ran out of time or failed.
Prints the drop rate, notes that changed, hook failures (non-zero exit, output that is not JSON or a
timeout, kept per prompt so one failure does not end the run) and hook time at p50 and p95.
"""

import argparse
import json
import multiprocessing
import shutil
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import notes_hook
from rig import ARMS, REPOS_DIR, WORK

RUN = uuid.uuid4().hex[:12]
BROKEN = "<<hook failed: "


def burn(stop):
    while not stop.is_set():
        sum(i * i for i in range(10_000))


def one(hook, job):
    index, row = job
    # Each prompt gets its own copy so parallel sessions never share a project, and each run its own
    # parent folder so two runs on one rig never delete each other's projects.
    dest = WORK / "notes" / f"load-{RUN}" / f"{row['repo']}-{index}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPOS_DIR / row["repo"] / "pristine", dest, symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    started = time.monotonic()
    try:
        text = notes_hook.note(hook, dest, row["prompt"], str(uuid.uuid4()))
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as failure:
        text = f"{BROKEN}{type(failure).__name__}: {str(failure)[:200]}>>"
    finally:
        took = time.monotonic() - started
        shutil.rmtree(dest, ignore_errors=True)
    return {**row, "loaded_note": text, "secs": round(took, 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="notes from an idle run (mixed.py --save)")
    ap.add_argument("--config", default=str(ARMS / "cigar" / "codex_home" / "config.toml"))
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--burn", type=int, default=4, help="CPU cores kept busy during the run")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--swap", action="append", default=[], metavar="OLD=NEW")
    ap.add_argument("--save")
    a = ap.parse_args()
    hook = tomllib.load(open(a.config, "rb"))["hooks"]["UserPromptSubmit"][0]["hooks"][0]
    for pair in a.swap:
        old, new = pair.split("=", 1)
        hook = {**hook, "command": hook["command"].replace(old, new),
                "env": {k: v.replace(old, new) for k, v in hook.get("env", {}).items()}}
    base = json.load(open(a.base))

    stop = multiprocessing.Event()
    burners = [multiprocessing.Process(target=burn, args=(stop,), daemon=True) for _ in range(a.burn)]
    for p in burners:
        p.start()
    try:
        jobs = [(n, row) for n, row in enumerate(base * a.rounds)]
        with ThreadPoolExecutor(a.jobs) as pool:
            rows = list(pool.map(lambda job: one(hook, job), jobs))
    finally:
        stop.set()
        for p in burners:
            p.join(5)
        shutil.rmtree(WORK / "notes" / f"load-{RUN}", ignore_errors=True)

    if a.save:
        Path(a.save).write_text(json.dumps(rows, indent=1))
    broken = [r for r in rows if r["loaded_note"].startswith(BROKEN)]
    had = [r for r in rows if r["note"]]
    dropped = [r for r in had if not r["loaded_note"] or r["loaded_note"].startswith(BROKEN)]
    changed = [r for r in had if r["loaded_note"] and r["loaded_note"] != r["note"] and r not in dropped]
    secs = sorted(r["secs"] for r in rows)

    def pct(q):
        return secs[min(len(secs) - 1, int(q * len(secs)))]

    print(f"prompts {len(rows)} at {a.jobs} jobs with {a.burn} busy cores")
    print(f"dropped {len(dropped)}/{len(had)} notes ({100 * len(dropped) / max(len(had), 1):.1f}%); "
          f"changed {len(changed)}; hook failed {len(broken)}")
    print(f"hook time p50 {pct(0.5):.2f}s p95 {pct(0.95):.2f}s max {secs[-1]:.2f}s")


if __name__ == "__main__":
    main()
