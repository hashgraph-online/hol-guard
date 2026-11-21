"""Commit-replay set: one merged public pull request, redone by an agent from its description.

Usage: replay_run.py --arm <arm> --task <index into references/replay.json> --tag <tag>

The project is the PR's parent commit as a fresh one-commit repository (no history, so the fix
cannot be read from later commits). The agent gets the PR's title and description as its only
prompt, in one session. Afterwards the PR's own test files are put in place and run: the task
passes when they pass. The row in runs/<tag>/results.jsonl has the session's tokens and cost.
This set is the fresh set: never tune notes on it.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as R
import replay_prep as P
from lang_rig import bin_dir, lang_env, python_of
from rig import ARMS, PROJECTS, REFS, RUNS, WORK

B, O = R.B, R.O
LANG_OF = {"py": None, "go": "go", "rust": "rust", "ts": "ts"}


# Claude Code (Haiku) read a bare PR description as a question and asked what to do, in one
# request and with no edits, on about a third of base runs. Codex and Oh My Pi act on it. Both
# Claude Code arms get this line, so their comparison holds; the other harnesses keep the bare
# prompt their results were measured with.
CLAUDE_LEAD = "Make this change in the repository. Do not ask; do the work and verify it.\n\n"


def build(task, project):
    """Copy the tree at the PR's parent into a new repository with one commit."""
    clone = P.ROOT / task["repo"] / "git"
    tree = project.parent / "parent"
    P.git("worktree", "add", "--detach", str(tree), task["parent"], cwd=clone)
    try:
        shutil.copytree(tree, project, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    finally:
        P.git("worktree", "remove", "--force", str(tree), cwd=clone, check=False)
    R.git(project, "init", "-q")
    for key, value in R.AGENT_GIT_CONFIG:
        R.git(project, "config", "--local", key, value)
    R.commit_all(project, "Start")


def check(task, project):
    """Put the PR's test files in place (the agent's edits to them are discarded) and run them."""
    clone = P.ROOT / task["repo"] / "git"
    for path in task["tests"]:
        blob = subprocess.run(["git", "show", f"{task['merge']}:{path}"], cwd=clone, capture_output=True, check=True)
        (project / path).parent.mkdir(parents=True, exist_ok=True)
        (project / path).write_bytes(blob.stdout)
    ok, secs = P.run(task["lang"], task["repo"], project, task["tests"])
    return {"tests_pass": ok is True, "timed_out": ok is None, "secs": secs}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--task", "--seed", dest="task", type=int, required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--set", default=str(REFS / "replay.json"))
    a = ap.parse_args()
    task = json.loads(Path(a.set).read_text())["tasks"][a.task]
    where = ARMS / a.arm
    harness = B.harness_of(where)
    codex_home, home = where / "codex_home", where / "home"
    lang = LANG_OF[task["lang"]]
    python = python_of(lang) if lang else WORK / "r" / task["repo"] / "venv" / "bin" / "python"
    runs = RUNS / a.tag
    runs.mkdir(parents=True, exist_ok=True)
    box = PROJECTS / f"{a.tag}-{a.arm}-t{a.task}"
    project = box / task["repo"]
    if box.exists():
        shutil.rmtree(box)
    box.mkdir(parents=True)
    build(task, project)
    if lang:
        os.environ.update(lang_env(), GOCACHE=str(project / ".gocache"))
        os.environ["PATH"] = os.pathsep.join([str(bin_dir(lang)), str(python.parent), os.environ["PATH"]])
        if lang == "ts":
            (project / "node_modules").symlink_to(P.lang_rig.LANG / task["repo"] / "node_modules")
    else:
        os.environ["PYTHONPATH"] = str(project / "src") + os.pathsep + str(project)
    B.preflight(project, codex_home, home if home.is_dir() else None, python)
    out, error, started = runs / f"{a.arm}-t{a.task}.jsonl", None, time.time()
    ledger, tokens, model = [], B.usage.empty(), None
    thread = str(uuid.uuid4())
    try:
        if harness == B.claude.HARNESS:
            model = B.claude.MODEL
            B.claude_exec(project, where, python, CLAUDE_LEAD + task["prompt"], thread, False, out)
        elif harness == O.HARNESS:
            model = O.MODEL
            env = B.agent_env(project, where / "codex_unused", None, python)
            code = O.run(where, project, box / "omp-sessions", env, task["prompt"], False, out, B.STEP_TIMEOUT)
            if code != 0:
                raise B.StepError(f"omp exited {code}")
        else:
            model = B.MODEL
            B.codex_exec(project, codex_home, home if home.is_dir() else None, python, task["prompt"], None, out)
    except (B.StepError, subprocess.TimeoutExpired) as failure:
        error = str(failure)
    finally:
        # Read usage whether or not the session finished: a failed session's requests were paid for.
        if harness == B.claude.HARNESS:
            ledger = B.usage.claude_transcripts(B.claude_projects(), thread)
            tokens = B.usage.claude_transcript(ledger) if ledger else tokens
        elif harness == O.HARNESS:
            ledger = [out] if out.exists() else []
            tokens = O.usage(ledger) if ledger else tokens
        else:
            rollout = B.rollout_path(codex_home, (B.thread_of(B.events_of(out)) if out.exists() else None) or "")
            ledger = [rollout] if rollout else []
            tokens = B.usage.codex_rollout(rollout) if rollout else tokens
    checks = check(task, project)
    row = {
        "arm": a.arm, "harness": harness, "task": a.task, "repo": task["repo"], "lang": task["lang"],
        "pr": task["pr"], "tag": a.tag, "secs": round(time.time() - started), "model": model,
        "ledger": [str(p) for p in ledger], "tokens": tokens,
        "cost": B.usage.cost(tokens, model) if model else None, "error": error, "checks": checks,
        "passed": error is None and checks["tests_pass"],
    }
    with (runs / "results.jsonl").open("a") as f:
        f.write(json.dumps(row) + "\n")
    print(a.arm, a.task, task["repo"], task["pr"], "pass" if row["passed"] else "FAIL", flush=True)


if __name__ == "__main__":
    main()
