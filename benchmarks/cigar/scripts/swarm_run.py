"""Swarm set: one task that splits in three, done by one agent or by three cold agents.

Usage: swarm_run.py --arm <arm> --seed <n> --tag <tag> --mode one|cold|warm

The seed picks a Python repo and three independent pieces of work in it: two broken functions and
one stubbed function, each in its own file. All three are set up as teammate commits, then:
  one   one session gets a prompt listing the three pieces.
  cold  three fresh sessions, one piece each, one after another (agents that share nothing).
  warm  as cold, but each session after the first starts with a hand-off: for every earlier
        session, the piece it was given, the files it changed and the test suite's summary line
        after it finished (Track F's hand-off facts and shared test result, F4 and F5). The
        prompt hook still sends its note, so the launch brief (F1) adds nothing here.
Both are checked the same way: the full suite passes and the tests are unchanged. The row in
runs/<tag>/results.jsonl has the summed tokens and cost of every session. `warm` is that third arm,
built in the runner to test whether Swarm hand-offs would pay before building them in Guard.
"""

import argparse
import hashlib
import json
import random
import shutil
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as R
from rig import ARMS, PROJECTS, REPOS_DIR, RUNS, pool_path

B, O = R.B, R.O
HANDOFF = ("Other agents already worked on this project. Guard's record of what they did "
           "(their work is in the files now; do not redo it):\n")
JOINED = "Three separate pieces of work are needed in this project. Do all three:\n\n"


def snapshot(project):
    """Content hash of every tracked and untracked file, so a session's own edits show up even if
    the agent staged or committed them."""
    out = R.git(project, "ls-files", "-z", "-c", "-o", "--exclude-standard")
    names = [n for n in out.split("\0") if n]
    return {n: hashlib.sha1((project / n).read_bytes()).hexdigest() for n in names if (project / n).is_file()}


def plan(seed):
    rng = random.Random(f"swarm-{seed}")
    name = rng.choice(sorted(n for n, r in R.REPOS.items() if not r.get("heldout")))
    pool = json.loads(pool_path(name).read_text())
    paths, tasks = set(), []
    for kind, key in (("bug", "mutations"), ("bug", "mutations"), ("stub", "stubs")):
        fresh = [t for t in pool[key] if t["path"] not in paths]
        if not fresh:
            # Each piece must sit in its own file, or the three sessions would edit one file.
            raise SystemExit(f"swarm seed {seed}: {name} has no {key} entry in a file not already used")
        t = rng.choice(fresh)
        paths.add(t["path"])
        if kind == "bug":
            prompt = R.BUG_PROMPTS[2].format(qual=f"`{t['qual']}`")
            tasks.append({"kind": kind, "setup": [t], "prompt": prompt})
        else:
            tasks.append({"kind": kind, "stub": t, "prompt": R.STUB_PROMPTS[0].format(**t)})
    return name, pool, tasks


def session(harness, where, project, python, prompt, box, out, spent):
    """Run one fresh session. Its ledger paths and token totals go into `spent` (paths, tokens, model)
    even when the session fails or times out, so paid requests are never dropped from the row."""
    codex_home, home = where / "codex_home", where / "home"
    if harness == B.claude.HARNESS:
        thread = str(uuid.uuid4())
        try:
            B.claude_exec(project, where, python, prompt, thread, False, out)
        finally:
            ledger = B.usage.claude_transcripts(B.claude_projects(), thread)
            spent(ledger, B.usage.claude_transcript(ledger) if ledger else B.usage.empty(), B.claude.MODEL)
        return
    if harness == O.HARNESS:
        env = B.agent_env(project, where / "codex_unused", None, python)
        code = None
        try:
            code = O.run(where, project, box / f"omp-{out.stem}", env, prompt, False, out, B.STEP_TIMEOUT)
        finally:
            spent([out], O.usage([out]) if out.exists() else B.usage.empty(), O.MODEL)
        if code != 0:
            raise B.StepError(f"omp exited {code}")
        return
    try:
        B.codex_exec(project, codex_home, home if home.is_dir() else None, python, prompt, None, out)
    finally:
        thread = B.thread_of(B.events_of(out)) if out.exists() else None
        rollout = B.rollout_path(codex_home, thread or "")
        spent([rollout] if rollout else [], B.usage.codex_rollout(rollout) if rollout else B.usage.empty(), B.MODEL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--mode", choices=("one", "cold", "warm"), required=True)
    a = ap.parse_args()
    repo, pool, tasks = plan(a.seed)
    where = ARMS / a.arm
    harness = B.harness_of(where)
    python = REPOS_DIR / repo / "venv" / "bin" / "python"
    runs = RUNS / a.tag
    runs.mkdir(parents=True, exist_ok=True)
    box = PROJECTS / f"{a.tag}-{a.arm}-{a.mode}-s{a.seed}"
    project = box / repo
    if box.exists():
        shutil.rmtree(box)
    box.mkdir(parents=True)
    shutil.copytree(REPOS_DIR / repo / "pristine", project, symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    for key, value in R.AGENT_GIT_CONFIG:
        R.git(project, "config", "--local", key, value)
    codex_home, home = where / "codex_home", where / "home"
    B.preflight(project, codex_home, home if home.is_dir() else None, python)
    R.os.environ["PYTEST_ADDOPTS"] = " ".join(
        [f"--deselect '{d}'" for d in pool["deselect"]] + [f"--ignore '{i}'" for i in pool.get("ignore", [])])
    R.os.environ["PYTHONPATH"] = str(project / "src") + R.os.pathsep + str(project)
    since = R.git(project, "rev-parse", "HEAD").strip()
    error = None
    if not all(R.apply_setup(project, t) for t in tasks):
        error = "setup did not apply"
    prompts = [JOINED + "\n".join(f"{n}. {t['prompt']}" for n, t in enumerate(tasks, 1))]
    if a.mode != "one":
        prompts = [t["prompt"] for t in tasks]
    handoff = []
    ledger, tokens, model, started = [], B.usage.empty(), None, time.time()

    def spent(paths, used, used_model):
        nonlocal tokens, model
        ledger.extend(paths)
        tokens = {k: tokens[k] + used.get(k, 0) for k in tokens}
        model = used_model

    for n, prompt in enumerate(prompts if error is None else [], 1):
        if handoff:
            prompt = HANDOFF + "\n".join(handoff) + "\n\nYour piece:\n" + prompt
        before = snapshot(project)
        try:
            session(harness, where, project, python, prompt, box,
                    runs / f"{a.arm}-{a.mode}-s{a.seed}-{n}.jsonl", spent)
        except (B.StepError, R.subprocess.TimeoutExpired) as failure:
            error = f"session {n}: {failure}"
            break
        if a.mode == "warm":
            after = snapshot(project)
            changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
            handoff.append(f"- Agent {n} was given: {tasks[n - 1]['prompt'].splitlines()[0][:200]}\n"
                           f"  Files it changed: {', '.join(changed) or 'none'}\n"
                           f"  Test suite after it finished: {R.suite(python, project, repo, pool)}")
    suite = R.suite(python, project, repo, pool)
    unchanged = R.tests_unchanged(project, repo, since)
    row = {
        "arm": a.arm, "harness": harness, "mode": a.mode, "seed": a.seed, "repo": repo, "tag": a.tag,
        "kinds": [t["kind"] for t in tasks], "sessions": len(prompts), "secs": round(time.time() - started),
        "model": model, "ledger": [str(p) for p in ledger], "tokens": tokens,
        "cost": B.usage.cost(tokens, model) if model else None, "error": error,
        "checks": {"suite": suite, "tests_unchanged": unchanged},
        "passed": error is None and B.passed({"suite": suite}) and unchanged,
    }
    with (runs / "results.jsonl").open("a") as f:
        f.write(json.dumps(row) + "\n")
    print(a.arm, a.mode, a.seed, repo, "pass" if row["passed"] else "FAIL", row["cost"], flush=True)


if __name__ == "__main__":
    main()
