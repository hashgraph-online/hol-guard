"""Swarm set (F13): one task that splits in three, done by one agent or by three cold agents.

Usage: swarm_run.py --arm <arm> --seed <n> --tag <tag> --mode one|cold

The seed picks a Python repo and three independent pieces of work in it: two broken functions and
one stubbed function, each in its own file. All three are set up as teammate commits, then:
  one   one session gets a prompt listing the three pieces.
  cold  three fresh sessions, one piece each, one after another (agents that share nothing).
Both are checked the same way: the full suite passes and the tests are unchanged. The row in
runs/<tag>/results.jsonl has the summed tokens and cost of every session. The third arm (agents
launched with Guard's brief) needs Swarm's launch brief, which does not exist yet.
"""

import argparse
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
JOINED = "Three separate pieces of work are needed in this project. Do all three:\n\n"


def plan(seed):
    rng = random.Random(f"swarm-{seed}")
    name = rng.choice(sorted(n for n, r in R.REPOS.items() if not r.get("heldout")))
    pool = json.loads(pool_path(name).read_text())
    paths, tasks = set(), []
    for kind, key in (("bug", "mutations"), ("bug", "mutations"), ("stub", "stubs")):
        fresh = [t for t in pool[key] if t["path"] not in paths]
        t = rng.choice(fresh or pool[key])
        paths.add(t["path"])
        if kind == "bug":
            prompt = R.BUG_PROMPTS[2].format(qual=f"`{t['qual']}`")
            tasks.append({"kind": kind, "setup": [t], "prompt": prompt})
        else:
            tasks.append({"kind": kind, "stub": t, "prompt": R.STUB_PROMPTS[0].format(**t)})
    return name, pool, tasks


def session(harness, where, project, python, prompt, box, out):
    """Run one fresh session; return its ledger paths and token totals."""
    codex_home, home = where / "codex_home", where / "home"
    if harness == B.claude.HARNESS:
        thread = str(uuid.uuid4())
        B.claude_exec(project, where, python, prompt, thread, False, out)
        ledger = B.usage.claude_transcripts(B.claude_projects(), thread)
        return ledger, B.usage.claude_transcript(ledger) if ledger else B.usage.empty(), B.claude.MODEL
    if harness == O.HARNESS:
        env = B.agent_env(project, where / "codex_unused", None, python)
        code = O.run(where, project, box / f"omp-{out.stem}", env, prompt, False, out, B.STEP_TIMEOUT)
        if code != 0:
            raise B.StepError(f"omp exited {code}")
        return [out], O.usage([out]), O.MODEL
    B.codex_exec(project, codex_home, home if home.is_dir() else None, python, prompt, None, out)
    rollout = B.rollout_path(codex_home, B.thread_of(B.events_of(out)) or "")
    return ([rollout] if rollout else []), (B.usage.codex_rollout(rollout) if rollout else B.usage.empty()), B.MODEL


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--mode", choices=("one", "cold"), required=True)
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
    if a.mode == "cold":
        prompts = [t["prompt"] for t in tasks]
    ledger, tokens, model, started = [], B.usage.empty(), None, time.time()
    for n, prompt in enumerate(prompts if error is None else [], 1):
        try:
            paths, used, model = session(harness, where, project, python, prompt, box,
                                         runs / f"{a.arm}-{a.mode}-s{a.seed}-{n}.jsonl")
        except (B.StepError, R.subprocess.TimeoutExpired) as failure:
            error = f"session {n}: {failure}"
            break
        ledger += paths
        tokens = {k: tokens[k] + used.get(k, 0) for k in tokens}
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
