"""One language-set session: seeded bug steps on a pinned Go, Rust or TypeScript repo, in one agent session.

Usage: lang_run.py --arm <arm> --seed <n> --tag <tag> --lang <go|rust|ts>
Steps: bug, bug, bug2, bug, review (the Python set's bug and review prompts, unchanged). A step passes
when the language's whole suite passes in the agent's sandbox and a fix step left the tests unchanged. Results go
to the same results.jsonl rows as run.py, so report.py reads them; run one tag per language.
Pools come from lang_prep.py; repos from lang_setup.sh.
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as R
from lang_rig import LANG, LANGS, lang_env, project_env, python_of, run_tests
from rig import ARMS, PROJECTS, REFS, RUNS

B, O = R.B, R.O
KINDS = ["bug", "bug", "bug2", "bug"]


def plan(seed, lang):
    pool = json.loads((REFS / "pools" / f"lang-{lang}.json").read_text())
    rng = random.Random(f"lang-{lang}-{seed}")
    order = list(range(len(pool["mutations"])))
    rng.shuffle(order)
    picked, files = [], set()
    # Each bug sits in its own function; a second pass allows a file already used.
    for avoid in (True, False):
        for i in order:
            m = pool["mutations"][i]
            if i in picked or (avoid and m["path"] in files) or any(pool["mutations"][j]["qual"] == m["qual"] for j in picked):
                continue
            picked.append(i)
            files.add(m["path"])
    muts = [pool["mutations"][i] for i in picked]
    tasks = []
    for k in KINDS:
        if k == "bug":
            m = muts.pop(0)
            p = rng.choice(R.BUG_PROMPTS)
            # ufo has a test named with a null byte, which no command line can carry.
            test = next((f for f in m["failing"] if f.isprintable()), m["failing"][0])
            tasks.append({"kind": k, "setup": [m], "prompt": p.format(test=f"`{test}`", qual=f"`{m['qual']}`")})
        else:
            tasks.append({"kind": k, "setup": [muts.pop(0), muts.pop(0)], "prompt": R.BUG2_PROMPT})
    tasks.append({"kind": "review", "prompt": R.REVIEW_PROMPT})
    return pool["repo"], tasks


def check(lang, project, task, since):
    code, out = run_tests(lang, project, sandbox_home=PROJECTS.parent / "sandbox_home")
    res = {"suite": "pass" if code == 0 else f"exit status {code}: {out.strip().splitlines()[-1] if out.strip() else ''}"[:200]}
    ok = code == 0
    # The review step's prompt asks the agent to tidy every change in the session, tests included,
    # so only fix steps must leave the tests alone; the review must still leave the suite passing.
    if task["kind"] != "review":
        res["tests_unchanged"] = not R.git(project, "diff", "--stat", since, "--", *LANGS[lang]["tests"]).strip()
        ok = ok and res["tests_unchanged"]
    res["ok"] = ok
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--lang", required=True, choices=sorted(LANGS))
    a = ap.parse_args()
    repo, tasks = plan(a.seed, a.lang)
    where = ARMS / a.arm
    harness = B.harness_of(where)
    codex_home, home = where / "codex_home", where / "home"
    python = python_of(a.lang)
    runs = RUNS / a.tag
    box = PROJECTS / f"{a.tag}-{a.arm}-s{a.seed}"
    project = box / repo
    if box.exists():
        subprocess.run(["rm", "-rf", str(box)], check=True)
    box.mkdir(parents=True)
    # A copy-on-write clone: the TypeScript repo carries its installed node_modules.
    subprocess.run(["cp", "-cR", str(LANG / repo), str(project)], check=True)
    for key, value in R.AGENT_GIT_CONFIG:
        R.git(project, "config", "--local", key, value)
    os.environ.update(lang_env(), **project_env(project))
    os.environ["PATH"] = str(python.parent) + os.pathsep + os.environ["PATH"]
    B.preflight(project, codex_home, home if home.is_dir() else None, python)
    runs.mkdir(parents=True, exist_ok=True)
    thread = str(uuid.uuid4()) if harness == B.claude.HARNESS else None
    steps, error, started, omp_outs = [], None, time.time(), []
    for n, task in enumerate(tasks, 1):
        if task["kind"] in ("bug", "bug2"):
            R.commit_all(project, f"work through step {n - 1}")
        since = R.git(project, "rev-parse", "HEAD").strip()
        if not R.apply_setup(project, task):
            error = f"step {n}: setup did not apply"
            break
        out = runs / f"{a.arm}-s{a.seed}-{n}.jsonl"
        at = time.time()
        try:
            if harness == B.claude.HARNESS:
                B.claude_exec(project, where, python, task["prompt"], thread, n > 1, out)
            elif harness == O.HARNESS:
                thread = thread or str(box / "omp-sessions")
                base_env = B.agent_env(project, where / "codex_unused", None, python)
                try:
                    code = O.run(where, project, Path(thread), base_env, task["prompt"], n > 1, out, B.STEP_TIMEOUT)
                except subprocess.TimeoutExpired as failure:
                    raise B.StepError(f"omp timed out after {B.STEP_TIMEOUT}s") from failure
                omp_outs.append(out)
                if code != 0:
                    raise B.StepError(f"omp exited {code}; see {out.with_suffix('.err')}")
            else:
                B.codex_exec(project, codex_home, home if home.is_dir() else None, python, task["prompt"], thread, out)
                thread = thread or B.thread_of(B.events_of(out))
        except B.StepError as failure:
            error = f"step {n}: {failure}"
            print(a.arm, a.seed, n, "FAIL", error, flush=True)
            break
        res = check(a.lang, project, task, since)
        steps.append({"step": n, "kind": task["kind"], "secs": round(time.time() - at), "checks": res, "passed": res["ok"]})
        print(a.arm, a.seed, repo, n, task["kind"], "pass" if res["ok"] else "FAIL", json.dumps(res)[:200], flush=True)
    if harness == B.claude.HARNESS:
        model, ledger = B.claude.MODEL, B.usage.claude_transcripts(B.claude_projects(), thread)
        tokens = B.usage.claude_transcript(ledger) if ledger else B.usage.empty()
    elif harness == O.HARNESS:
        model, ledger, tokens = O.MODEL, omp_outs, O.usage(omp_outs)
    else:
        model = B.MODEL
        rollout = B.rollout_path(codex_home, thread) if thread else None
        ledger = [rollout] if rollout else []
        tokens = B.usage.codex_rollout(rollout) if rollout else B.usage.empty()
    row = {
        "arm": a.arm,
        "harness": harness,
        "seed": a.seed,
        "repo": repo,
        "lang": a.lang,
        "kinds": [t["kind"] for t in tasks],
        "thread": thread,
        "secs": round(time.time() - started),
        "model": model,
        "ledger": [str(p) for p in ledger],
        "tokens": tokens,
        "cost": B.usage.cost(tokens, model),
        "steps": steps,
        "error": error,
        "passed": error is None and len(steps) == len(tasks) and all(s["passed"] for s in steps),
        "tag": a.tag,
    }
    with (runs / "results.jsonl").open("a") as f:
        f.write(json.dumps(row) + "\n")
    print(a.arm, a.seed, repo, "DONE", "pass" if row["passed"] else "FAIL", row["cost"], flush=True)


if __name__ == "__main__":
    main()
