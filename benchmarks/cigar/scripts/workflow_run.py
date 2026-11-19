"""One workflow-set session: the chores around a fix, in one agent session.

Usage: workflow_run.py --arm <arm> --seed <n> --tag <tag>
Steps: bug (the Python set's bug step), changelog, dependency, build. The repo is one of the flit-built
Python repos (workflow_setup.sh puts flit_core in their venvs, so a wheel builds with no network).
Results go to the same results.jsonl rows as run.py, so report.py reads them.
"""

import argparse
import collections
import json
import os
import random
import re
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as R
from rig import ARMS, PROJECTS, REPOS_DIR, RUNS

B, O = R.B, R.O
WORKFLOW_REPOS = ["boltons", "click", "jinja", "moreit", "tomli"]
DEPENDENCY = "typing_extensions"
# Not a commit: Codex's sandbox keeps `.git` read-only, so a commit step would fail on every Codex arm.
CHANGELOG_PROMPT = (
    "Add an entry for this fix to the project's changelog, in the style of the entries already there "
    "(create CHANGELOG.md if the project has none)."
)
CHANGELOG = ("CHANGELOG", "CHANGES", "HISTORY", "NEWS")
DEPENDENCY_PROMPT = (
    f"This package is about to start using `{DEPENDENCY}` at runtime (version 4.0 or newer). "
    "Declare that in the package metadata. Don't install anything; there is no network."
)
BUILD_PROMPT = (
    "Build a wheel of this package into `dist/`. There is no network, so build with what is "
    "already installed. Don't commit the build output."
)


def plan(seed):
    rng = random.Random(f"workflow-{seed}")
    repo = rng.choice(WORKFLOW_REPOS)
    _, pool, tasks = R.plan(seed, 6, repo, frozen=False)
    bug = next((t for t in tasks if t["kind"] == "bug"), None)
    if bug is None:
        m = rng.choice(pool["mutations"])
        bug = {
            "kind": "bug",
            "setup": [m],
            "prompt": rng.choice(R.BUG_PROMPTS).format(test="`" + m["failing"][0] + "`", qual=f"`{m['qual']}`"),
        }
    return (
        repo,
        pool,
        [
            bug,
            {"kind": "changelog", "prompt": CHANGELOG_PROMPT},
            {"kind": "dependency", "prompt": DEPENDENCY_PROMPT},
            {"kind": "build", "prompt": BUILD_PROMPT},
        ],
    )


REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)(?:;(.*))?$")
CLAUSE = re.compile(r"^\s*(~=|==|!=|>=|<=|>|<)\s*([0-9][0-9.]*)(\.\*)?\s*$")


def version(text):
    return tuple(int(part) for part in text.split(".") if part)


def admits_minimum(spec, minimum=(4,)):
    """True when the version range allows the minimum's line and excludes everything older."""
    clauses = [c for c in spec.split(",") if c.strip()]
    if not clauses:
        return False
    floor = False
    for clause in clauses:
        m = CLAUSE.match(clause)
        if not m:
            return False
        op, v = m.group(1), version(m.group(2))
        if op in (">=", "~=", "==") and v >= minimum:
            floor = True
        elif op == ">" and v >= minimum:
            floor = True
        elif op in ("<", "<=") and v <= minimum:
            return False
    return floor


def declared(project):
    """True when pyproject.toml parses and lists the new runtime dependency at 4.0 or newer.

    A declaration with an environment marker does not count: the step asks for an
    unconditional runtime dependency, and a marker can leave it out on the grader's Python.
    """
    try:
        meta = tomllib.loads((project / "pyproject.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return False
    deps = meta.get("project", {}).get("dependencies", []) if isinstance(meta.get("project"), dict) else []
    if not isinstance(deps, list):
        return False
    for dep in deps:
        m = REQUIREMENT.match(dep) if isinstance(dep, str) else None
        if not m or (m.group(3) or "").strip():
            continue
        if re.sub(r"[-_.]+", "_", m.group(1)).lower() == DEPENDENCY and admits_minimum(m.group(2)):
            return True
    return False


def changelogs(project):
    """Changelog files at the project root and their lines, read before a step."""
    return {
        f.name: f.read_text(errors="replace").splitlines()
        for f in project.iterdir()
        if f.is_file() and f.name.upper().startswith(CHANGELOG)
    }


def logged(project, before):
    """The root changelog file that gained a non-blank line during the step."""
    for name, lines in changelogs(project).items():
        added = collections.Counter(line for line in lines if line.strip())
        added.subtract(line for line in before.get(name, []) if line.strip())
        if any(n > 0 for n in added.values()):
            return name
    return None


def wheel_ok(project, repo):
    pkg = R.REPOS[repo]["src"].split("/")[-1]
    for whl in (project / "dist").glob("*.whl"):
        try:
            names = zipfile.ZipFile(whl).namelist()
        except zipfile.BadZipFile:
            continue
        if any(n.startswith(f"{pkg}/") and n.endswith(".py") for n in names):
            return whl.name
    return None


def check(python, project, repo, pool, task, since, notes):
    k = task["kind"]
    res = {"suite": R.suite(python, project, repo, pool)}
    ok = B.passed({"suite": res["suite"]})
    if k == "bug":
        res["tests_unchanged"] = R.tests_unchanged(project, repo, since)
        ok = ok and res["tests_unchanged"]
    elif k == "changelog":
        res["changelog"] = logged(project, notes)
        ok = ok and bool(res["changelog"])
    elif k == "dependency":
        res["declared"] = declared(project)
        ok = ok and res["declared"]
    elif k == "build":
        res["wheel"] = wheel_ok(project, repo)
        res["dist_untracked"] = not R.git(project, "ls-files", "dist").strip()
        ok = ok and bool(res["wheel"]) and res["dist_untracked"]
    res["ok"] = bool(ok)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--tag", required=True)
    a = ap.parse_args()
    repo, pool, tasks = plan(a.seed)
    where = ARMS / a.arm
    harness = B.harness_of(where)
    codex_home, home = where / "codex_home", where / "home"
    python = REPOS_DIR / repo / "venv" / "bin" / "python"
    runs = RUNS / a.tag
    box = PROJECTS / f"{a.tag}-{a.arm}-s{a.seed}"
    project = box / repo
    if box.exists():
        subprocess.run(["rm", "-rf", str(box)], check=True)
    box.mkdir(parents=True)
    subprocess.run(["cp", "-cR", str(REPOS_DIR / repo / "pristine"), str(project)], check=True)
    subprocess.run(
        ["find", str(project), "-name", "__pycache__", "-prune", "-exec", "rm", "-rf", "{}", "+"], check=True
    )
    with (project / ".git" / "info" / "exclude").open("a") as f:
        # The grader's own test runs leave caches; only the agent's work counts toward "clean".
        f.write(".vs_accept/\n.pytest_cache/\n__pycache__/\n")
    for key, value in R.AGENT_GIT_CONFIG:
        R.git(project, "config", "--local", key, value)
    B.preflight(project, codex_home, home if home.is_dir() else None, python)
    os.environ["PYTEST_ADDOPTS"] = " ".join(
        [f"--deselect '{d}'" for d in pool["deselect"]] + [f"--ignore '{i}'" for i in pool.get("ignore", [])]
    )
    os.environ["PYTHONPATH"] = str(project / "src") + os.pathsep + str(project)
    runs.mkdir(parents=True, exist_ok=True)
    thread = str(uuid.uuid4()) if harness == B.claude.HARNESS else None
    steps, error, started, omp_outs = [], None, time.time(), []
    for n, task in enumerate(tasks, 1):
        if task["kind"] == "bug":
            R.commit_all(project, f"work through step {n - 1}")
        since = R.git(project, "rev-parse", "HEAD").strip()
        if not R.apply_setup(project, task):
            error = f"step {n}: setup did not apply"
            break
        if task["kind"] == "bug":
            since = R.git(project, "rev-parse", "HEAD").strip()
        notes = changelogs(project)
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
                finally:
                    # A step that times out has still paid for the requests it streamed.
                    if out.exists():
                        omp_outs.append(out)
                if code != 0:
                    raise B.StepError(f"omp exited {code}; see {out.with_suffix('.err')}")
            else:
                B.codex_exec(project, codex_home, home if home.is_dir() else None, python, task["prompt"], thread, out)
                thread = thread or B.thread_of(B.events_of(out))
        except B.StepError as failure:
            if harness not in (B.claude.HARNESS, O.HARNESS) and not thread and out.exists():
                # A first step that fails after it started a thread has still paid for its requests.
                try:
                    thread = B.thread_of(B.events_of(out))
                except ValueError:
                    pass
            error = f"step {n}: {failure}"
            print(a.arm, a.seed, n, "FAIL", error, flush=True)
            break
        res = check(python, project, repo, pool, task, since, notes)
        steps.append(
            {"step": n, "kind": task["kind"], "secs": round(time.time() - at), "checks": res, "passed": res["ok"]}
        )
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
        "set": "workflow",
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
