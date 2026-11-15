"""One varied CIGAR session: a seeded random chain of tasks on a pinned repo, in one resumed agent session.

Usage: run.py --arm <arm> --seed <n> --tag <tag> [--repo name] [--steps 6]
The same seed gives the same repo, tasks and targets on every arm, so arms pair up by seed.
Arms live in $CIGAR_GAUNTLET_WORK/arms/<arm> (codex_home, or a `harness` marker plus claude_settings.json).
Keep the prompts and checks as they are: the stored baseline was measured with exactly these.
"""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import ARMS, GUARD_SRC, PROJECTS, REFS, REPOS_DIR, RUNS, pool_path

sys.path.insert(0, str(GUARD_SRC / "scripts"))
import bench_guard_cigar_long_task as B
import omp_exec as O

# Agents see plain test and tool output, as from an agent started in an ordinary terminal: a
# forced-color setting in the operator's shell would pad every result with escape codes.
for _name in ("FORCE_COLOR", "CLICOLOR_FORCE", "PY_COLORS"):
    os.environ.pop(_name, None)
# Agents commit as a plain user would: a name and nothing else from the operator's Git setup,
# whose identity wrapper, commit hooks and signing key the agent's sandbox cannot use. With them
# every commit failed and the agent retried it a dozen ways, in either arm.
os.environ["HOL_SKIP_GITHUB_IDENTITY_HOOKS"] = "1"
_gitconfig = Path(os.environ.get("CIGAR_GAUNTLET_WORK", "/tmp/cigar-gauntlet")).resolve() / "gitconfig"
_gitconfig.parent.mkdir(parents=True, exist_ok=True)
_gitconfig.write_text("[user]\n\tname = dev\n\temail = dev@example.test\n")
# The rig's own Git calls read only that file. Agents get the same settings from each project's
# local config instead (see AGENT_GIT_CONFIG): an exported GIT_CONFIG_GLOBAL, even /dev/null, is
# a configuration Guard's hook cannot see, so with it Guard holds every git status, log and diff.
os.environ.pop("GIT_CONFIG_GLOBAL", None)
AGENT_GIT_CONFIG = [
    ("user.name", "dev"),
    ("user.email", "dev@example.test"),
    ("commit.gpgsign", "false"),
    ("tag.gpgsign", "false"),
]
# No core.hooksPath=/dev/null here: Guard's sandbox only accepts a hooks folder inside the project or
# under HOME, so with it Guard held every git add, rm and script in the repo. The repos carry only
# Git's sample hooks, which never run.

REPOS = json.loads((REFS / "repos.json").read_text())
GIT_ENV = dict(
    GIT_AUTHOR_NAME="teammate",
    GIT_AUTHOR_EMAIL="teammate@example.test",
    GIT_COMMITTER_NAME="teammate",
    GIT_COMMITTER_EMAIL="teammate@example.test",
)

BUG_PROMPTS = [
    "A teammate just pushed a commit and now some tests fail. Find the root cause in the library code and fix it without changing the tests.",
    "{test} started failing after the last commit. Fix the bug in the library code; don't edit the tests.",
    "Something in {qual} broke recently and its tests fail now. Track it down and fix it. Leave the tests alone.",
]
BUG2_PROMPT = "The last commit broke several tests in different places. Find every root cause in the library code and fix them all without changing the tests."
STUB_PROMPTS = [
    "`{qual}` in {path} was stubbed out during a refactor and now raises NotImplementedError. Implement it again so it does what its docstring says and the existing tests pass.",
    "Tests fail because {qual} is not implemented ({path}). Write the implementation; the docstring and tests describe the expected behavior.",
]
RENAME_PROMPT = "Rename the internal helper `{old}` to `{new}` everywhere in the project, including tests. Behavior must not change."
DOC_PROMPT = "Add a short usage example to the docstring of `{qual}` in {path}, written as a doctest (`>>>` lines with their expected output). Make sure the example actually passes."
QUESTION_PROMPT = (
    'Question, no code changes: which function does this? "{sentence}" Reply with its file path and function name.'
)
REVIEW_PROMPT = "Review every change made in this session. Remove leftovers or duplication, match the style of the surrounding code, and make sure the full test suite passes."
# Held-out seeds (>= HELDOUT_SEED) run only on repos marked "heldout" and phrase every task in loose,
# unbenchmarked wording, so a result there cannot come from tuning to the prompts above.
HELDOUT_SEED = 200
FREEFORM = {
    "bug": [
        "tests are red on main since the last push, can you sort it out? don't touch the tests",
        "ci is failing, looks like {test} -- please fix whatever broke (library code only)",
        "hey, {qual} seems busted after yesterday's change. mind taking a look and fixing it? tests should stay as they are",
    ],
    "bug2": [
        "a bunch of tests started failing after the last commit, probably more than one thing broke. fix the code so they all pass again, leave tests alone"
    ],
    "stub": [
        "someone left {qual} as a NotImplementedError stub in {path}. fill it in please, the tests and docstring say what it should do",
        "{path}: {qual} isn't implemented anymore and things are failing. bring it back",
    ],
    "rename": ["can you rename `{old}` to `{new}`? it's used in a few places incl. tests. no behavior change"],
    "doc": [
        "the docstring for `{qual}` ({path}) could use a small doctest example. add one and check it actually runs"
    ],
    "question": [
        'quick q, don\'t change anything: where is the code that does this -- "{sentence}"? tell me the file and function name'
    ],
    "review": [
        "ok, last thing: look over everything you changed today, clean up anything leftover or duplicated, keep the style consistent, and run the whole test suite to make sure it's green"
    ],
}


def git(project, *args, env=None):
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
        env=dict(os.environ, GIT_CONFIG_GLOBAL=str(_gitconfig), **(env or {})),
    ).stdout


def commit_all(project, message):
    git(project, "add", "-A")
    if git(project, "status", "--porcelain").strip():
        git(project, "commit", "-q", "-m", message, env=GIT_ENV)


def plan(seed, steps, repo=None, frozen=True):
    # A frozen plan (export_plans.py) is the record any runner replays; the RNG below only makes new ones.
    saved = REFS / "plans" / f"s{seed}.json"
    if frozen and repo is None and steps == 6 and saved.exists():
        doc = json.loads(saved.read_text())
        return doc["repo"], json.loads(pool_path(doc["repo"]).read_text()), doc["steps"]
    rng = random.Random(seed)
    heldout = seed >= HELDOUT_SEED
    name = repo or rng.choice(sorted(n for n, r in REPOS.items() if bool(r.get("heldout")) == heldout))
    pool = json.loads(pool_path(name).read_text())
    kinds = ["bug", "bug", "bug2", "stub", "rename", "doc", "question"]
    picks = []
    while len(picks) < steps - 1:
        k = rng.choice(kinds)
        if k == "question" and "question" in picks:
            continue
        if k == "bug2" and len(pool["mutations"]) < 2:
            continue
        key = {
            "bug": "mutations",
            "bug2": "mutations",
            "stub": "stubs",
            "rename": "renames",
            "doc": "docs",
            "question": "questions",
        }[k]
        # Each step takes its own target: never plan more of a kind than the pool holds.
        wanted = sum(
            {"bug": 1, "bug2": 2}.get(p, 1)
            for p in picks + [k]
            if {"bug": "mutations", "bug2": "mutations"}.get(p, p + "s") == key
        )
        if wanted > len(pool[key]):
            continue
        picks.append(k)
    if not any(k in ("bug", "bug2") for k in picks):
        picks[rng.randrange(len(picks))] = "bug"
    used = {"mutations": set(), "stubs": set(), "renames": set(), "docs": set(), "questions": set()}
    touched = set()

    taken = set()

    def take(key, avoid_paths=True):
        # A pool can list one mutation twice; the same target is never set up twice.
        sig = lambda t: (key, t.get("path"), t.get("line"), t.get("orig"), t.get("qual"), t.get("old"))
        fresh = [i for i, t in enumerate(pool[key]) if i not in used[key] and sig(t) not in taken]
        items = [i for i in fresh if not (avoid_paths and pool[key][i].get("path") in touched)] or fresh
        if not items:
            items = [i for i, t in enumerate(pool[key]) if i not in used[key]]
        i = rng.choice(items)
        used[key].add(i)
        taken.add(sig(pool[key][i]))
        touched.add(pool[key][i].get("path"))
        return pool[key][i]

    tasks = []
    for k in picks:
        if k == "bug":
            m = take("mutations")
            p = rng.choice(BUG_PROMPTS)
            tasks.append(
                {"kind": k, "setup": [m], "prompt": p.format(test="`" + m["failing"][0] + "`", qual=f"`{m['qual']}`")}
            )
        elif k == "bug2":
            a = take("mutations")
            b = take("mutations")
            tasks.append({"kind": k, "setup": [a, b], "prompt": BUG2_PROMPT})
        elif k == "stub":
            s = take("stubs")
            tasks.append({"kind": k, "stub": s, "prompt": rng.choice(STUB_PROMPTS).format(**s)})
        elif k == "rename":
            r = take("renames", avoid_paths=False)
            tasks.append({"kind": k, "rename": r, "prompt": RENAME_PROMPT.format(**r)})
        elif k == "doc":
            d = take("docs")
            tasks.append({"kind": k, "doc": d, "prompt": DOC_PROMPT.format(**d)})
        elif k == "question":
            q = take("questions", avoid_paths=False)
            tasks.append({"kind": k, "question": q, "prompt": QUESTION_PROMPT.format(**q)})
    tasks.append({"kind": "review", "prompt": REVIEW_PROMPT})
    if heldout:
        prng = random.Random(f"freeform-{seed}")
        for t in tasks:
            fields = {
                "bug": lambda: {"test": "`" + t["setup"][0]["failing"][0] + "`", "qual": f"`{t['setup'][0]['qual']}`"},
                "stub": lambda: t["stub"],
                "rename": lambda: t["rename"],
                "doc": lambda: t["doc"],
                "question": lambda: t["question"],
            }.get(t["kind"], dict)()
            t["prompt"] = prng.choice(FREEFORM[t["kind"]]).format(**fields)
    return name, pool, tasks


def apply_setup(project, task):
    """Change the tree before a step (the teammate's commit). Returns False if it cannot apply cleanly."""
    if task["kind"] in ("bug", "bug2"):
        for m in task["setup"]:
            f = project / m["path"]
            text = f.read_text()
            if text.count(m["orig"]) != 1:
                return False
            f.write_text(text.replace(m["orig"], m["new"], 1))
        commit_all(project, "Tidy up conditions" if task["kind"] == "bug" else "Small cleanups")
    elif task["kind"] == "stub":
        s = task["stub"]
        f = project / s["path"]
        text = f.read_text()
        # Classes can share a body word for word (cachetools' FIFO, LRU and MRU popitem); take the copy
        # nearest the stub's recorded line.
        starts, at = [], text.find(s["body"])
        while at != -1:
            starts.append(at)
            at = text.find(s["body"], at + 1)
        if not starts:
            return False
        at = min(starts, key=lambda o: abs(text.count("\n", 0, o) + 1 - s["body_start"]))
        f.write_text(text[:at] + " " * s["indent"] + "raise NotImplementedError\n" + text[at + len(s["body"]) :])
        commit_all(project, f"Drop old {s['qual'].split('.')[-1]} implementation for rewrite")
    return True


def sandbox_py(python, project, code, timeout=300):
    home = PROJECTS.parent / "sandbox_home"
    home.mkdir(exist_ok=True)
    done = subprocess.run(
        B.sandboxed([str(python), "-c", code]),
        cwd=project,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=dict(os.environ, PYTHONPATH=str(project / "src") + os.pathsep + str(project), CODEX_HOME=str(home)),
    )
    return done.returncode, (done.stdout + done.stderr)[-400:]


def suite(python, project, repo, pool):
    args = [REPOS[repo]["tests"]]
    for d in pool["deselect"]:
        args += ["--deselect", d]
    # The grader reads the last line of the output. A SyntaxWarning printed while a module is
    # compiled (pluggy's `return` in `finally` on Python 3.14) comes after pytest's summary, so
    # the first run after a module changes read as a failure. Only for the grader's run.
    before = os.environ.get("PYTHONWARNINGS")
    os.environ["PYTHONWARNINGS"] = "ignore::SyntaxWarning"
    try:
        return B.pytest_tail(python, project, *args)
    finally:
        if before is None:
            os.environ.pop("PYTHONWARNINGS")
        else:
            os.environ["PYTHONWARNINGS"] = before


def tests_unchanged(project, repo, since):
    t = REPOS[repo]["tests"]
    return not git(project, "diff", "--stat", since, "--", t, *([] if t == "tests" else [])).strip()


def check(python, project, repo, pool, task, before_tree, answer, since):
    res = {"suite": suite(python, project, repo, pool)}
    ok = B.passed({"suite": res["suite"]})
    k = task["kind"]
    if k in ("bug", "bug2", "stub"):
        res["tests_unchanged"] = tests_unchanged(project, repo, since)
        ok = ok and res["tests_unchanged"]
    elif k == "rename":
        r = task["rename"]
        left, found = 0, 0
        for p in project.rglob("*.py"):
            if ".vs_" in str(p):
                continue
            t = p.read_text(errors="replace")
            left += len(re.findall(rf"\b{re.escape(r['old'])}\b", t))
            found += len(re.findall(rf"\b{re.escape(r['new'])}\b", t))
        res["rename"] = {"left": left, "new": found, "want": r["count"]}
        ok = ok and left == 0 and found >= r["count"]
    elif k == "doc":
        d = task["doc"]
        mod, qual = d["module"], d["qual"]
        code = (
            "import doctest,importlib,sys\n"
            f"m=importlib.import_module({mod!r})\n"
            f"o=m\nfor p in {qual!r}.split('.'): o=getattr(o,p)\n"
            "o=getattr(o,'__wrapped__',o)\n"
            "ts=doctest.DocTestFinder(recurse=False).find(o, globs=dict(vars(m)))\n"
            "n=sum(len(t.examples) for t in ts)\n"
            "r=doctest.DocTestRunner(optionflags=doctest.ELLIPSIS|doctest.NORMALIZE_WHITESPACE)\n"
            "[r.run(t, out=lambda s: None) for t in ts]\n"
            "print('EX',n,'FAIL',r.failures)\n"
            "sys.exit(0 if n and not r.failures else 1)\n"
        )
        rc, out = sandbox_py(python, project, code)
        res["doctest"] = out.strip().splitlines()[-1] if out.strip() else f"rc {rc}"
        ok = ok and rc == 0
    elif k == "question":
        q = task["question"]
        res["answer_has_name"] = bool(answer and re.search(rf"\b{re.escape(q['name'])}\b", answer))
        res["tree_unchanged"] = tree_hash(project) == before_tree
        ok = ok and res["answer_has_name"] and res["tree_unchanged"]
    res["ok"] = bool(ok)
    return res


def rename_hint(project, r):
    files = sorted(
        str(p.relative_to(project))
        for p in project.rglob("*.py")
        if ".vs_" not in str(p) and re.search(rf"\b{re.escape(r['old'])}\b", p.read_text(errors="replace"))
    )
    tests = [f for f in files if "test" in Path(f).name]
    cmd = f"perl -pi -e 's/\\b{r['old']}\\b/{r['new']}/g' {' '.join(files)}"
    if tests:
        cmd += f" && python -m pytest -q {' '.join(tests)}"
    return (
        f"\n\nOne Bash call makes this whole rename (every file naming `{r['old']}` as a word) "
        f"and runs its tests:\n{cmd}"
    )


def tree_hash(project):
    # HEAD is in the hash too: an edit committed during the step leaves status and diff empty.
    state = git(project, "rev-parse", "HEAD") + git(project, "status", "--porcelain") + git(project, "diff", "HEAD")
    return hashlib.sha256(state.encode()).hexdigest()


def final_message(out):
    msg = None
    for e in B.events_of(out):
        item = e.get("item") or {}
        if e.get("type") == "item.completed" and item.get("type") == "agent_message":
            msg = item.get("text")
    return msg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--repo")
    ap.add_argument("--steps", type=int, default=6)
    ap.add_argument("--tag", required=True)
    a = ap.parse_args()
    repo, pool, tasks = plan(a.seed, a.steps, a.repo)
    # Probes only: CIGAR_GAUNTLET_KINDS keeps just those step kinds; CIGAR_GAUNTLET_RENAME_HINT=1
    # appends a ready one-command rename to rename prompts, to test a note text before building it.
    only = os.environ.get("CIGAR_GAUNTLET_KINDS")
    if only:
        tasks = [t for t in tasks if t["kind"] in only.split(",")]
    where = ARMS / a.arm
    harness = B.harness_of(where)
    codex_home, home = where / "codex_home", where / "home"
    python = REPOS_DIR / repo / "venv" / "bin" / "python"
    runs = RUNS / a.tag
    # Each run's folder holds only its project, so an agent searching `..` finds no other run's
    # work to copy.
    box = PROJECTS / f"{a.tag}-{a.arm}-s{a.seed}"
    project = box / repo
    if box.exists():
        shutil.rmtree(box)
    box.mkdir(parents=True)
    shutil.copytree(
        REPOS_DIR / repo / "pristine",
        project,
        symlinks=True,
        # Bytecode compiled in the pristine copy names its paths, so an assertion
        # on a code object's file name fails in the copy.
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    with (project / ".git" / "info" / "exclude").open("a") as f:
        f.write(".vs_accept/\n")
    for key, value in AGENT_GIT_CONFIG:
        git(project, "config", "--local", key, value)
    B.preflight(project, codex_home, home if home.is_dir() else None, python)
    # Tests that fail on the pristine checkout in this Python stay out of every run, so the suite starts green.
    # A pool's `ignore` keeps out test files that fetch from the network (toolz's bench downloads a
    # text with wget), which the sandbox cannot reach and the task never asks for.
    os.environ["PYTEST_ADDOPTS"] = " ".join(
        [f"--deselect '{d}'" for d in pool["deselect"]] + [f"--ignore '{i}'" for i in pool.get("ignore", [])]
    )
    # The agent imports the code it edits, as the grader does: the repo venv also holds a released
    # copy of some packages (pytest itself pulls in pluggy), which would otherwise shadow the work tree.
    os.environ["PYTHONPATH"] = str(project / "src") + os.pathsep + str(project)
    runs.mkdir(parents=True, exist_ok=True)
    thread = str(uuid.uuid4()) if harness == B.claude.HARNESS else None
    steps, events, error, started = [], [], None, time.time()
    omp_outs = []
    for n, task in enumerate(tasks, 1):
        if task["kind"] in ("bug", "bug2", "stub"):
            commit_all(project, f"work through step {n - 1}")
        since = git(project, "rev-parse", "HEAD").strip()
        if not apply_setup(project, task):
            error = f"step {n}: setup did not apply"
            break
        if task["kind"] == "rename" and os.environ.get("CIGAR_GAUNTLET_RENAME_HINT") == "1":
            task = dict(task, prompt=task["prompt"] + rename_hint(project, task["rename"]))
        before_tree = tree_hash(project)
        out = runs / f"{a.arm}-s{a.seed}-{n}.jsonl"
        at = time.time()
        answer = None
        try:
            if harness == B.claude.HARNESS:
                r = B.claude_exec(project, where, python, task["prompt"], thread, n > 1, out)
                answer = r.get("result") if isinstance(r, dict) else None
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
                answer = O.answer(out)
            else:
                B.codex_exec(project, codex_home, home if home.is_dir() else None, python, task["prompt"], thread, out)
                ev = B.events_of(out)
                events.extend(ev)
                thread = thread or B.thread_of(ev)
                answer = final_message(out)
        except B.StepError as failure:
            error = f"step {n}: {failure}"
            print(a.arm, a.seed, n, "FAIL", error, flush=True)
            break
        res = check(python, project, repo, pool, task, before_tree, answer, since)
        steps.append(
            {"step": n, "kind": task["kind"], "secs": round(time.time() - at), "checks": res, "passed": res["ok"]}
        )
        print(a.arm, a.seed, repo, n, task["kind"], "pass" if res["ok"] else "FAIL", json.dumps(res)[:200], flush=True)
    if harness == B.claude.HARNESS:
        model = B.claude.MODEL
        ledger = B.usage.claude_transcripts(B.claude_projects(), thread)
        tokens = B.usage.claude_transcript(ledger) if ledger else B.usage.empty()
    elif harness == O.HARNESS:
        model = O.MODEL
        ledger = omp_outs
        tokens = O.usage(omp_outs)
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
    }
    row["tag"] = a.tag
    with (runs / "results.jsonl").open("a") as f:
        f.write(json.dumps(row) + "\n")
    print(a.arm, a.seed, repo, "DONE", "pass" if row["passed"] else "FAIL", row["cost"], flush=True)


if __name__ == "__main__":
    main()
