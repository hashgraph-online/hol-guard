"""Long-task token benchmark: one resumed Codex session, six prompts, per arm.

Measures what CIGAR saves on a long coding session, with real inference. An
arm is a Codex home (and optionally a HOME) prepared ahead of time; `base`
is written here with no hooks. Every rep replays the same six prompts on a
fresh copy of the fixture (pallets/click 8.1.8), resumed in one thread, and
checks the suite and the acceptance tests after each step. The number that
counts is the sum of `token_usage_record` input tokens in the thread's
rollout, which includes compaction calls; `turn.completed` usage and the
per-step `session` rows are cumulative and must not be summed.

    bench_guard_cigar_long_task.py --work DIR fixture
    bench_guard_cigar_long_task.py --work DIR arm-init base
    bench_guard_cigar_long_task.py --work DIR run --arm base --reps 5
    bench_guard_cigar_long_task.py --work DIR report --base base cigar

The agent edits the fixture under Codex's workspace-write sandbox, but the
suite and acceptance checks then run that edited code on the host, as any
test run of a checkout does. Run the benchmark under a scratch account or
machine, not next to anything the fixture's tests could reach.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import bench_guard_cigar_long_task_claude as claude
import bench_guard_cigar_usage as usage
from bench_guard_cigar_long_task_report import EFFORT, FIXTURE_SHA, MODEL, markdown, report

HERE = Path(__file__).resolve().parent
DATA = HERE / "cigar_long_task"
FIXTURE_REPO = "https://github.com/pallets/click.git"
# FIXTURE_SHA is the "8.1.8" tag commit. Its tree is what the original rig measured.
FIXTURE_TREE = "48a3e9893840b8ad002fc31b14be47a31dfd96ed"
# click 8.1.8's suite does not collect under pytest 9 (iterator parametrize became an error).
PYTEST_VERSION = "8.3.4"
STEPS = 6
TEAMMATE_STEP = 4
ACCEPTANCE = ("t1", "t2", "s3")
READ_COMMANDS = {"cat", "sed", "nl", "head", "tail", "awk", "less", "bat"}
LIST_COMMANDS = {"ls", "find", "fd", "tree"}
TEST_COMMANDS = {"pytest", "tox", "nox", "py.test"}
STEP_TIMEOUT = 3600
CLAUDE_PROJECTS = Path.home() / ".claude" / "projects"
CHECK_TIMEOUT = 600

# The teammate's change at step 4: the same two bugs as the single-task
# variant, applied as exact text so the step cannot drift.
TEAMMATE_EDITS = (
    (
        "src/click/parser.py",
        "state.rargs.insert(0, explicit_value)",
        "state.rargs.append(explicit_value)",
    ),
    ("src/click/types.py", "        return bound + dir\n", "        return bound - dir\n"),
)


KIND_ORDER = ("test", "read", "search", "list", "git", "edit", "python")


def kind(command: str) -> str:
    """The shape of an agent shell command, for the tool-output breakdown.

    Codex wraps commands as `<shell> -lc <quoted text>`; the text often chains
    several commands with `;` or `&&`. The chain takes the most output-heavy
    kind of any segment, in KIND_ORDER, so a run of `sed -n` reads counts as a read.
    """
    match = re.match(r"^\S+ -lc (['\"])(.*)\1$", command, re.S)
    text = match.group(2) if match else command
    text = text.replace("'\"'\"'", "'").replace('\\"', '"')
    kinds = {segment_kind(segment) for segment in re.split(r"\s*(?:;|&&|\|\|)\s*", text) if segment.strip()}
    for name in KIND_ORDER:
        if name in kinds:
            return name
    return "other"


def segment_kind(segment: str) -> str:
    words = re.split(r"\s+", segment.strip().split("|")[0].strip() or "?")
    first = words[0]
    module = words[2] if len(words) > 2 and words[1] == "-m" else ""
    if first in TEST_COMMANDS or module in ("pytest", "unittest", "tox", "nox"):
        return "test"
    if first in READ_COMMANDS:
        return "read"
    if first in ("rg", "grep", "ag", "ack"):
        return "search"
    if first in LIST_COMMANDS:
        return "list"
    if first == "git":
        return "search" if re.search(r"\bgit grep\b", segment) else "git"
    if "apply_patch" in segment or (first in ("python", "python3") and "write" in segment):
        return "edit"
    if first in ("python", "python3"):
        return "python"
    return "other"


def rollout_path(codex_home: Path, thread_id: str) -> Path | None:
    found = sorted((codex_home / "sessions").rglob(f"rollout-*-{thread_id}.jsonl"))
    return found[-1] if found else None


# Kept under its old name: the Codex ledger reader now lives with the other harnesses' readers.
rollout_sum = usage.codex_rollout


def output_breakdown(events: list[dict]) -> dict:
    """Tool-output characters and call counts by command shape."""
    chars = collections.Counter()
    calls = collections.Counter()
    for event in events:
        item = event.get("item", {})
        if event.get("type") != "item.completed" or item.get("type") != "command_execution":
            continue
        shape = kind(item.get("command", ""))
        chars[shape] += len(item.get("aggregated_output") or "")
        calls[shape] += 1
    return {"chars": dict(chars), "calls": dict(calls)}


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("{")]


def apply_teammate_change(project: Path) -> None:
    for relative, before, after in TEAMMATE_EDITS:
        target = project / relative
        text = target.read_text(encoding="utf-8")
        if before not in text:
            raise RuntimeError(f"teammate edit not found in {relative}")
        target.write_text(text.replace(before, after, 1), encoding="utf-8")


def git(project: Path, *args: str) -> str:
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", *args], cwd=project, env=env, check=True, capture_output=True, text=True).stdout


def commit(project: Path, message: str, *paths: str) -> None:
    """Commit the given paths, or everything when none are given, as the bench identity."""
    git(project, "add", "-A", "--", *paths)
    git(project, "-c", "user.name=bench", "-c", "user.email=bench@example.invalid", "commit", "-qm", message)


def fixture(work: Path) -> Path:
    """The fixture checkout at the pinned commit, with pytest in its own venv."""
    pristine = work / "pristine"
    if not (pristine / ".git").is_dir():
        # The pinned commit is not a branch tip, so a depth-1 fetch of it is refused;
        # a blobless clone fetches history cheaply and the checkout pulls the blobs it needs.
        pristine.parent.mkdir(parents=True, exist_ok=True)
        git(work, "clone", "-q", "--filter=blob:none", "--no-checkout", FIXTURE_REPO, str(pristine))
        git(pristine, "checkout", "-q", FIXTURE_SHA)
    if git(pristine, "rev-parse", "HEAD^{tree}").strip() != FIXTURE_TREE:
        raise RuntimeError("fixture is not at the pinned commit")
    venv = work / "venv"
    if not (venv / "bin" / "python").exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        pip = [str(venv / "bin" / "python"), "-m", "pip", "-q", "install", f"pytest=={PYTEST_VERSION}"]
        subprocess.run(pip, check=True)
    return pristine


def arm_dir(work: Path, arm: str) -> Path:
    return work / "arms" / arm


def harness_of(arm: Path) -> str:
    marker = arm / "harness"
    return marker.read_text(encoding="utf-8").strip() if marker.exists() else "codex"


def arm_init_base(work: Path) -> Path:
    """A Codex home with no hooks: the control arm."""
    home = arm_dir(work, "base") / "codex_home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(
        f'model = "{MODEL}"\nmodel_reasoning_effort = "{EFFORT}"\n'
        'approval_policy = "never"\nsandbox_mode = "workspace-write"\n'
        "[sandbox_workspace_write]\nnetwork_access = false\n",
        encoding="utf-8",
    )
    return home


def fresh_project(work: Path, arm: str, rep: int) -> Path:
    project = work / "projects" / f"{arm}-r{rep}"
    if project.exists():
        shutil.rmtree(project)
    shutil.copytree(work / "pristine", project, symlinks=True)
    with (project / ".git" / "info" / "exclude").open("a", encoding="utf-8") as exclude:
        exclude.write(".bench_accept/\n")
    dirty = git(project, "status", "--porcelain").strip()
    if dirty or git(project, "rev-parse", "HEAD^{tree}").strip() != FIXTURE_TREE:
        raise RuntimeError(f"{project} is not a clean copy of the pinned fixture")
    return project


def sandboxed(command: list[str]) -> list[str]:
    """Wrap a check in the sandbox the agent ran under: writes only inside the project, no network."""
    return [
        "codex",
        "sandbox",
        "-c",
        'sandbox_mode="workspace-write"',
        "-c",
        "sandbox_workspace_write.network_access=false",
        "--",
        *command,
    ]


def pytest_tail(python: Path, project: Path, *args: str) -> str:
    # The suite runs code the agent edited, so it gets the agent's sandbox, not the host. An empty
    # bench-owned CODEX_HOME (beside the projects folder) keeps the user's Codex config out of it.
    sandbox_home = project.parent.parent / "sandbox_home"
    sandbox_home.mkdir(exist_ok=True)
    try:
        done = subprocess.run(
            sandboxed([str(python), "-m", "pytest", "-q", "-p", "no:cacheprovider", *args]),
            cwd=project,
            capture_output=True,
            text=True,
            timeout=CHECK_TIMEOUT,
            env=dict(os.environ, PYTHONPATH=str(project / "src"), CODEX_HOME=str(sandbox_home)),
        )
    except subprocess.TimeoutExpired:
        return f"timed out after {CHECK_TIMEOUT}s"
    lines = re.sub(r"\x1b\[[0-9;]*m", "", done.stdout + done.stderr).strip().splitlines()
    last = lines[-1] if lines else "no output"
    # A sandbox or pytest failure can still end on a summary line that reads as a pass.
    return last if done.returncode == 0 else f"exit status {done.returncode}: {last}"


def check_step(python: Path, project: Path) -> dict:
    """Suite and acceptance results after one step; every rep must pass at step 6."""
    results = {"suite": pytest_tail(python, project, "tests")}
    # Acceptance tests run from a copy inside the project so pytest's rootdir, and any
    # conftest it picks up, is the fixture's and not this repository's.
    accept = project / ".bench_accept"
    accept.mkdir(exist_ok=True)
    for name in ACCEPTANCE:
        target = accept / f"{name}_accept.py"
        shutil.copyfile(DATA / "accept" / f"{name}_accept.py", target)
        results[name] = pytest_tail(python, project, str(target.relative_to(project)))
    return results


def passed(results: dict) -> bool:
    """Every check's pytest summary line reports passes and no failures ("xfailed" is not a failure)."""
    return all(
        " passed" in value
        and not re.search(r"\b(failed|errors?)\b", value)
        and "no output" not in value
        and not value.startswith("exit status")
        for value in results.values()
    )


def agent_env(project: Path, codex_home: Path, home: Path | None, python: Path) -> dict:
    """The environment Codex and its shell commands get, the same for every arm.

    Codex runs commands through a login shell, and a login shell rebuilds PATH from the
    user's startup files (and macOS path_helper), so a PATH set here alone does not reach
    the agent. A bench-owned ZDOTDIR puts the fixture venv first after that rebuild,
    whatever HOME the arm uses. Without it an arm with its own HOME found a Python
    without pytest and spent a fifth of its tool calls looking for one.
    """
    zdot = python.parent.parent.parent / "zdot"
    zdot.mkdir(exist_ok=True)
    (zdot / ".zshenv").write_text("", encoding="utf-8")
    # .zprofile serves Codex's login shell; .zshrc serves the snapshot Claude Code's shell sources.
    for name in (".zprofile", ".zshrc"):
        (zdot / name).write_text(f'export PATH="{python.parent}:$PATH"\n', encoding="utf-8")
    path = os.pathsep.join([str(python.parent), os.environ.get("PATH", "")])
    env = dict(os.environ, CODEX_HOME=str(codex_home), PYTHONPATH=str(project / "src"), PATH=path, ZDOTDIR=str(zdot))
    if home:
        env["HOME"] = str(home)
    return env


def preflight(project: Path, codex_home: Path, home: Path | None, python: Path) -> None:
    """The agent's login shell must find the fixture venv's pytest before any step runs."""
    env = agent_env(project, codex_home, home, python)
    shell = env.get("SHELL") or "/bin/zsh"
    done = subprocess.run(
        [shell, "-lc", "command -v python"], cwd=project, env=env, capture_output=True, text=True, timeout=60
    )
    if done.stdout.strip() != str(python.parent / "python"):
        raise SystemExit(f"agent shell resolves python to {done.stdout.strip() or 'nothing'}, not {python}")


class StepError(RuntimeError):
    """A Codex step did not finish; the rep is recorded as failed and the next one starts."""


def codex_exec(
    project: Path, codex_home: Path, home: Path | None, python: Path, prompt: str, thread: str | None, out: Path
) -> None:
    command = ["codex", "exec"]
    if thread:
        command.append("resume")
    command += ["--json", "--skip-git-repo-check", "-m", MODEL, "-c", f'model_reasoning_effort="{EFFORT}"']
    if thread:
        command.append(thread)
    command.append(prompt)
    env = agent_env(project, codex_home, home, python)
    with out.open("w", encoding="utf-8") as stdout, out.with_suffix(".err").open("a", encoding="utf-8") as stderr:
        try:
            streams = {"stdin": subprocess.DEVNULL, "stdout": stdout, "stderr": stderr}
            done = subprocess.run(command, cwd=project, env=env, timeout=STEP_TIMEOUT, **streams)
        except subprocess.TimeoutExpired as error:
            raise StepError(f"codex exec timed out after {STEP_TIMEOUT}s") from error
    if done.returncode != 0:
        raise StepError(f"codex exec exited {done.returncode}; see {out.with_suffix('.err')}")


def claude_exec(project: Path, arm: Path, python: Path, prompt: str, session: str, resume: bool, out: Path) -> dict:
    env = dict(agent_env(project, arm / "codex_unused", None, python), **claude.ISOLATION_ENV)
    with out.open("w", encoding="utf-8") as stdout, out.with_suffix(".err").open("a", encoding="utf-8") as stderr:
        try:
            streams = {"stdin": subprocess.DEVNULL, "stdout": stdout, "stderr": stderr}
            done = subprocess.run(
                claude.command(arm, prompt, session, resume), cwd=project, env=env, timeout=STEP_TIMEOUT, **streams
            )
        except subprocess.TimeoutExpired as error:
            raise StepError(f"claude -p timed out after {STEP_TIMEOUT}s") from error
    if done.returncode != 0:
        raise StepError(f"claude -p exited {done.returncode}; see {out.with_suffix('.err')}")
    try:
        return claude.step_result(out)
    except RuntimeError as failure:
        raise StepError(str(failure)) from failure


def thread_of(events: list[dict]) -> str | None:
    for event in events:
        if event.get("type") == "thread.started":
            return event.get("thread_id")
    return None


def run_session(work: Path, arm: str, rep: int) -> dict:
    """One rep of one arm: six resumed prompts, checked after each step."""
    where = arm_dir(work, arm)
    harness = harness_of(where)
    codex_home = where / "codex_home"
    home = where / "home"
    if harness == "codex" and not (codex_home / "config.toml").exists():
        raise SystemExit(f"arm {arm!r} has no codex_home/config.toml under {where}")
    if harness == claude.HARNESS and not claude.settings_path(where).exists():
        raise SystemExit(f"arm {arm!r} has no {claude.settings_path(where).name} under {where}")
    # A rep that errored (the harness crashed or timed out) may be run again; the report leaves it out.
    if any(row["arm"] == arm and row["rep"] == rep and not row.get("error") for row in load_results(work)):
        raise SystemExit(f"{arm} r{rep} is already recorded under {work / 'runs'}; pick another --first-rep")
    python = work / "venv" / "bin" / "python"
    project = fresh_project(work, arm, rep)
    preflight(project, codex_home, home if home.is_dir() else None, python)
    runs = work / "runs"
    runs.mkdir(exist_ok=True)
    thread = str(uuid.uuid4()) if harness == claude.HARNESS else None
    steps = []
    all_events: list[dict] = []
    started = time.time()
    error = None
    for step in range(1, STEPS + 1):
        if step == TEAMMATE_STEP:
            # The agent's own work so far is committed first so the teammate commit holds only its two edits.
            if git(project, "status", "--porcelain").strip():
                commit(project, f"agent work through step {step - 1}")
            apply_teammate_change(project)
            commit(project, "teammate change", *(relative for relative, _, _ in TEAMMATE_EDITS))
        prompt = (DATA / "steps" / f"s{step}.txt").read_text(encoding="utf-8").strip()
        out = runs / f"{arm}-r{rep}-s{step}.jsonl"
        at = time.time()
        try:
            if harness == claude.HARNESS:
                claude_exec(project, where, python, prompt, thread, step > 1, out)
            else:
                codex_exec(project, codex_home, home if home.is_dir() else None, python, prompt, thread, out)
        except StepError as failure:
            error = f"step {step}: {failure}"
            print(f"{arm} r{rep} s{step} FAIL {error}", flush=True)
            break
        if harness == "codex":
            events = events_of(out)
            all_events.extend(events)
            thread = thread or thread_of(events)
            if not thread:
                raise RuntimeError(f"step {step}: no thread.started in {out}")
        checks = check_step(python, project)
        steps.append({"step": step, "secs": round(time.time() - at), "checks": checks, "passed": passed(checks)})
        print(
            f"{arm} r{rep} s{step} {thread} {'pass' if steps[-1]['passed'] else 'FAIL'} {checks['suite']}", flush=True
        )
    if harness == claude.HARNESS:
        model = claude.MODEL
        ledger = usage.claude_transcripts(CLAUDE_PROJECTS, thread)
        tokens = usage.claude_transcript(ledger) if ledger else usage.empty()
        tool_output = claude.tool_output(ledger, kind)
    else:
        model = MODEL
        rollout = rollout_path(codex_home, thread) if thread else None
        ledger = [rollout] if rollout else []
        tokens = rollout_sum(rollout) if rollout else usage.empty()
        tool_output = output_breakdown(all_events)
    if error is None and not tokens["requests"]:
        raise RuntimeError(f"no usage ledger with requests for session {thread} of arm {arm}")
    result = {
        "arm": arm,
        "harness": harness,
        "rep": rep,
        "thread": thread,
        "secs": round(time.time() - started),
        "fixture": FIXTURE_SHA,
        "model": model,
        "effort": EFFORT if harness == "codex" else None,
        "ledger": [str(path) for path in ledger],
        "tokens": tokens,
        "cost": usage.cost(tokens, model),
        "tool_output": tool_output,
        "steps": steps,
        "error": error,
        "passed": error is None and len(steps) == STEPS and steps[-1]["passed"],
    }
    with (runs / "results.jsonl").open("a", encoding="utf-8") as sink:
        sink.write(json.dumps(result) + "\n")
    return result


def load_results(work: Path) -> list[dict]:
    path = work / "runs" / "results.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", type=Path, required=True, help="scratch directory for fixture, arms and runs")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fixture", help="fetch the fixture and create its venv")
    init = commands.add_parser("arm-init", help="write a control arm: Codex home or Claude Code settings")
    init.add_argument("arm", choices=["base", "claude-base"])
    run = commands.add_parser("run", help="run reps of one arm")
    run.add_argument("--arm", required=True)
    run.add_argument("--reps", type=int, default=1)
    run.add_argument("--first-rep", type=int, default=1)
    rep = commands.add_parser("report", help="summarize recorded runs")
    rep.add_argument("--base", default="base")
    rep.add_argument("arms", nargs="*")
    rep.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    work = args.work.resolve()
    if args.command == "fixture":
        print(fixture(work))
    elif args.command == "arm-init":
        print(claude.arm_init_base(arm_dir(work, args.arm)) if args.arm == "claude-base" else arm_init_base(work))
    elif args.command == "run":
        fixture(work)
        for index in range(args.first_rep, args.first_rep + args.reps):
            result = run_session(work, args.arm, index)
            print(json.dumps({"arm": args.arm, "rep": index, "passed": result["passed"], **result["tokens"]}))
    else:
        try:
            summary = report(load_results(work), args.base, args.arms)
        except ValueError as error:
            print(error, file=sys.stderr)
            return 2
        print(json.dumps(summary, indent=2) if args.json else markdown(summary))
        if not all(stats["all_passed"] for stats in summary["arms"].values()):
            print("some reps failed a check; the table is not comparable", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
