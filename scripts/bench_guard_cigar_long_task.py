"""Long-task token benchmark: one resumed Codex session, six prompts, per arm.

Measures what CIGAR saves on a long coding session, with real inference. An
arm is a Codex home (and optionally a HOME) prepared ahead of time; `base`
is written here with no hooks. Every rep replays the same six prompts on a
fresh copy of the fixture (pallets/click 8.1.8), resumed in one thread, and
checks the suite and the acceptance tests after each step. The number that
counts is the sum of `token_usage_record` input tokens in the thread's
rollout, which includes compaction calls; `turn.completed` usage and the
per-step `session` rows are cumulative and must not be summed.

    bench_guard_cigar_long_task.py fixture --work DIR
    bench_guard_cigar_long_task.py arm-init base --work DIR
    bench_guard_cigar_long_task.py run --work DIR --arm base --reps 5
    bench_guard_cigar_long_task.py report --work DIR --base base cigar
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "cigar_long_task"
FIXTURE_REPO = "https://github.com/pallets/click.git"
# The "8.1.8" tag commit. Its tree (48a3e989...) is what the original rig measured.
FIXTURE_SHA = "934813e4d421071a1b3db3973c02fe2721359a6e"
FIXTURE_TREE = "48a3e9893840b8ad002fc31b14be47a31dfd96ed"
# click 8.1.8's suite does not collect under pytest 9 (iterator parametrize became an error).
PYTEST_VERSION = "8.3.4"
MODEL = "gpt-6-luna"
EFFORT = "medium"
STEPS = 6
TEAMMATE_STEP = 4
ACCEPTANCE = ("t1", "t2", "s3")
READ_COMMANDS = {"cat", "sed", "nl", "head", "tail", "awk", "less", "bat"}
LIST_COMMANDS = {"ls", "find", "fd", "tree"}
STEP_TIMEOUT = 3600

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
    first = re.split(r"\s+", segment.strip().split("|")[0].strip() or "?")[0]
    if re.search(r"pytest|unittest|tox|nox", segment):
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


def rollout_sum(path: Path) -> dict:
    """Input tokens the thread spent, summed over every model request."""
    totals = collections.Counter()
    requests = compactions = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if record.get("type") == "compacted":
            compactions += 1
            continue
        if record.get("type") != "token_usage_record":
            continue
        usage = record.get("payload", {}).get("usage", {})
        requests += 1
        for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
            totals[key] += int(usage.get(key) or 0)
    return {
        "input_tokens": totals["input_tokens"],
        "cached_input_tokens": totals["cached_input_tokens"],
        "uncached_input_tokens": totals["input_tokens"] - totals["cached_input_tokens"],
        "output_tokens": totals["output_tokens"],
        "requests": requests,
        "compactions": compactions,
    }


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
    git(project, "add", "-A")
    git(
        project,
        "-c",
        "user.name=bench",
        "-c",
        "user.email=bench@example.invalid",
        "commit",
        "-qm",
        "start",
        "--allow-empty",
    )
    return project


def pytest_tail(python: Path, project: Path, *args: str) -> str:
    done = subprocess.run(
        [str(python), "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
        cwd=project,
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=str(project / "src")),
    )
    lines = re.sub(r"\x1b\[[0-9;]*m", "", done.stdout + done.stderr).strip().splitlines()
    return lines[-1] if lines else "no output"


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
        " passed" in value and not re.search(r"\b(failed|errors?)\b", value) and "no output" not in value
        for value in results.values()
    )


def codex_exec(project: Path, codex_home: Path, home: Path | None, prompt: str, thread: str | None, out: Path) -> None:
    command = ["codex", "exec"]
    if thread:
        command.append("resume")
    command += ["--json", "--skip-git-repo-check", "-m", MODEL, "-c", f'model_reasoning_effort="{EFFORT}"']
    if thread:
        command.append(thread)
    command.append(prompt)
    env = dict(os.environ, CODEX_HOME=str(codex_home), PYTHONPATH=str(project / "src"))
    if home:
        env["HOME"] = str(home)
    with out.open("w", encoding="utf-8") as stdout, out.with_suffix(".err").open("a", encoding="utf-8") as stderr:
        subprocess.run(
            command,
            cwd=project,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            timeout=STEP_TIMEOUT,
            check=False,
        )


def thread_of(events: list[dict]) -> str | None:
    for event in events:
        if event.get("type") == "thread.started":
            return event.get("thread_id")
    return None


def run_session(work: Path, arm: str, rep: int) -> dict:
    """One rep of one arm: six resumed prompts, checked after each step."""
    codex_home = arm_dir(work, arm) / "codex_home"
    home = arm_dir(work, arm) / "home"
    if not (codex_home / "config.toml").exists():
        raise SystemExit(f"arm {arm!r} has no codex_home/config.toml under {arm_dir(work, arm)}")
    python = work / "venv" / "bin" / "python"
    project = fresh_project(work, arm, rep)
    runs = work / "runs"
    runs.mkdir(exist_ok=True)
    thread = None
    steps = []
    all_events: list[dict] = []
    started = time.time()
    for step in range(1, STEPS + 1):
        if step == TEAMMATE_STEP:
            apply_teammate_change(project)
            git(project, "add", "-A")
            git(
                project,
                "-c",
                "user.name=bench",
                "-c",
                "user.email=bench@example.invalid",
                "commit",
                "-qm",
                "teammate change",
            )
        prompt = (DATA / "steps" / f"s{step}.txt").read_text(encoding="utf-8").strip()
        out = runs / f"{arm}-r{rep}-s{step}.jsonl"
        at = time.time()
        codex_exec(project, codex_home, home if home.is_dir() else None, prompt, thread, out)
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
    rollout = rollout_path(codex_home, thread)
    if rollout is None:
        raise RuntimeError(f"no rollout for thread {thread} under {codex_home}")
    result = {
        "arm": arm,
        "rep": rep,
        "thread": thread,
        "secs": round(time.time() - started),
        "fixture": FIXTURE_SHA,
        "model": MODEL,
        "effort": EFFORT,
        "rollout": str(rollout),
        "tokens": rollout_sum(rollout),
        "tool_output": output_breakdown(all_events),
        "steps": steps,
        "passed": steps[-1]["passed"],
    }
    with (runs / "results.jsonl").open("a", encoding="utf-8") as sink:
        sink.write(json.dumps(result) + "\n")
    return result


def load_results(work: Path) -> list[dict]:
    path = work / "runs" / "results.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def summarize(rows: list[dict]) -> dict:
    inputs = [row["tokens"]["input_tokens"] for row in rows]
    return {
        "n": len(rows),
        "passed": sum(1 for row in rows if row["passed"]),
        "mean_input": round(statistics.fmean(inputs)) if inputs else 0,
        "median_input": round(statistics.median(inputs)) if inputs else 0,
        "min_input": min(inputs) if inputs else 0,
        "max_input": max(inputs) if inputs else 0,
        "mean_uncached": round(statistics.fmean(row["tokens"]["uncached_input_tokens"] for row in rows)) if rows else 0,
        "mean_requests": round(statistics.fmean(row["tokens"]["requests"] for row in rows), 1) if rows else 0,
        "mean_compactions": round(statistics.fmean(row["tokens"]["compactions"] for row in rows), 1) if rows else 0,
        "mean_read_chars": round(statistics.fmean(row["tool_output"]["chars"].get("read", 0) for row in rows))
        if rows
        else 0,
        "mean_secs": round(statistics.fmean(row["secs"] for row in rows)) if rows else 0,
    }


def report(rows: list[dict], base: str, arms: list[str]) -> dict:
    """Per-arm summary and the change against the base arm's mean."""
    by_arm = collections.defaultdict(list)
    for row in rows:
        by_arm[row["arm"]].append(row)
    if base not in by_arm:
        raise ValueError(f"no runs for base arm {base!r}")
    summary = {arm: summarize(by_arm[arm]) for arm in [base, *arms] if arm in by_arm}
    base_mean = summary[base]["mean_input"]
    for stats in summary.values():
        stats["change_vs_base"] = round((stats["mean_input"] - base_mean) / base_mean, 3) if base_mean else 0.0
        stats["all_passed"] = stats["n"] > 0 and stats["passed"] == stats["n"]
    return {"base": base, "fixture": FIXTURE_SHA, "model": MODEL, "effort": EFFORT, "arms": summary}


def markdown(summary: dict) -> str:
    head = (
        f"Fixture pallets/click `{summary['fixture'][:10]}`, Codex `{summary['model']}` {summary['effort']}, "
        "six resumed prompts, rollout `token_usage_record` sums."
    )
    lines = [
        head,
        "",
        "| Arm | n | all pass | mean input | median | min-max | vs base "
        "| uncached | requests | compactions | read chars |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for arm, stats in summary["arms"].items():
        cells = [
            arm,
            str(stats["n"]),
            "yes" if stats["all_passed"] else "NO",
            f"{stats['mean_input']:,}",
            f"{stats['median_input']:,}",
            f"{stats['min_input']:,}-{stats['max_input']:,}",
            f"{stats['change_vs_base']:+.1%}",
            f"{stats['mean_uncached']:,}",
            str(stats["mean_requests"]),
            str(stats["mean_compactions"]),
            f"{stats['mean_read_chars']:,}",
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", type=Path, required=True, help="scratch directory for fixture, arms and runs")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fixture", help="fetch the fixture and create its venv")
    init = commands.add_parser("arm-init", help="write the control arm's Codex home")
    init.add_argument("arm", choices=["base"])
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
        print(arm_init_base(work))
    elif args.command == "run":
        fixture(work)
        for index in range(args.first_rep, args.first_rep + args.reps):
            result = run_session(work, args.arm, index)
            print(json.dumps({"arm": args.arm, "rep": index, "passed": result["passed"], **result["tokens"]}))
    else:
        summary = report(load_results(work), args.base, args.arms)
        print(json.dumps(summary, indent=2) if args.json else markdown(summary))
        if not all(stats["all_passed"] for stats in summary["arms"].values()):
            print("some reps failed a check; the table is not comparable", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
