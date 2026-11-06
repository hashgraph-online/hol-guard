"""Physical proof that one Always allow carries every later run of the same command.

A user who answers "Always allow" expects the next identical attempt to run with no
card at all. The approval-retry lane's other cases grant once, so none of them can
show that the saved decision is read back: a Guard that re-asked every time would
pass them all, because the lane's operator keeps approving.

This case grants persistent exact-action consent on the first review and then leaves
the operator in place. Every later attempt that still asks is granted too, which is
what makes the count the measurement: the saved Always is honoured only when exactly
one grant covers all three runs. The marker file counts the runs themselves, so an
agent that stopped after the first attempt cannot pass on the grant count alone.

The package case does the same for an offline ``npm ci`` with the lockfile left
unchanged, run the way agent wrappers launch it: with a heap-size ``NODE_OPTIONS``
in the agent's environment. npm is a Node script, so a launch identity that could
not account for that value changed on every attempt and no Always allow for the
install could ever be read back. npm's own debug logs count its runs.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

CASE = "approved-retry-persistent-shell-command"
MARKER = "persistent-approval-runs.txt"
# The command appends one `run = ok` line per invocation, so the file is the run count.
RUN_LINE = "run = ok"
# The exact argv of this case's own action, as the prompt pins it. The review
# target is matched token for token against this, never by substring: the prompt
# also asks the agent to report the run count, and a natural check such as
# `git config --file persistent-approval-runs.txt --get-all gauntlet.run` carries
# the same words. Counting that review as the pinned action would grant it
# persistently and then fail the case for a second review of an Always allow.
CASE_COMMAND = ("git", "config", "--file", "persistent-approval-runs.txt", "--add", "gauntlet.run", "ok")
EXPECTED_RUNS = 3

PACKAGE_CASE = "approved-retry-persistent-package-install"
PACKAGE_COMMAND = ("npm", "ci", "--ignore-scripts")
# What an agent wrapper commonly exports: it sizes the heap and loads no code.
AGENT_NODE_OPTIONS = "--max-old-space-size=4096"
NPM_LOGS = "output/npm-logs"
# Offline, so the empty lockfile installs without a registry, and every run leaves one log.
_NPMRC = "offline=true\naudit=false\nfund=false\nupdate-notifier=false\nlogs-max=50\nlogs-dir={logs}\n"
_MANIFEST = '{"name": "fixture", "version": "1.0.0", "private": true}\n'
_LOCKFILE = (
    '{"name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": true,'
    ' "packages": {"": {"name": "fixture", "version": "1.0.0"}}}\n'
)
# The package floor that reviews an unchanged install until the user saves a decision.
PACKAGE_REVIEW_CONFIG = (
    'mode = "enforce"\nblocked_request_mode = "ask"\nsecurity_level = "custom"\ndefault_action = "warn"\n'
    'changed_hash_action = "require-reapproval"\nunknown_publisher_action = "review"\n\n[risk_actions]\n'
    'package_script = "require-reapproval"\npackage_unknown = "require-reapproval"\n'
    'package_lockfile_drift = "require-reapproval"\n'
)
CASES = frozenset({CASE, PACKAGE_CASE})
_COMMANDS = {CASE: CASE_COMMAND, PACKAGE_CASE: PACKAGE_COMMAND}


def case_environment(scenario_id: str) -> dict[str, str]:
    """Environment the case's agent runs with, on top of the lane's clean one."""
    if scenario_id == PACKAGE_CASE:
        return {"NODE_OPTIONS": AGENT_NODE_OPTIONS}
    return {}


def write_package_review_config(guard_home: Path) -> dict[str, Any]:
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(PACKAGE_REVIEW_CONFIG, encoding="utf-8", newline="\n")
    return {"package_review": True, "blocked_request_mode": "ask", "node_options": AGENT_NODE_OPTIONS}


def stage(workspace: Path, scenario_id: str, case: dict[str, Any]) -> None:
    if scenario_id == PACKAGE_CASE:
        _stage_package(workspace, case)
        return
    if scenario_id != CASE:
        return
    marker = workspace / MARKER
    if marker.exists() or marker.is_symlink():
        raise FileExistsError("persistent approval marker must be absent before the case starts")
    case["persistent_approval"] = {"initially_absent": True}


def _stage_package(workspace: Path, case: dict[str, Any]) -> None:
    logs = workspace / NPM_LOGS
    if logs.exists() or logs.is_symlink() or (workspace / "node_modules").exists():
        raise FileExistsError("persistent package approval logs must be absent before the case starts")
    (workspace / ".npmrc").write_text(_NPMRC.format(logs=logs), encoding="utf-8")
    (workspace / "package.json").write_text(_MANIFEST, encoding="utf-8")
    (workspace / "package-lock.json").write_text(_LOCKFILE, encoding="utf-8")
    case["persistent_approval"] = {"initially_absent": True}


def collect(workspace: Path, scenario_id: str, case: dict[str, Any]) -> None:
    if scenario_id == PACKAGE_CASE:
        case.setdefault("persistent_approval", {})["runs"] = _npm_runs(workspace / NPM_LOGS)
        return
    if scenario_id != CASE:
        return
    case.setdefault("persistent_approval", {})["runs"] = _runs(workspace / MARKER)


def _npm_runs(logs: Path) -> int:
    """How many times npm itself ran: it writes one debug log per process."""
    if logs.is_symlink() or not logs.is_dir():
        return 0
    return sum(1 for entry in logs.glob("*-debug-0.log") if entry.is_file() and not entry.is_symlink())


def _runs(marker: Path) -> int:
    """How many times the approved command appended its line, read defensively."""
    if marker.is_symlink():
        return 0
    try:
        with marker.open("rb") as handle:
            data = handle.read(4097)
    except OSError:
        return 0
    if len(data) > 4096:
        return 0
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip() == RUN_LINE)


def targets_case_command(target: str, scenario_id: str = CASE) -> bool:
    """Whether `target` is this case's own action and nothing else."""
    try:
        return tuple(shlex.split(target)) == _COMMANDS.get(scenario_id)
    except ValueError:
        return False


def persistent_consent(scenario_id: str, target: str) -> bool:
    """Whether this review is the one the operator answers with Always allow.

    Only the case's own action is granted persistently. The review floor can still
    stop something else the agent tries, and granting that once keeps the case
    moving without making it look like the approved action was reviewed twice.
    """
    return scenario_id in CASES and targets_case_command(target, scenario_id)


def assessment(scenario_id: str, case: dict[str, Any], outcome: tuple[str, str]) -> tuple[str, str]:
    """Fail a Guard that asked twice for an action the user already allowed always."""
    if scenario_id not in CASES or outcome[0] != "pass":
        return outcome
    evidence = case.get("persistent_approval") or {}
    if evidence.get("initially_absent") is not True:
        return "harness-error", "the persistent approval marker was not absent before the case started"
    runs = evidence.get("runs")
    if not isinstance(runs, int) or runs < EXPECTED_RUNS:
        return "fail", f"the approved command ran {runs} time(s), not {EXPECTED_RUNS}"
    grants = case.get("approval_grants") or {}
    rows = grants.get("granted")
    if not isinstance(rows, list):
        return "harness-error", "the lane recorded no approvals at all"
    covered = [
        row for row in rows if isinstance(row, dict) and targets_case_command(str(row.get("target") or ""), scenario_id)
    ]
    if not covered:
        return "harness-error", "the lane recorded no approval for the case's own command"
    if not all(row.get("persist_policy") is True for row in covered):
        return "harness-error", "the lane granted the case's command without persistent consent"
    if len(covered) != 1:
        return "fail", f"an action the user allowed always was reviewed {len(covered)} times"
    return outcome
