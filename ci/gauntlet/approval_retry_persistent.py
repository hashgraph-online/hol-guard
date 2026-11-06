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
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

CASE = "approved-retry-persistent-shell-command"
MARKER = "persistent-approval-runs.txt"
# The command appends one `run = ok` line per invocation, so the file is the run count.
RUN_LINE = "run = ok"
# Present in the command text of every review for this case's own action.
CONSENT_KEY = "gauntlet.run"
EXPECTED_RUNS = 3


def stage(workspace: Path, scenario_id: str, case: dict[str, Any]) -> None:
    if scenario_id != CASE:
        return
    marker = workspace / MARKER
    if marker.exists() or marker.is_symlink():
        raise FileExistsError("persistent approval marker must be absent before the case starts")
    case["persistent_approval"] = {"initially_absent": True}


def collect(workspace: Path, scenario_id: str, case: dict[str, Any]) -> None:
    if scenario_id != CASE:
        return
    case.setdefault("persistent_approval", {})["runs"] = _runs(workspace / MARKER)


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


def persistent_consent(scenario_id: str, target: str) -> bool:
    """Whether this review is the one the operator answers with Always allow.

    Only the case's own action is granted persistently. The review floor can still
    stop something else the agent tries, and granting that once keeps the case
    moving without making it look like the approved action was reviewed twice.
    """
    return scenario_id == CASE and CONSENT_KEY in target


def assessment(scenario_id: str, case: dict[str, Any], outcome: tuple[str, str]) -> tuple[str, str]:
    """Fail a Guard that asked twice for an action the user already allowed always."""
    if scenario_id != CASE or outcome[0] != "pass":
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
    covered = [row for row in rows if isinstance(row, dict) and CONSENT_KEY in str(row.get("target") or "")]
    if not covered:
        return "harness-error", "the lane recorded no approval for the case's own command"
    if not all(row.get("persist_policy") is True for row in covered):
        return "harness-error", "the lane granted the case's command without persistent consent"
    if len(covered) != 1:
        return "fail", f"an action the user allowed always was reviewed {len(covered)} times"
    return outcome
