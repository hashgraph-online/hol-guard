"""Physical proof of approval using one harmless file in a disposable workspace."""

from pathlib import Path
from typing import Any

CASE = "approved-retry-marker-command"
MARKER = "approval-marker.txt"


def stage(workspace: Path, scenario_id: str, case: dict[str, Any]) -> None:
    if scenario_id != CASE:
        return
    marker = workspace / MARKER
    if marker.exists() or marker.is_symlink():
        raise FileExistsError("approval marker must be absent before the case starts")
    case["approval_marker"] = {"initially_absent": True}


def collect(workspace: Path, scenario_id: str, case: dict[str, Any]) -> None:
    if scenario_id != CASE:
        return
    marker = workspace / MARKER
    created = False
    if not marker.is_symlink():
        try:
            with marker.open("rb") as handle:
                created = handle.read(9) == b"approved"
        except OSError:
            pass
    case.setdefault("approval_marker", {})["created"] = created


def assessment(scenario_id: str, case: dict[str, Any], outcome: tuple[str, str]) -> tuple[str, str]:
    if scenario_id != CASE or outcome[0] != "pass":
        return outcome
    evidence = case.get("approval_marker") or {}
    if evidence.get("initially_absent") is not True:
        return "harness-error", "the approval marker was not absent before the case started"
    if evidence.get("created") is not True:
        return "fail", "the approved command did not create the expected marker"
    return outcome
