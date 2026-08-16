"""Defense-in-depth checks for the retired release/3.1 train."""

# pyright: reportAny=false, reportMissingModuleSource=false

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def test_only_manual_dispatch_remains() -> None:
    value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert value[True] == {"workflow_dispatch": None}


def test_retirement_job_has_no_checkout_or_external_action() -> None:
    value = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = value["jobs"]["retired"]["steps"]
    assert all("uses" not in step for step in steps)
    assert steps[0]["run"].rstrip().endswith("exit 1")
