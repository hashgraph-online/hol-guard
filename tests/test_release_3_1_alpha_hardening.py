"""Defense-in-depth checks for the retired release/3.1 train."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml  # pyright: ignore[reportMissingModuleSource]

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def _mapping(value: object) -> dict[object, object]:
    assert isinstance(value, dict)
    return cast(dict[object, object], value)


def _sequence(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _workflow() -> dict[object, object]:
    return _mapping(cast(object, yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))))


def test_only_manual_dispatch_remains() -> None:
    value = _workflow()
    assert value[True] == {"workflow_dispatch": None}


def test_retirement_job_has_no_checkout_or_external_action() -> None:
    jobs = _mapping(_workflow()["jobs"])
    retired = _mapping(jobs["retired"])
    steps = [_mapping(step) for step in _sequence(retired["steps"])]
    assert all("uses" not in step for step in steps)
    run = steps[0]["run"]
    assert isinstance(run, str)
    assert run.rstrip().endswith("exit 1")
