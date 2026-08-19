"""Contracts for unpublished alpha reservation recovery."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


def _workflow() -> dict[object, object]:
    workflow = yaml.safe_load(PUBLISH_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def test_alpha_reservation_waits_for_native_assemble() -> None:
    jobs = _workflow()["jobs"]
    job = jobs["reserve-alpha-tag"]
    assert job["needs"] == ["build", "assemble-native-guard-distributions"]
    assert "needs.assemble-native-guard-distributions.result == 'success'" in job["if"]


def test_unpublished_alpha_reservation_is_released_when_publish_fails() -> None:
    jobs = _workflow()["jobs"]
    job = jobs["release-unpublished-alpha-reservation"]
    cleanup_run = next(step["run"] for step in job["steps"] if step.get("name") == "Delete unpublished reservation tag")
    assert job["needs"] == ["build", "reserve-alpha-tag", "publish-alpha-pypi"]
    assert job["permissions"] == {"contents": "write"}
    assert "needs.reserve-alpha-tag.result == 'success'" in job["if"]
    assert "needs.publish-alpha-pypi.result != 'success'" in job["if"]
    assert "git/refs/tags/${tag}" in cleanup_run
    assert "git/ref/tags/${tag}" in cleanup_run


def test_native_guard_wheel_timeout_covers_musl_builds() -> None:
    native = _workflow()["jobs"]["build-native-guard-wheels"]
    assert native["timeout-minutes"] == 45
