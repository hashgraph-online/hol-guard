"""Contracts for unpublished alpha reservation recovery."""

from __future__ import annotations

from tests.test_release_train_workflow import PUBLISH_WORKFLOW, _workflow


def test_alpha_reservation_waits_for_native_assemble() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]
    job = jobs["reserve-alpha-tag"]
    assert job["needs"] == ["build", "assemble-native-guard-distributions"]
    assert "needs.assemble-native-guard-distributions.result == 'success'" in job["if"]


def test_native_guard_wheel_timeout_covers_musl_builds() -> None:
    native = _workflow(PUBLISH_WORKFLOW)["jobs"]["build-native-guard-wheels"]
    assert native["timeout-minutes"] == 45
