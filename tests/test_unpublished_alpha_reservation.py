"""Contracts for unpublished alpha reservation recovery."""

from __future__ import annotations

from tests.test_release_train_workflow import _workflow, PUBLISH_WORKFLOW


def test_alpha_reservation_waits_for_native_assemble() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]
    job = jobs["reserve-alpha-tag"]
    assert job["needs"] == ["build", "assemble-native-guard-distributions"]
    assert "needs.assemble-native-guard-distributions.result == 'success'" in job["if"]


def test_unpublished_alpha_reservation_is_released_when_publish_fails() -> None:
    jobs = _workflow(PUBLISH_WORKFLOW)["jobs"]
    job = jobs["release-unpublished-alpha-reservation"]
    cleanup_run = next(step["run"] for step in job["steps"] if step.get("name") == "Delete unpublished reservation tag")
    assert job["needs"] == ["build", "reserve-alpha-tag", "publish-alpha-pypi"]
    assert job["permissions"] == {"contents": "write"}
    assert "needs.reserve-alpha-tag.result == 'success'" in job["if"]
    assert "needs.publish-alpha-pypi.result != 'success'" in job["if"]
    assert "git/ref/tags/${tag}" in cleanup_run
    assert "git/refs/tags/${tag}" in cleanup_run
    assert "pypi.org/pypi/${project}/${VERSION}/json" in cleanup_run
    assert "hol-guard plugin-scanner" in cleanup_run
    assert "%{http_code}" in cleanup_run
    assert "Not Found" in cleanup_run


def test_native_guard_wheel_timeout_covers_musl_builds() -> None:
    native = _workflow(PUBLISH_WORKFLOW)["jobs"]["build-native-guard-wheels"]
    assert native["timeout-minutes"] == 45
