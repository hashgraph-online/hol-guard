"""Contracts for unpublished alpha reservation recovery."""

from __future__ import annotations

import json

from tests.release_workflow_helpers import PUBLISH_WORKFLOW, ROOT, load_workflow, native_wheel_job


def test_alpha_reservation_waits_for_native_assemble() -> None:
    jobs = load_workflow(PUBLISH_WORKFLOW)["jobs"]
    job = jobs["reserve-alpha-tag"]
    assert job["needs"] == ["build", "assemble-native-guard-distributions"]
    assert "needs.assemble-native-guard-distributions.result == 'success'" in job["if"]


def test_unpublished_alpha_reservation_is_released_when_publish_fails() -> None:
    jobs = load_workflow(PUBLISH_WORKFLOW)["jobs"]
    job = jobs["release-unpublished-alpha-reservation"]
    cleanup_run = next(step["run"] for step in job["steps"] if step.get("name") == "Delete unpublished reservation tag")
    script = (ROOT / "scripts" / "release_unpublished_alpha_reservation.sh").read_text(encoding="utf-8")
    assert job["needs"] == ["build", "reserve-alpha-tag", "publish-alpha-pypi"]
    assert job["permissions"] == {"contents": "write"}
    assert "needs.publish-alpha-pypi.result != 'success'" in job["if"]
    assert cleanup_run == "bash scripts/release_unpublished_alpha_reservation.sh"
    assert "hol-guard plugin-scanner" in script
    assert "%{http_code}" in script
    assert "Not Found" in script


def test_native_guard_wheel_timeout_covers_in_job_release_compiles() -> None:
    native = native_wheel_job()
    assert native["timeout-minutes"] == 90


def test_windows_native_guard_wheel_uses_reproducible_linker_mode() -> None:
    jobs = load_workflow(PUBLISH_WORKFLOW)["jobs"]
    native = native_wheel_job()
    selector = next(step for step in jobs["build"]["steps"] if step.get("id") == "native_wheel_matrix")
    legs = json.loads(selector["env"]["NATIVE_WHEEL_MATRIX"])
    windows = [row for row in legs if row["platform_tag"] in {"win_amd64", "win_arm64"}]
    build = next(step for step in native["steps"] if step.get("name") == "Build version-matched runtime")
    assert [row["rustflags"] for row in windows] == ["-C link-arg=/Brepro"] * 2
    assert build["env"]["RUSTFLAGS"] == "${{ matrix.rustflags }}"
