"""Contracts for unpublished alpha reservation recovery."""

from __future__ import annotations

from tests.release_workflow_helpers import PUBLISH_WORKFLOW, ROOT, load_workflow


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


def test_native_guard_wheel_timeout_covers_musl_builds() -> None:
    native = load_workflow(PUBLISH_WORKFLOW)["jobs"]["build-native-guard-wheels"]
    assert native["timeout-minutes"] == 45


def test_windows_native_guard_wheel_uses_reproducible_linker_mode() -> None:
    native = load_workflow(PUBLISH_WORKFLOW)["jobs"]["build-native-guard-wheels"]
    windows = next(row for row in native["strategy"]["matrix"]["include"] if row["platform_tag"] == "win_amd64")
    build = next(step for step in native["steps"] if step.get("name") == "Build version-matched runtime")
    assert windows["rustflags"] == "-C link-arg=/Brepro"
    assert build["env"]["RUSTFLAGS"] == "${{ matrix.rustflags }}"
