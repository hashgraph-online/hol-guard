"""Keep CI optimizations bound to trusted inputs and complete release proofs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


@pytest.mark.parametrize("filename", ["publish-mcpb.yml", "publish-mcp-registry.yml"])
def test_downstream_publication_requires_successful_same_repository_release(filename: str) -> None:
    workflow = _workflow(filename)
    # PyYAML's YAML 1.1 loader parses the unquoted Actions key as True.
    trigger = workflow[True]
    assert "push" not in trigger
    assert trigger["workflow_run"] == {
        "workflows": ["Publish to PyPI"],
        "types": ["completed"],
        "branches": ["main", "release/3.0"],
    }
    job = workflow["jobs"]["publish"]
    for condition in (
        "github.event.workflow_run.conclusion == 'success'",
        'contains(fromJSON(\'["push", "workflow_dispatch"]\'), github.event.workflow_run.event)',
        "github.event.workflow_run.run_attempt == 1",
        "github.event.workflow_run.head_repository.full_name == github.repository",
        "github.event.workflow_run.head_branch)",
        "[skip release publish]",
    ):
        assert condition in job["if"]
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ github.event.workflow_run.head_sha }}"
    assert checkout["with"]["persist-credentials"] is False
    release = next(step for step in job["steps"] if step.get("id") == "release")
    assert release["env"]["SOURCE_SHA"] == "${{ github.event.workflow_run.head_sha }}"
    assert release["env"]["SOURCE_REF"] == "refs/heads/${{ github.event.workflow_run.head_branch }}"
    assert 'git tag --points-at "$SOURCE_SHA"' in release["run"]
    if filename == "publish-mcpb.yml":
        validation = workflow["jobs"]["validate"]
        for condition in (
            "github.event_name == 'pull_request'",
            "github.event.workflow_run.conclusion == 'success'",
            'contains(fromJSON(\'["push", "workflow_dispatch"]\'), github.event.workflow_run.event)',
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.head_repository.full_name == github.repository",
            "github.event.workflow_run.head_branch)",
        ):
            assert condition in validation["if"]


@pytest.mark.parametrize(
    "script", ["scripts/build_native_hol_guard_wheel.py", "scripts/ci/native_approval_contract_gate.py"]
)
def test_native_wheel_helpers_run_without_site_packages(script: str) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(ROOT / script), "--help"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_native_wheel_build_keeps_all_platforms_and_integrity_checks() -> None:
    job = _workflow("publish.yml")["jobs"]["build-native-guard-wheels"]
    assert len(job["strategy"]["matrix"]["include"]) == 4
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "uv sync" not in commands
    assert "pip install" not in commands
    assert "native_approval_contract_gate.py --root . --require-release-root" in commands
    assert '"$RUNTIME" self-test --json' in commands
    assert "python scripts/build_native_hol_guard_wheel.py" in commands


def test_duration_telemetry_uses_successful_push_on_target_branch() -> None:
    workflow = _workflow("ci.yml")
    assert set(workflow[True]["pull_request"]["branches"]) <= set(workflow[True]["push"]["branches"])
    job = workflow["jobs"]["test-plan"]
    restore = next(step for step in job["steps"] if step.get("id") == "latest-duration-telemetry")
    assert restore["env"]["TELEMETRY_BRANCH"] == "${{ github.event.pull_request.base.ref || github.ref_name }}"
    command = restore["run"]
    assert '-f branch="$TELEMETRY_BRANCH" -f event=push -f status=success' in command
    assert 'test "$event" = "push"' in command
    assert 'test "$conclusion" = "success"' in command
    assert 'test "$branch" = "$TELEMETRY_BRANCH"' in command
    assert 'test "$workflow_path" = ".github/workflows/ci.yml"' in command
    assert "/actions/runs/${run_id}/artifacts?" in command
    assert "release/3.0" not in command
