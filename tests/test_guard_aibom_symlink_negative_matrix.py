"""Parametric negative symlink matrix for portal scenarios D-07, D-08, D-09, and D-12-secret-like.

D-10 and D-11 are registry/local trust-score scenarios, not symlink negatives.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.aibom_symlink import inspect_aibom_source_path
from codex_plugin_scanner.guard.inventory_contract import (
    inventory_snapshot_from_detection,
    serialize_inventory_snapshot,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection

SCENARIO_MATRIX = (
    pytest.param(
        "D-07",
        "broken",
        "broken",
        "aibom.symlink.broken",
        id="D-07-broken",
    ),
    pytest.param(
        "D-08",
        "loop",
        "loop",
        "aibom.symlink.loop",
        id="D-08-loop",
    ),
    pytest.param(
        "D-09",
        "escape",
        "escape_blocked",
        "aibom.symlink.escape_blocked",
        id="D-09-escape",
    ),
    pytest.param(
        "D-12-secret-like",
        "secret-like",
        "escape_blocked",
        "aibom.symlink.escape_blocked",
        id="D-12-secret-like",
    ),
)


def _build_workspace(tmp_path: Path, scenario: str) -> tuple[Path, Path]:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    if scenario == "broken":
        broken = workspace / "broken-link"
        broken.symlink_to(workspace / "missing-target")
        return broken, workspace
    if scenario == "loop":
        loop_a = workspace / "loop-a"
        loop_b = workspace / "loop-b"
        loop_a.symlink_to(loop_b)
        loop_b.symlink_to(loop_a)
        return loop_a, workspace
    if scenario in {"escape", "secret-like"}:
        outside = tmp_path / "outside"
        outside.mkdir()
        if scenario == "secret-like":
            (outside / ".env").write_text("API_KEY=hol_test_secret_should_not_escape\n", encoding="utf-8")
            target = outside / ".env"
        else:
            (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
            target = outside / "secret.txt"
        escape = workspace / "escape-link"
        escape.symlink_to(target)
        return escape, workspace
    raise AssertionError(f"Unknown scenario fixture: {scenario}")


@pytest.mark.parametrize(
    ("scenario_id", "fixture_name", "validation_state", "finding_check_id"),
    SCENARIO_MATRIX,
)
def test_aibom_symlink_negative_matrix_fails_closed(
    tmp_path: Path,
    scenario_id: str,
    fixture_name: str,
    validation_state: str,
    finding_check_id: str,
) -> None:
    path, workspace = _build_workspace(tmp_path, fixture_name)
    home = tmp_path / "home"

    inspection = inspect_aibom_source_path(
        path,
        safe_roots=(workspace,),
        home_dir=home,
        workspace_dir=workspace,
    )
    assert inspection.validation_state == validation_state

    snapshot = inventory_snapshot_from_detection(
        HarnessDetection(
            harness="hermes",
            installed=True,
            command_available=False,
            config_paths=(),
            artifacts=(
                GuardArtifact(
                    artifact_id=f"hermes:skill:{fixture_name}",
                    name=fixture_name,
                    harness="hermes",
                    artifact_type="skill",
                    source_scope="project",
                    config_path=str(path),
                ),
            ),
        ),
        generated_at="2026-06-10T00:00:00Z",
        home_dir=home,
        workspace_dir=workspace,
    )
    source_of_truth = snapshot.items[0].metadata.get("sourceOfTruth")
    assert isinstance(source_of_truth, dict)
    assert source_of_truth.get("validationState") == validation_state
    assert source_of_truth.get("linkKind") == "symlink"
    assert any(finding.check_id == finding_check_id for finding in snapshot.findings)

    serialized = json.dumps(serialize_inventory_snapshot(snapshot))
    assert str(tmp_path) not in serialized
    if fixture_name == "secret-like":
        assert "hol_test_secret_should_not_escape" not in serialized
