"""HGP-183: policy permissions at the Python launch/action boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifact_policy import (
    _runtime_artifact_policy_action,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact


def _config(tmp_path: Path, *, default_action: str) -> GuardConfig:
    return GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path, default_action=default_action)


def _artifact(kind: str, *, harness: str = "codex") -> GuardArtifact:
    metadata: dict[str, object] = {"action_class": kind}
    if kind == "mcp":
        metadata["tool_name"] = "mcp__server__tool"
    if kind == "package":
        metadata["package_name"] = "demo-pkg"
    return GuardArtifact(
        artifact_id=f"{harness}:{kind}:canary",
        name=kind,
        harness=harness,
        artifact_type=kind,
        source_scope="project",
        config_path="/workspace/config.toml",
        command="echo canary" if kind == "shell" else None,
        metadata=metadata,
    )


@pytest.mark.parametrize("kind", ["shell", "file_read", "mcp", "package"])
@pytest.mark.parametrize("action", ["allow", "review", "block"])
def test_explicit_launch_floors_have_exact_outcomes(tmp_path: Path, kind: str, action: str) -> None:
    artifact = _artifact(kind)
    artifact.metadata["guard_default_action"] = "allow"
    assert _runtime_artifact_policy_action(_config(tmp_path, default_action=action), artifact, "codex") == action


def test_harness_contract_records_known_blind_spots() -> None:
    assert any(contract.known_blind_spots for contract in HARNESS_CONTRACTS)
