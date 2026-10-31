from __future__ import annotations

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
    _runtime_artifact_command_action_floor,
)
from codex_plugin_scanner.guard.models import GuardArtifact


def test_compound_action_floor_applies_to_non_tool_action_primary() -> None:
    artifact = GuardArtifact(
        artifact_id="test:package",
        name="package request",
        harness="codex",
        artifact_type="package_request",
        source_scope="project",
        config_path="guard-config",
        metadata={"command_action_floor": "require-reapproval"},
    )

    assert _runtime_artifact_command_action_floor(artifact) == "require-reapproval"
