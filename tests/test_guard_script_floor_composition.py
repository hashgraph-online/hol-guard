"""A local-script review floor cannot mask an independent blocking risk."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifact_policy import _runtime_artifact_policy_action
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact(*risks: str) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:test:script-floor",
        name="local script with independent risk",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="workspace",
        config_path="fixture",
        metadata={
            "action_class": "local script execution shell command",
            "reason_code": "shell_local_script_execution_review",
            "guard_default_action": "require-reapproval",
            "risk_classes": ["execution", *risks],
        },
    )


@pytest.mark.parametrize("risk", ("destructive_shell", "guard_bypass", "credential_exfiltration"))
def test_script_floor_keeps_independent_paranoid_block(tmp_path: Path, risk: str) -> None:
    config = GuardConfig(guard_home=tmp_path, workspace=None, security_level="paranoid")
    assert _runtime_artifact_policy_action(config, _artifact(risk), "codex") == "block"


def test_script_floor_alone_remains_a_review_contract(tmp_path: Path) -> None:
    config = GuardConfig(guard_home=tmp_path, workspace=None, security_level="paranoid")
    assert _runtime_artifact_policy_action(config, _artifact(), "codex") == "require-reapproval"


def test_script_floor_keeps_explicit_execution_block(tmp_path: Path) -> None:
    config = GuardConfig(guard_home=tmp_path, workspace=None, risk_actions={"execution": "block"})
    assert _runtime_artifact_policy_action(config, _artifact(), "codex") == "block"
