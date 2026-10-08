from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_artifact_policy_action
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)
from tests.native_command_test_support import real_native_review_fixture


def _native_fixture(command: str, *, controls=(), force_rule_ids=("command.git.stash",)):
    fixture = real_native_review_fixture(
        command,
        force_rule_ids=force_rule_ids,
        controls=controls,
    )
    canonical = _canonical_command_from_native(command, fixture.payload["command_model"])
    assert canonical is not None
    evaluation = evaluate_command(
        command,
        canonical_command=canonical,
        extension_control_snapshot=fixture.snapshot,
        native_extension_evidence=fixture.payload,
    )
    return fixture, canonical, evaluation


def _permission_layer(permission_id: str, state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.PERMISSION, permission_id),
                state=state,
            ),
        ),
    )


@pytest.mark.parametrize(
    "command",
    (
        "git stash",
        "git stash push -m wip",
    ),
)
def test_explicit_git_stash_permission_allows_wrapped_shell_forms(command: str, tmp_path: Path) -> None:
    fixture, canonical, evaluation = _native_fixture(
        command,
        controls=(("permission", "command.git.permission.stash", "enabled"),),
    )
    request = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
        canonical_command=canonical,
        native_evaluation=evaluation,
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "grok",
        request,
        config_path="config.toml",
        source_scope="project",
        extension_control_snapshot=fixture.snapshot,
        native_extension_evidence=fixture.payload,
    )

    assert artifact.metadata["command_action_floor"] == "allow"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": False,
        "failures": [],
        "explicitly_enabled_permission_ids": ["command.git.permission.stash"],
    }
    assert (
        _runtime_artifact_policy_action(
            GuardConfig(
                guard_home=tmp_path / "guard",
                workspace=tmp_path,
                default_action="review",
                risk_actions={"destructive_shell": "require-reapproval"},
            ),
            artifact,
            "grok",
        )
        == "allow"
    )


def test_explicit_git_stash_permission_does_not_unwrap_login_shells(tmp_path: Path) -> None:
    command = "zsh -lc 'git stash list'"
    fixture = real_native_review_fixture(
        command,
        controls=(("permission", "command.git.permission.stash", "enabled"),),
    )
    extensions = fixture.payload["command_extensions"]
    assert extensions["evaluation_error"] == "native_command_evaluation_failed"
    assert extensions["observations"] == []
    assert fixture.payload["command_model"]["uncertainty_reason"] == "transparent_wrapper_not_yet_supported"
    request = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "grok",
        request,
        config_path="config.toml",
        source_scope="project",
    )

    assert artifact.metadata["command_action_floor"] == "review"
    assert artifact.metadata["native_extension_evidence"] == "unavailable"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": True,
        "failures": ["native-evidence-unavailable"],
    }


def test_explicit_permission_allow_keeps_harness_risk_blocks(tmp_path: Path) -> None:
    command = "gh pr merge 5115 --repo example/project --squash --auto"
    fixture, canonical, evaluation = _native_fixture(
        command,
        force_rule_ids=(),
        controls=(("permission", "command.github.permission.merge-remote", "enabled"),),
    )
    request = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
        canonical_command=canonical,
        native_evaluation=evaluation,
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "codex",
        request,
        config_path="config.toml",
        source_scope="project",
        extension_control_snapshot=fixture.snapshot,
        native_extension_evidence=fixture.payload,
    )
    risk_classes = artifact.metadata["risk_classes"]
    assert isinstance(risk_classes, list) and risk_classes
    base = dict(guard_home=tmp_path / "guard", workspace=tmp_path, default_action="review")

    assert (
        _runtime_artifact_policy_action(
            GuardConfig(**base, artifact_actions={artifact.artifact_id: "block"}), artifact, "codex"
        )
        == "block"
    )
    assert (
        _runtime_artifact_policy_action(
            GuardConfig(**base, risk_actions={str(risk_classes[0]): "block"}), artifact, "codex"
        )
        == "allow"
    )
    assert (
        _runtime_artifact_policy_action(
            GuardConfig(
                **base,
                harness_risk_actions={"codex": {str(risk_classes[0]): "block"}},
            ),
            artifact,
            "codex",
        )
        == "block"
    )
