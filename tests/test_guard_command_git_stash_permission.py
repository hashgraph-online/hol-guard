from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_artifact_policy_action
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)


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
        "zsh -lc 'git stash'",
        "zsh -lc 'git stash list'",
    ),
)
def test_explicit_git_stash_permission_allows_wrapped_shell_forms(command: str, tmp_path: Path) -> None:
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=11,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(_permission_layer("command.git.permission.stash", ControlState.ENABLED),),
        )
    )

    assert request is not None
    with use_extension_control_snapshot(snapshot):
        artifact = build_tool_action_request_artifact(
            "grok",
            request,
            config_path="config.toml",
            source_scope="project",
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


def test_explicit_permission_allow_keeps_harness_risk_blocks(tmp_path: Path) -> None:
    command = "gh pr merge 5115 --repo example/project --squash --auto"
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=9,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(_permission_layer("command.github.permission.merge-remote", ControlState.ENABLED),),
        )
    )

    assert request is not None
    with use_extension_control_snapshot(snapshot):
        artifact = build_tool_action_request_artifact(
            "codex",
            request,
            config_path="config.toml",
            source_scope="project",
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
