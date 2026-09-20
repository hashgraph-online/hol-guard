from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_artifact_policy_action
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
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


def _github_permission_layer(permission_id: str, state: ControlState) -> ExtensionControlLayer:
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
        (
            "gh api -X PUT repos/example/project/pulls/5115/merge -f merge_method=squash "
            '--field commit_title="feat: bounded title (#5115)"'
        ),
        "gh pr merge 5115 --repo example/project --squash --auto",
    ),
)
def test_explicit_github_merge_permission_allows_exact_merge_through_runtime_artifact(
    command: str,
    tmp_path: Path,
) -> None:
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    layer = _github_permission_layer("command.github.permission.merge-remote", ControlState.ENABLED)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=7,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
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

    assert artifact.metadata["command_action_floor"] == "allow"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": False,
        "failures": [],
        "explicitly_enabled_permission_ids": ["command.github.permission.merge-remote"],
    }
    decision_plane = artifact.metadata["command_decision_plane"]
    assert isinstance(decision_plane, dict)
    assert decision_plane["proof_routes"] == ["verified"]
    assert decision_plane["controlling_reasons"] == [
        {
            "source": "control",
            "reason_code": "control.explicitly-enabled-permission",
            "action_floor": "allow",
            "segment_ref": None,
            "operation_ref": None,
        }
    ]


@pytest.mark.parametrize("executable", ("gh", "gh.exe"))
def test_explicit_github_content_permission_applies_without_matcher_owned_rule(tmp_path: Path, executable: str) -> None:
    command = f'{executable} pr edit 123 --repo example/project --title "fix: corrected title"'
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    layer = _github_permission_layer("command.github.permission.content-remote", ControlState.ENABLED)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=8,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
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

    assert artifact.metadata["command_action_floor"] == "allow"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": False,
        "failures": [],
        "explicitly_enabled_permission_ids": ["command.github.permission.content-remote"],
    }


@pytest.mark.parametrize(
    ("health", "state", "expected_action_class"),
    (
        (AuthorityHealth.PROTECTED, ControlState.ENABLED, None),
        (AuthorityHealth.PROTECTED, ControlState.DISABLED, "GitHub pull-request proposal command"),
        (AuthorityHealth.TAMPERED, ControlState.ENABLED, "GitHub pull-request proposal command"),
    ),
)
def test_github_pr_create_body_file_honors_proposal_permission_toggle(
    tmp_path: Path,
    health: AuthorityHealth,
    state: ControlState,
    expected_action_class: str | None,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "CascadeProjects" / "hashgraph-online"
    body_directory = home_dir / "CascadeProjects" / "hol-guard-protection-posture"
    workspace.mkdir(parents=True)
    body_directory.mkdir()
    body_file = body_directory / "PR_BODY_PROTECTION.md"
    body_file.write_text("## Summary\n- Add the protection posture.\n", encoding="utf-8")
    command = (
        "gh pr create --repo hashgraph-online/hol-guard --base release/3.0 "
        "--head feat/protection-posture "
        "--title 'feat(guard): add protection_posture with dual-write to mode and level' "
        "--body-file ~/CascadeProjects/hol-guard-protection-posture/PR_BODY_PROTECTION.md"
    )
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=health,
            revision=9,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(_github_permission_layer("command.github.permission.propose-remote", state),),
        )
    )

    with use_extension_control_snapshot(snapshot):
        request = extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=workspace,
            home_dir=home_dir,
        )

    if expected_action_class is None:
        assert request is None
    else:
        assert request is not None
        assert request.action_class == expected_action_class


def test_explicit_git_force_push_permission_allows_matcher_owned_rule(tmp_path: Path) -> None:
    command = "git push --force origin feature"
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    layer = _github_permission_layer("command.git.permission.force-push", ControlState.ENABLED)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=8,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
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

    assert artifact.metadata["command_action_floor"] == "allow"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": False,
        "failures": [],
        "explicitly_enabled_permission_ids": ["command.git.permission.force-push"],
    }


def test_explicit_permission_allow_cannot_override_explicit_policy(tmp_path: Path) -> None:
    command = "gh pr merge 5115 --repo example/project --squash --auto"
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    layer = _github_permission_layer("command.github.permission.merge-remote", ControlState.ENABLED)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=9,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
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


def test_explicit_permission_allow_requires_protected_authority(tmp_path: Path) -> None:
    command = "gh pr merge 5115 --repo example/project --squash --auto"
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    layer = _github_permission_layer("command.github.permission.merge-remote", ControlState.ENABLED)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.UNENROLLED,
            revision=0,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
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

    assert artifact.metadata["command_action_floor"] == "block"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": True,
        "failures": ["authority-unavailable"],
    }


@pytest.mark.parametrize(
    ("command", "permission_ids", "expected_floor"),
    (
        (
            "gh pr merge 5115 --repo example/project --squash --auto",
            ("command.github.permission.merge-remote",),
            "require-reapproval",
        ),
        ("gh pr merge 5115 --repo example/project --squash --auto", (), "require-reapproval"),
        (
            "gh pr merge 5115 --repo example/project --delete-branch",
            ("command.github.permission.merge-remote",),
            "require-reapproval",
        ),
        (
            "gh repo sync example/project --force",
            ("command.github.permission.force-remote",),
            "block",
        ),
        (
            "sh -c 'gh pr merge 5115 --repo example/project --squash --auto'",
            ("command.github.permission.merge-remote",),
            "require-reapproval",
        ),
    ),
)
def test_github_permission_allow_cannot_weaken_uncovered_or_hard_floors(
    command: str,
    permission_ids: tuple[str, ...],
    expected_floor: str,
    tmp_path: Path,
) -> None:
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    controls = tuple(
        ExtensionControl(
            target=ControlTarget(ControlTargetKind.PERMISSION, permission_id),
            state=ControlState.ENABLED,
        )
        for permission_id in permission_ids
    )
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=controls,
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "codex",
        request,
        config_path="config.toml",
        source_scope="project",
        extension_control_layers=(layer,),
    )

    assert artifact.metadata["command_action_floor"] == expected_floor


def test_managed_github_merge_block_dominates_local_allow(tmp_path: Path) -> None:
    command = "gh pr merge 5115 --repo example/project --squash --auto"
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    permission_id = "command.github.permission.merge-remote"
    local = _github_permission_layer(permission_id, ControlState.ENABLED)
    managed = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.PERMISSION, permission_id),
                state=ControlState.DISABLED,
            ),
        ),
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "codex",
        request,
        config_path="config.toml",
        source_scope="project",
        extension_control_layers=(local, managed),
    )

    assert artifact.metadata["command_action_floor"] == "block"
    assert artifact.metadata["extension_control_resolution"] == {
        "blocked": True,
        "failures": [],
    }


def test_managed_routine_merge_block_still_gates_merged_branch_cleanup(tmp_path: Path) -> None:
    command = (
        "gh pr merge 5134 --repo example/project --squash --delete-branch && "
        "gh pr view 5134 --repo example/project --json state,mergedAt,mergeCommit,url"
    )
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(
                    ControlTargetKind.PERMISSION,
                    "command.github.permission.routine-merge-remote",
                ),
                state=ControlState.DISABLED,
            ),
        ),
    )
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=10,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            layers=(layer,),
        )
    )

    with use_extension_control_snapshot(snapshot):
        request = extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )

    assert request is not None
    assert request.action_class == "GitHub routine pull-request merge command"


def test_inspection_and_runtime_artifact_share_canonical_wrapper_evidence(tmp_path: Path) -> None:
    command = "sudo --command-timeout 10 git push origin main --force"
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    request = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "codex",
        request,
        config_path="config.toml",
        source_scope="project",
    )

    assert payload["classification"]["wrapper_chain"] == ["sudo"]
    assert artifact.metadata["wrapper_chain"] == ["sudo"]


def test_inspection_parses_each_command_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime import command_inspection as inspection_module

    real_parser = inspection_module.parse_shell_command
    calls = 0

    def counting_parser(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return real_parser(*args, **kwargs)

    monkeypatch.setattr(inspection_module, "parse_shell_command", counting_parser)

    payload = inspect_command("git push origin main --force", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert calls == 1
