from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_github_workflow as workflow_hook
from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity
from codex_plugin_scanner.guard.cli import commands_support_compound_decision as compound
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
)


def test_compound_native_unavailable_is_explicit_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del monkeypatch

    assert compound.compound_command_decision_metadata(
        "git push origin main",
        native_review=None,
        workspace=tmp_path,
        home_dir=tmp_path,
    ) == {
        "command_action_floor": "require-reapproval",
        "command_evaluation_status": "native_unavailable",
    }


def test_activity_read_only_authority_upgrade_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SimpleNamespace(
        read_extension_control_authority_for_registry=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            NativeCommandControlMutationRequiredError()
        )
    )
    monkeypatch.setattr(
        activity,
        "evaluate_command_native",
        lambda *_args, **_kwargs: pytest.fail("native evaluation must not run without a read-only snapshot"),
    )

    assert (
        activity._evaluate_payload_command(
            {"tool_name": "Shell", "tool_input": {"command": "git push origin main"}},
            store=store,
            guard_home=tmp_path / "guard",
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_workflow_native_unavailable_does_not_fabricate_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = object()
    store = SimpleNamespace(read_extension_control_authority_for_registry=lambda *_args, **_kwargs: object())
    monkeypatch.setattr(workflow_hook, "_runtime_github_workflow_descriptor", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(workflow_hook.GitHubWorkflowApprovalRecord, "from_descriptor", lambda _descriptor: None)
    monkeypatch.setattr(workflow_hook, "github_workflow_capability_required", lambda *_args: True)
    monkeypatch.setattr(workflow_hook, "claim_resolved_github_workflow_authorization", lambda *_args: object())
    monkeypatch.setattr(
        workflow_hook,
        "ExtensionControlRuntimeSnapshot",
        SimpleNamespace(from_authority_view=lambda _view: object()),
    )
    monkeypatch.setattr(workflow_hook, "evaluate_command_native", lambda *_args, **_kwargs: None)
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:github",
        name="GitHub workflow",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="redacted",
        command="gh run rerun 1",
    )

    state = workflow_hook.prepare_github_workflow_hook_state(
        artifact,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
        config=GuardConfig(guard_home=tmp_path / "guard", workspace=tmp_path),
        store=store,
        approval_request_id="request-1",
    )

    assert state.authorization_claimed is True
    assert state.artifact.metadata["command_action_floor"] == "require-reapproval"
    assert state.artifact.metadata["command_evaluation_status"] == "native_unavailable"
    assert "command_decision_plane" not in state.artifact.metadata
