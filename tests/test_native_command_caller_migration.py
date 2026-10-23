from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_github_workflow as workflow_hook
from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
)


def test_activity_read_only_authority_upgrade_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    with pytest.raises(NativeCommandControlMutationRequiredError):
        activity._evaluate_payload_command(
            {"tool_name": "Shell", "tool_input": {"command": "git push origin main"}},
            store=store,
            guard_home=tmp_path / "guard",
            cwd=tmp_path,
            home_dir=tmp_path,
        )


_WORKFLOW_ARTIFACT = GuardArtifact(
    artifact_id="codex:project:tool-action:github",
    name="GitHub workflow",
    harness="codex",
    artifact_type="tool_action_request",
    source_scope="project",
    config_path="redacted",
    command="gh run rerun 1",
)


def _workflow_hook_without_resident(monkeypatch: pytest.MonkeyPatch, claims: list[object]) -> SimpleNamespace:
    descriptor = SimpleNamespace(record=None, command_identity="command-security-v2:test")
    monkeypatch.setattr(workflow_hook, "_runtime_github_workflow_descriptor", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(workflow_hook, "github_workflow_capability_required", lambda *_args: True)
    monkeypatch.setattr(workflow_hook, "resolved_github_workflow_capability_preflight", lambda *_args: True)
    monkeypatch.setattr(
        workflow_hook,
        "claim_resolved_github_workflow_authorization",
        lambda *args: claims.append(args) or object(),
    )
    monkeypatch.setattr(
        workflow_hook,
        "ExtensionControlRuntimeSnapshot",
        SimpleNamespace(from_authority_view=lambda _view: object()),
    )
    return SimpleNamespace(read_extension_control_authority_for_registry=lambda *_args, **_kwargs: object())


def _prepare(tmp_path: Path, store: object) -> object:
    return workflow_hook.prepare_github_workflow_hook_state(
        _WORKFLOW_ARTIFACT,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
        config=GuardConfig(guard_home=tmp_path / "guard", workspace=tmp_path),
        store=store,
        approval_request_id="request-1",
    )


def test_workflow_resident_miss_is_an_outage_and_spends_no_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claims: list[object] = []
    store = _workflow_hook_without_resident(monkeypatch, claims)
    monkeypatch.setattr(workflow_hook, "native_command_review", lambda *_args, **_kwargs: None)

    with pytest.raises(workflow_hook.GitHubWorkflowEvaluationUnavailableError) as error:
        _prepare(tmp_path, store)

    assert error.value.code == "native_github_workflow_evaluation_unavailable"
    assert claims == []


def test_workflow_unresolved_review_is_an_outage_not_a_python_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claims: list[object] = []
    store = _workflow_hook_without_resident(monkeypatch, claims)
    review = SimpleNamespace(native={"minimum_action": "review"})
    monkeypatch.setattr(workflow_hook, "native_command_review", lambda *_args, **_kwargs: review)
    monkeypatch.setattr(workflow_hook, "resolve_native_command_review", lambda *_args, **_kwargs: None)

    with pytest.raises(workflow_hook.GitHubWorkflowEvaluationUnavailableError) as error:
        _prepare(tmp_path, store)

    assert error.value.code == "native_github_workflow_evaluation_unavailable"
    assert len(claims) == 1


def test_workflow_without_a_live_capability_asks_the_resident_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claims: list[object] = []
    store = _workflow_hook_without_resident(monkeypatch, claims)
    monkeypatch.setattr(workflow_hook, "resolved_github_workflow_capability_preflight", lambda *_args: False)
    monkeypatch.setattr(
        workflow_hook,
        "native_command_review",
        lambda *_args, **_kwargs: pytest.fail("an approval with no live capability needs no resident review"),
    )

    state = _prepare(tmp_path, store)

    assert state.authorization_claimed is False
    assert claims == []


def test_workflow_resident_block_leaves_the_approval_use_unspent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claims: list[object] = []
    store = _workflow_hook_without_resident(monkeypatch, claims)
    review = SimpleNamespace(native={"minimum_action": "block"})
    monkeypatch.setattr(workflow_hook, "native_command_review", lambda *_args, **_kwargs: review)
    monkeypatch.setattr(
        workflow_hook,
        "resolve_native_command_review",
        lambda *_args, **_kwargs: pytest.fail("a resident block is never resolved against a workflow proof"),
    )

    state = _prepare(tmp_path, store)

    assert state.authorization_claimed is False
    assert claims == []
