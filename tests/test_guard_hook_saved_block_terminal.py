"""Regression coverage for terminal saved blocks in hook-specific flows."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_copilot as copilot_hook
from codex_plugin_scanner.guard.cli import commands_hook_runtime_review as runtime_review
from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import RuntimeArtifactHookState
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.receipts import build_receipt
from codex_plugin_scanner.guard.store import GuardStore


def _artifact(tmp_path: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="copilot:project:tool-action:saved-block",
        name="Copilot saved-block tool call",
        harness="copilot",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(tmp_path / ".vscode" / "mcp.json"),
        command="dangerous_delete",
    )


def _context(tmp_path: Path) -> HarnessContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / "guard-home",
    )


def _saved_block_decision() -> ToolCallDecision:
    return ToolCallDecision(
        action="block",
        source="policy",
        signals=("tool name implies destructive file or system changes",),
        summary="Local Guard kept this tool call blocked by saved policy.",
        risk_categories=("destructive_mutation",),
        approval_reuse_status="accepted",
        approval_reuse_reason_code="approval_reuse_saved_block",
        current_action="review",
        saved_action="block",
    )


def _fresh_block_decision() -> ToolCallDecision:
    return ToolCallDecision(
        action="block",
        source="heuristic",
        signals=("tool name implies destructive file or system changes",),
        summary="The current call is destructive.",
        risk_categories=("destructive_mutation",),
    )


def _saved_allow_decision() -> ToolCallDecision:
    return ToolCallDecision(
        action="allow",
        source="policy",
        signals=("tool name implies destructive file or system changes",),
        summary="Local Guard reused an exact saved approval for this tool call.",
        risk_categories=("destructive_mutation",),
        approval_reuse_status="accepted",
        approval_reuse_reason_code="approval_reuse_accepted",
        current_action="review",
        saved_action="allow",
    )


def _copilot_args(*, json_output: bool = False) -> argparse.Namespace:
    return argparse.Namespace(harness="copilot", json=json_output)


def _fail_queue(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
    raise AssertionError("a terminal saved block must not be queued for approval")


def _receipt_reuse_evidence(store: GuardStore) -> dict[str, object]:
    receipt = store.list_receipts(limit=1)[0]
    evidence = receipt["scanner_evidence"]
    assert isinstance(evidence, list)
    typed_evidence = [item for item in evidence if isinstance(item, dict)]
    return next(item for item in typed_evidence if item.get("source") == "approval_reuse")


def _runtime_receipt(artifact: GuardArtifact, artifact_hash: str, policy_action: str):
    return build_receipt(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_action,
        capabilities_summary="runtime tool action",
        changed_capabilities=["runtime_tool_call"],
        provenance_summary=f"runtime tool request evaluated from {artifact.config_path}",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
    )


def test_runtime_review_observe_mode_keeps_saved_block_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    context = _context(tmp_path)
    artifact_hash = "guard-approval-context:v1:saved-block"
    state = RuntimeArtifactHookState(
        action_envelope=None,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        browser_approval_daemon_client=None,
        changed_capabilities=["runtime_tool_call"],
        decision_signals=(),
        decision_v2_payload={},
        event_name="PreToolUse",
        initial_policy_action="block",
        package_evaluation=None,
        policy_action="block",
        receipt=_runtime_receipt(artifact, artifact_hash, "block"),
        requested_policy_action=None,
        response_payload={"policy_action": "block"},
        risk_summary="Saved policy blocks this action.",
        runtime_artifact=artifact,
        runtime_artifact_hash=artifact_hash,
        scanner_evidence_payload=[],
        stored_policy_action="block",
    )
    emitted_actions: list[str] = []
    monkeypatch.setattr(runtime_review, "_runtime_artifact_native_reason", lambda *_args, **_kwargs: "blocked")
    monkeypatch.setattr(runtime_review, "_claude_prompt_additional_context", lambda **_kwargs: None)
    monkeypatch.setattr(runtime_review, "_should_emit_copilot_hook_response", lambda _args: True)
    monkeypatch.setattr(runtime_review, "_record_harness_usage_for_hook", lambda **_kwargs: None)
    monkeypatch.setattr(runtime_review, "_copilot_hook_reason", lambda *_args: "blocked")
    monkeypatch.setattr(
        runtime_review,
        "_emit_copilot_hook_response",
        lambda **kwargs: emitted_actions.append(str(kwargs["policy_action"])),
    )
    monkeypatch.setattr(runtime_review, "ensure_guard_daemon", _fail_queue)
    monkeypatch.setattr(runtime_review, "queue_blocked_approvals", _fail_queue)

    result = runtime_review._review_runtime_artifact_hook(
        state,
        _copilot_args(),
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="observe"),
        context=context,
        guard_home=context.guard_home,
        managed_install=None,
        payload={"hook_event_name": "PreToolUse", "tool_name": "dangerous_delete"},
        store=GuardStore(context.guard_home),
        workspace=context.workspace_dir,
    )

    assert result == 0
    assert state.policy_action == "block"
    assert state.response_payload["policy_action"] == "block"
    assert emitted_actions == ["block"]


def test_runtime_review_observe_mode_allows_fresh_block_without_approval_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    context = _context(tmp_path)
    artifact_hash = "guard-approval-context:v1:fresh-block"
    state = RuntimeArtifactHookState(
        action_envelope=None,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        browser_approval_daemon_client=None,
        changed_capabilities=["runtime_tool_call"],
        decision_signals=(),
        decision_v2_payload={},
        event_name="PreToolUse",
        initial_policy_action="block",
        package_evaluation=None,
        policy_action="block",
        receipt=_runtime_receipt(artifact, artifact_hash, "block"),
        requested_policy_action=None,
        response_payload={"policy_action": "block"},
        risk_summary="The current call is destructive.",
        runtime_artifact=artifact,
        runtime_artifact_hash=artifact_hash,
        scanner_evidence_payload=[],
        stored_policy_action=None,
    )
    monkeypatch.setattr(runtime_review, "ensure_guard_daemon", _fail_queue)
    monkeypatch.setattr(runtime_review, "queue_blocked_approvals", _fail_queue)

    result = runtime_review._review_runtime_artifact_hook(
        state,
        _copilot_args(json_output=True),
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="observe"),
        context=context,
        guard_home=context.guard_home,
        managed_install=None,
        payload={"hook_event_name": "PreToolUse", "tool_name": "dangerous_delete"},
        store=GuardStore(context.guard_home),
        workspace=context.workspace_dir,
    )

    assert result is None
    assert state.policy_action == "allow"
    assert state.response_payload["policy_action"] == "allow"
    assert state.response_payload["approval_requests"] == []
    assert state.response_payload["observed_terminal_action"] == "block"


def test_copilot_pretool_observe_mode_keeps_saved_block_terminal_with_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    output = io.StringIO()
    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", lambda **_kwargs: _saved_block_decision())
    monkeypatch.setattr(copilot_hook, "_queue_observed_copilot_approval", _fail_queue)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)

    result = copilot_hook._run_hook_copilot_pretool(
        _copilot_args(),
        action_envelope=None,
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="observe"),
        context=context,
        copilot_hook_stage="pretooluse",
        copilot_runtime_tool_call=(artifact, "saved-block-hash", {"target": "important.txt"}),
        output_stream=output,
        payload={"tool_name": "dangerous_delete"},
        runtime_workspace=context.workspace_dir,
        store=store,
    )

    response = cast(dict[str, object], json.loads(output.getvalue()))
    assert result == 0
    assert response["permissionDecision"] == "deny"
    assert "approve" not in str(response["permissionDecisionReason"]).lower()
    assert response["approval_reuse"] == {
        "status": "accepted",
        "reason_code": "approval_reuse_saved_block",
        "current_action": "review",
        "saved_action": "block",
        "effective_action": "block",
    }
    approval_reuse = response["approval_reuse"]
    scanner_evidence = response["scanner_evidence"]
    assert isinstance(approval_reuse, dict)
    assert isinstance(scanner_evidence, list)
    assert scanner_evidence[0] == {"source": "approval_reuse", **approval_reuse}
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "block"
    assert _receipt_reuse_evidence(store) == {"source": "approval_reuse", **approval_reuse}
    assert store.list_approval_requests(limit=10) == []


def test_copilot_permission_request_saved_block_is_terminal_and_never_queued(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    output = io.StringIO()
    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", lambda **_kwargs: _saved_block_decision())
    monkeypatch.setattr(copilot_hook, "_queue_observed_copilot_approval", _fail_queue)
    monkeypatch.setattr(copilot_hook, "ensure_guard_daemon", _fail_queue)
    monkeypatch.setattr(copilot_hook, "queue_blocked_approvals", _fail_queue)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)

    result = copilot_hook._run_hook_copilot_permission_request(
        _copilot_args(),
        action_envelope=None,
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="observe"),
        context=context,
        copilot_permission_request=(artifact, "saved-block-hash", {"target": "important.txt"}),
        guard_home=context.guard_home,
        managed_install=None,
        output_stream=output,
        payload={"tool_name": "dangerous_delete"},
        runtime_workspace=context.workspace_dir,
        store=store,
    )

    response = cast(dict[str, object], json.loads(output.getvalue()))
    assert result == 0
    assert response["behavior"] == "deny"
    assert response["interrupt"] is True
    assert "approve" not in str(response["message"]).lower()
    approval_reuse = response["approval_reuse"]
    scanner_evidence = response["scanner_evidence"]
    assert isinstance(approval_reuse, dict)
    assert isinstance(scanner_evidence, list)
    assert approval_reuse["saved_action"] == "block"
    assert approval_reuse["effective_action"] == "block"
    first_evidence = scanner_evidence[0]
    assert isinstance(first_evidence, dict)
    assert first_evidence["reason_code"] == "approval_reuse_saved_block"
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "block"
    assert _receipt_reuse_evidence(store)["reason_code"] == "approval_reuse_saved_block"
    assert store.list_approval_requests(limit=10) == []


def test_copilot_permission_request_fresh_block_is_terminal_and_never_queued(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    output = io.StringIO()
    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", lambda **_kwargs: _fresh_block_decision())
    monkeypatch.setattr(copilot_hook, "_queue_observed_copilot_approval", _fail_queue)
    monkeypatch.setattr(copilot_hook, "ensure_guard_daemon", _fail_queue)
    monkeypatch.setattr(copilot_hook, "queue_blocked_approvals", _fail_queue)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)

    result = copilot_hook._run_hook_copilot_permission_request(
        _copilot_args(),
        action_envelope=None,
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="prompt"),
        context=context,
        copilot_permission_request=(artifact, "fresh-block-hash", {"target": "important.txt"}),
        guard_home=context.guard_home,
        managed_install=None,
        output_stream=output,
        payload={"tool_name": "dangerous_delete"},
        runtime_workspace=context.workspace_dir,
        store=store,
    )

    response = cast(dict[str, object], json.loads(output.getvalue()))
    assert result == 0
    assert response["behavior"] == "deny"
    assert response["interrupt"] is True
    assert "approve" not in str(response["message"]).lower()
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "block"
    assert store.list_approval_requests(limit=10) == []


def test_copilot_saved_allow_is_explained_in_native_response_and_allow_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    output = io.StringIO()
    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", lambda **_kwargs: _saved_allow_decision())
    monkeypatch.setattr(copilot_hook, "_queue_observed_copilot_approval", _fail_queue)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)

    result = copilot_hook._run_hook_copilot_pretool(
        _copilot_args(),
        action_envelope=None,
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="observe"),
        context=context,
        copilot_hook_stage="pretooluse",
        copilot_runtime_tool_call=(artifact, "saved-allow-hash", {"target": "approved.txt"}),
        output_stream=output,
        payload={"tool_name": "dangerous_delete"},
        runtime_workspace=context.workspace_dir,
        store=store,
    )

    response = cast(dict[str, object], json.loads(output.getvalue()))
    approval_reuse = response["approval_reuse"]
    assert isinstance(approval_reuse, dict)
    assert result == 0
    assert response["permissionDecision"] == "allow"
    assert approval_reuse["status"] == "accepted"
    assert approval_reuse["reason_code"] == "approval_reuse_accepted"
    assert approval_reuse["current_action"] == "review"
    assert approval_reuse["saved_action"] == "allow"
    assert approval_reuse["effective_action"] == "allow"
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "allow"
    assert _receipt_reuse_evidence(store) == {"source": "approval_reuse", **approval_reuse}


@pytest.mark.parametrize("flow", ("pretool", "permission-request"))
def test_copilot_observe_mode_allows_fresh_block_without_approval_queue(
    flow: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    output = io.StringIO()
    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", lambda **_kwargs: _fresh_block_decision())
    monkeypatch.setattr(copilot_hook, "_queue_observed_copilot_approval", _fail_queue)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)
    config = GuardConfig(context.guard_home, context.workspace_dir, mode="observe")
    if flow == "pretool":
        result = copilot_hook._run_hook_copilot_pretool(
            _copilot_args(),
            action_envelope=None,
            config=config,
            context=context,
            copilot_hook_stage="pretooluse",
            copilot_runtime_tool_call=(artifact, "fresh-block-hash", {"target": "important.txt"}),
            output_stream=output,
            payload={"tool_name": "dangerous_delete"},
            runtime_workspace=context.workspace_dir,
            store=store,
        )
    else:
        result = copilot_hook._run_hook_copilot_permission_request(
            _copilot_args(),
            action_envelope=None,
            config=config,
            context=context,
            copilot_permission_request=(artifact, "fresh-block-hash", {"target": "important.txt"}),
            guard_home=context.guard_home,
            managed_install=None,
            output_stream=output,
            payload={"tool_name": "dangerous_delete"},
            runtime_workspace=context.workspace_dir,
            store=store,
        )

    response = cast(dict[str, object], json.loads(output.getvalue()))
    assert result == 0
    assert response.get("permissionDecision", response.get("behavior")) == "allow"
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "allow"
    scanner_evidence = receipt["scanner_evidence"]
    assert isinstance(scanner_evidence, list)
    assert not any(item.get("source") == "approval_reuse" for item in scanner_evidence if isinstance(item, dict))
