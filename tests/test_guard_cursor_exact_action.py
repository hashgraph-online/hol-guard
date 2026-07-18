"""Exact-action regressions for Cursor native hook review projection."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_runtime_review as runtime_review
from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import (
    RuntimeArtifactHookState,
    record_runtime_artifact_hook_receipt,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.receipts import build_receipt
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("action", ["review", "require-reapproval"])
def test_cursor_queue_receipt_and_response_preserve_exact_review_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: GuardAction,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=guard_home)
    store = GuardStore(guard_home)
    artifact = GuardArtifact(
        artifact_id=f"cursor:project:tool-action:{action}",
        name=f"Cursor {action} action",
        harness="cursor",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".cursor" / "hooks.json"),
        command="run_tool",
    )
    artifact_hash = f"sha256:{action}"
    receipt = build_receipt(
        harness="cursor",
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=action,
        capabilities_summary="runtime tool action",
        changed_capabilities=["runtime_tool_call"],
        provenance_summary="Cursor native hook",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
    )
    state = RuntimeArtifactHookState(
        action_envelope=None,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        browser_approval_daemon_client=None,
        changed_capabilities=["runtime_tool_call"],
        decision_signals=(),
        decision_v2_payload={"action": "ask", "reason": action},
        event_name="PreToolUse",
        initial_policy_action=action,
        package_evaluation=None,
        policy_action=action,
        receipt=receipt,
        requested_policy_action=None,
        response_payload={"policy_action": action, "risk_signals": ["requires a decision"]},
        risk_summary="Cursor action requires a decision.",
        runtime_artifact=artifact,
        runtime_artifact_hash=artifact_hash,
        scanner_evidence_payload=[],
        stored_policy_action=None,
    )
    queued_actions: list[object] = []

    def capture_queue(**kwargs: object) -> list[dict[str, object]]:
        evaluation = kwargs["evaluation"]
        assert isinstance(evaluation, dict)
        artifacts = evaluation["artifacts"]
        assert isinstance(artifacts, list)
        queued_action = artifacts[0]["policy_action"]
        queued_actions.append(queued_action)
        return [{"request_id": f"cursor-{action}", "policy_action": queued_action}]

    monkeypatch.setattr(runtime_review, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(
        runtime_review,
        "load_guard_surface_daemon_client",
        lambda _guard_home: (_ for _ in ()).throw(RuntimeError("surface unavailable")),
    )
    monkeypatch.setattr(runtime_review, "queue_blocked_approvals", capture_queue)
    monkeypatch.setattr(runtime_review, "_should_emit_copilot_hook_response", lambda _args: False)
    monkeypatch.setattr(
        runtime_review,
        "_should_emit_prequeue_native_hook_response",
        lambda _args, **_kwargs: False,
    )
    monkeypatch.setattr(runtime_review, "_prompt_requires_hard_block", lambda _artifact: False)
    monkeypatch.setattr(runtime_review, "_attach_primary_approval_link", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runtime_review, "_attach_cursor_pending_approval_request_ids", lambda **_kwargs: None)
    monkeypatch.setattr(runtime_review, "_preferred_approval_review_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runtime_review, "approval_center_hint", lambda **_kwargs: "Review in HOL Guard.")
    monkeypatch.setattr(runtime_review, "_approval_delivery_payload", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(runtime_review, "_localize_pending_approval_copy", lambda *_args, **_kwargs: None)

    result = runtime_review._review_runtime_artifact_hook(
        state,
        argparse.Namespace(harness="cursor", json=True),
        config=GuardConfig(guard_home=guard_home, workspace=workspace),
        context=context,
        guard_home=guard_home,
        managed_install=None,
        payload={"hook_event_name": "PreToolUse", "tool_name": "run_tool"},
        store=store,
        workspace=workspace,
    )

    assert result is None
    assert queued_actions == [action]
    assert state.policy_action == action
    assert state.response_payload["policy_action"] == action
    assert state.response_payload["approval_requests"][0]["policy_action"] == action
    assert state.receipt.policy_decision == action

    record_runtime_artifact_hook_receipt(state, store)
    assert store.list_receipts(harness="cursor")[0]["policy_decision"] == action
