"""Post-claim freshness regressions for native runtime hook consumers."""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook as hook_command
from codex_plugin_scanner.guard.cli import commands_hook_copilot as copilot_hook
from codex_plugin_scanner.guard.cli import commands_hook_runtime_finish as runtime_finish
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import (
    _evaluate_runtime_artifact_hook,
)
from codex_plugin_scanner.guard.cli.commands_hook_runtime_review import (
    _review_runtime_artifact_hook,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import (
    ToolCallDecision,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore


def _record_once_allow(
    store: GuardStore,
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace: Path,
    request_id: str,
) -> None:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None


def test_runtime_artifact_hook_rebuilds_policy_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    artifact_actions: dict[str, GuardAction] = {}
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
        artifact_actions=artifact_actions,
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:post-claim",
        name="Codex post-claim action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="echo",
        args=("post-claim",),
        metadata={"guard_default_action": "review"},
    )
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(
        home_dir=tmp_path,
        workspace_dir=workspace,
        guard_home=guard_home,
    )
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo post-claim"},
        "source_scope": "project",
    }
    initial = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
    )
    assert not isinstance(initial, int)
    assert initial.policy_action == "review"
    _record_once_allow(
        store,
        artifact=artifact,
        artifact_hash=initial.runtime_artifact_hash,
        workspace=workspace,
        request_id="runtime-hook-post-claim-policy-change",
    )
    original_claim = store.claim_approval_reuse_decision

    def claim_then_block(decision: object, *, now: str | None = None) -> bool:
        claimed = original_claim(decision, now=now)
        if claimed:
            artifact_actions[artifact.artifact_id] = "block"
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_block)

    result = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
    )

    assert not isinstance(result, int)
    assert result.policy_action == "block"
    assert result.response_payload["policy_composition"]["authoritative_action"] == "block"
    assert result.response_payload["approval_reuse"]["reason_code"] == ("approval_reuse_context_changed_after_claim")

    _review_runtime_artifact_hook(
        result,
        args,
        config=replace(config, mode="observe"),
        context=context,
        guard_home=guard_home,
        managed_install=None,
        output_stream=io.StringIO(),
        payload=payload,
        store=store,
        workspace=workspace,
    )
    assert result.policy_action == "block"
    assert result.response_payload["policy_action"] == "block"
    assert result.response_payload["approval_requests"] == []


def test_runtime_artifact_hook_missing_fresh_provider_fails_closed(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=workspace, default_action="allow")
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:missing-fresh-provider",
        name="Codex missing fresh provider action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="echo",
        metadata={"guard_default_action": "review"},
    )
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(tmp_path, workspace, guard_home)
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash"}
    initial = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
    )
    assert not isinstance(initial, int)
    _record_once_allow(
        store,
        artifact=artifact,
        artifact_hash=initial.runtime_artifact_hash,
        workspace=workspace,
        request_id="runtime-hook-missing-fresh-provider",
    )

    result = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
        post_claim_revalidator=lambda _artifact_hash, _trusted: None,
    )

    assert not isinstance(result, int)
    assert result.policy_action == "require-reapproval"
    assert result.response_payload["approval_reuse"]["reason_code"] == ("approval_reuse_context_changed_after_claim")


@pytest.mark.parametrize("mode", ("prompt", "observe"))
def test_copilot_pretool_uses_fresh_provider_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name="danger-lab",
        tool_name="shell_exec",
        source_scope="project",
        config_path=str(workspace / ".vscode" / "mcp.json"),
        transport="stdio",
    )
    arguments = {"command": "rm relative-target"}
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        mode=mode,  # type: ignore[arg-type]
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    artifact_hash = build_tool_call_hash(
        artifact,
        arguments,
        workspace=workspace,
        config=config,
    )
    _record_once_allow(
        store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace=workspace,
        request_id="copilot-post-claim-policy-change",
    )
    fresh_artifact = replace(
        artifact,
        name="fresh-danger-lab:fresh_shell_exec",
        config_path=str(workspace / ".github" / "fresh-mcp.json"),
    )
    fresh_arguments = {"command": "rm fresh-relative-target"}
    fresh_config = replace(config, artifact_actions={artifact.artifact_id: "block"})
    fresh_hash = build_tool_call_hash(
        fresh_artifact,
        fresh_arguments,
        workspace=workspace,
        config=fresh_config,
    )
    output = io.StringIO()
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)

    result = copilot_hook._run_hook_copilot_pretool(
        argparse.Namespace(harness="copilot", json=False),
        action_envelope=None,
        config=config,
        context=HarnessContext(tmp_path, workspace, guard_home),
        copilot_hook_stage="pretooluse",
        copilot_runtime_tool_call=(artifact, artifact_hash, arguments),
        output_stream=output,
        payload={"hook_event_name": "PreToolUse", "tool_name": "mcp_danger_lab_shell_exec"},
        runtime_workspace=workspace,
        store=store,
        fresh_tool_call_authority_provider=lambda: (
            fresh_config,
            fresh_artifact,
            fresh_hash,
            fresh_arguments,
        ),
    )

    response = json.loads(output.getvalue())
    receipt = store.list_receipts(limit=1)[0]
    inventory = store.find_inventory_item(artifact.artifact_id)
    event = store.list_events(limit=1, event_name="runtime_tool_call_blocked")[0]
    assert result == 0
    assert response["permissionDecision"] == "deny"
    assert fresh_artifact.name in response["permissionDecisionReason"]
    assert response["approval_reuse"]["status"] == "rejected"
    assert response["approval_reuse"]["reason_code"] == ("approval_reuse_context_changed_after_claim")
    assert receipt["policy_decision"] == "block"
    assert receipt["artifact_hash"] == fresh_hash
    assert receipt["artifact_name"] == fresh_artifact.name
    assert receipt["raw_command_text"] == fresh_arguments["command"]
    assert inventory is not None
    assert inventory["artifact_hash"] == fresh_hash
    assert inventory["artifact_name"] == fresh_artifact.name
    assert inventory["config_path"] == fresh_artifact.config_path
    assert inventory["last_policy_action"] == "block"
    assert event["payload"]["artifact_hash"] == fresh_hash
    assert event["payload"]["policy_action"] == "block"


def _hook_args(harness: str, *, json_output: bool) -> argparse.Namespace:
    return argparse.Namespace(
        artifact_id=None,
        artifact_name=None,
        event_file=None,
        harness=harness,
        json=json_output,
        policy_action=None,
        runtime_harness=None,
    )


def _record_once_from_receipt(
    store: GuardStore,
    receipt: dict[str, object],
    *,
    request_id: str,
    workspace: Path,
) -> None:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=cast(str, receipt["harness"]),
        artifact_id=cast(str, receipt["artifact_id"]),
        artifact_hash=cast(str, receipt["artifact_hash"]),
        workspace=str(workspace),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None


def _approval_reuse_reason(receipt: dict[str, object]) -> str | None:
    evidence = receipt.get("scanner_evidence")
    if not isinstance(evidence, list):
        return None
    for item in evidence:
        if isinstance(item, dict) and item.get("source") == "approval_reuse":
            reason = item.get("reason_code")
            return reason if isinstance(reason, str) else None
    return None


def test_runtime_hook_reloads_synced_policy_after_atomic_claim(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="review",
        approval_wait_timeout_seconds=0,
    )
    context = HarnessContext(tmp_path, workspace, guard_home)
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:synced-runtime-post-claim",
        name="Codex synced runtime post-claim action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="echo",
        args=("synced-runtime-post-claim",),
        metadata={"guard_default_action": "review", "action_class": "test runtime action"},
    )
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo synced-runtime-post-claim"},
        "source_scope": "project",
    }
    args = _hook_args("codex", json_output=True)
    monkeypatch.setattr(hook_command, "load_guard_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(hook_command, "_hook_runtime_artifact", lambda **_kwargs: artifact)
    monkeypatch.setattr(hook_command, "_review_runtime_artifact_hook", lambda *_args, **_kwargs: None)

    hook_command._run_guard_hook_command(
        args,
        guard_home=guard_home,
        workspace=workspace,
        context=context,
        store=store,
        config=config,
        input_text=json.dumps(payload),
    )
    capsys.readouterr()
    initial_receipt = store.list_receipts(limit=1)[0]
    assert initial_receipt["policy_decision"] == "review"
    _record_once_from_receipt(
        store,
        initial_receipt,
        request_id="runtime-synced-policy-post-claim",
        workspace=workspace,
    )
    original_claim = store.claim_approval_reuse_decision

    def claim_then_sync_block(decision: object, *, now: str | None = None) -> bool:
        claimed = original_claim(decision, now=now)
        if claimed:
            store.set_sync_payload(
                "policy",
                {"defaultAction": "block"},
                "2026-07-17T00:01:00+00:00",
            )
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_sync_block)

    hook_command._run_guard_hook_command(
        args,
        guard_home=guard_home,
        workspace=workspace,
        context=context,
        store=store,
        config=config,
        input_text=json.dumps(payload),
    )
    capsys.readouterr()

    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "block"
    assert _approval_reuse_reason(receipt) == "approval_reuse_context_changed_after_claim"


def test_generic_hook_reloads_synced_policy_after_atomic_claim(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="review",
    )
    context = HarnessContext(tmp_path, workspace, guard_home)
    payload = {
        "artifact_id": "generic-test:project:opaque-synced-request",
        "artifact_name": "opaque synced request",
        "hook_event_name": "OpaqueHookEvent",
        "source_scope": "project",
        "tool_name": "opaque_tool",
        "tool_input": {"target": "unchanged"},
    }
    args = _hook_args("generic-test", json_output=True)
    monkeypatch.setattr(hook_command, "load_guard_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(hook_command, "_hook_runtime_artifact", lambda **_kwargs: None)

    hook_command._run_guard_hook_command(
        args,
        guard_home=guard_home,
        workspace=workspace,
        context=context,
        store=store,
        config=config,
        input_text=json.dumps(payload),
    )
    capsys.readouterr()
    initial_receipt = store.list_receipts(limit=1)[0]
    assert initial_receipt["policy_decision"] == "review"
    _record_once_from_receipt(
        store,
        initial_receipt,
        request_id="generic-synced-policy-post-claim",
        workspace=workspace,
    )
    original_claim = store.claim_approval_reuse_decision

    def claim_then_sync_block(decision: object, *, now: str | None = None) -> bool:
        claimed = original_claim(decision, now=now)
        if claimed:
            store.set_sync_payload(
                "policy",
                {"defaultAction": "block"},
                "2026-07-17T00:01:00+00:00",
            )
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_sync_block)

    rc = hook_command._run_guard_hook_command(
        args,
        guard_home=guard_home,
        workspace=workspace,
        context=context,
        store=store,
        config=config,
        input_text=json.dumps(payload),
    )
    output = json.loads(capsys.readouterr().out)
    receipt = store.list_receipts(limit=1)[0]

    assert rc == 1
    assert output["policy_action"] == "block"
    assert output["approval_reuse"]["reason_code"] == "approval_reuse_context_changed_after_claim"
    assert receipt["policy_decision"] == "block"
    assert _approval_reuse_reason(receipt) == "approval_reuse_context_changed_after_claim"


def test_copilot_hook_reloads_synced_policy_after_atomic_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    vscode_dir = workspace / ".vscode"
    vscode_dir.mkdir()
    (vscode_dir / "mcp.json").write_text(
        json.dumps(
            {
                "servers": {
                    "danger-lab": {
                        "type": "stdio",
                        "command": sys.executable,
                        "args": ["-c", "pass"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    context = HarnessContext(tmp_path, workspace, guard_home)
    payload = {
        "hook_name": "preToolUse",
        "tool_name": "danger-lab/shell_exec",
        "tool_input": {"command": "rm synced-copilot-target"},
        "source_scope": "project",
    }
    initial_tool_call = hook_command._copilot_runtime_tool_call(
        payload=payload,
        home_dir=tmp_path,
        workspace=workspace,
        config=config,
        preferred_workspace_config="ide",
    )
    assert initial_tool_call is not None
    artifact, artifact_hash, _arguments = initial_tool_call
    _record_once_allow(
        store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace=workspace,
        request_id="copilot-synced-policy-post-claim",
    )
    original_claim = store.claim_approval_reuse_decision

    def claim_then_sync_block(decision: object, *, now: str | None = None) -> bool:
        claimed = original_claim(decision, now=now)
        if claimed:
            store.set_sync_payload(
                "policy",
                {"defaultAction": "block"},
                "2026-07-17T00:01:00+00:00",
            )
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_sync_block)
    monkeypatch.setattr(hook_command, "load_guard_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)
    output = io.StringIO()

    rc = hook_command._run_guard_hook_command(
        _hook_args("copilot", json_output=False),
        guard_home=guard_home,
        workspace=workspace,
        context=context,
        store=store,
        config=config,
        input_text=json.dumps(payload),
        output_stream=output,
    )

    response = json.loads(output.getvalue())
    receipt = store.list_receipts(limit=1)[0]
    assert rc == 0
    assert response["permissionDecision"] == "deny"
    assert response["approval_reuse"]["reason_code"] == "approval_reuse_context_changed_after_claim"
    assert receipt["policy_decision"] == "block"
    assert _approval_reuse_reason(receipt) == "approval_reuse_context_changed_after_claim"


def test_browser_post_wait_revalidation_reloads_synced_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    secret_file = workspace / ".env"
    secret_file.write_text("TOKEN=test-only\n", encoding="utf-8")
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="review",
        approval_wait_timeout_seconds=0,
    )
    context = HarnessContext(tmp_path, workspace, guard_home)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(secret_file)},
        "source_scope": "project",
    }
    observed_fresh_context: dict[str, object] = {}
    monkeypatch.setattr(hook_command, "load_guard_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(hook_command, "_review_runtime_artifact_hook", lambda *_args, **_kwargs: None)

    def browser_decision(**kwargs: object) -> str:
        store.set_sync_payload(
            "policy",
            {"defaultAction": "block"},
            "2026-07-17T00:01:00+00:00",
        )
        provider = cast(object, kwargs["fresh_context_provider"])
        assert callable(provider)
        fresh_context = provider()
        assert isinstance(fresh_context, dict)
        observed_fresh_context.update(fresh_context)
        return "block"

    monkeypatch.setattr(runtime_finish, "_codex_browser_approval_decision", browser_decision)

    hook_command._run_guard_hook_command(
        _hook_args("codex", json_output=True),
        guard_home=guard_home,
        workspace=workspace,
        context=context,
        store=store,
        config=config,
        input_text=json.dumps(payload),
    )
    capsys.readouterr()

    assert observed_fresh_context["current_action"] == "block"
    assert observed_fresh_context["authoritative_action"] == "block"
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"


def test_copilot_permission_postclaim_uses_fresh_authority_for_queue_and_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name="danger-lab",
        tool_name="shell_exec",
        source_scope="project",
        config_path=str(workspace / ".vscode" / "mcp.json"),
        transport="stdio",
    )
    initial_arguments = {"command": "rm initial-permission-target"}
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    initial_hash = build_tool_call_hash(
        artifact,
        initial_arguments,
        workspace=workspace,
        config=config,
    )
    _record_once_allow(
        store,
        artifact=artifact,
        artifact_hash=initial_hash,
        workspace=workspace,
        request_id="copilot-permission-complete-fresh-authority",
    )
    fresh_artifact = replace(
        artifact,
        name="fresh-danger-lab:fresh_shell_exec",
        config_path=str(workspace / ".github" / "fresh-mcp.json"),
    )
    fresh_arguments = {"command": "rm fresh-permission-target"}
    fresh_config = replace(
        config,
        mode="observe",
        receipt_redaction_level="none",
    )
    fresh_hash = build_tool_call_hash(
        fresh_artifact,
        fresh_arguments,
        workspace=workspace,
        config=fresh_config,
    )
    observed_decisions: list[ToolCallDecision] = []
    queue_call: dict[str, object] = {}
    original_evaluate_tool_call = evaluate_tool_call

    def capture_decision(**kwargs: object) -> ToolCallDecision:
        decision = original_evaluate_tool_call(**kwargs)  # type: ignore[arg-type]
        observed_decisions.append(decision)
        return decision

    def unavailable_daemon_client(_guard_home: Path) -> object:
        raise RuntimeError("test uses the local approval queue")

    def capture_queue(**kwargs: object) -> list[dict[str, object]]:
        queue_call.update(kwargs)
        return [
            {
                "artifact_id": fresh_artifact.artifact_id,
                "request_id": "fresh-authority-request",
                "review_url": "http://127.0.0.1:4455/approvals/fresh-authority-request",
            }
        ]

    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", capture_decision)
    monkeypatch.setattr(copilot_hook, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(copilot_hook, "load_guard_surface_daemon_client", unavailable_daemon_client)
    monkeypatch.setattr(copilot_hook, "queue_blocked_approvals", capture_queue)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)
    output = io.StringIO()

    result = copilot_hook._run_hook_copilot_permission_request(
        _hook_args("copilot", json_output=False),
        action_envelope=None,
        config=config,
        context=HarnessContext(tmp_path, workspace, guard_home),
        copilot_permission_request=(artifact, initial_hash, initial_arguments),
        guard_home=guard_home,
        managed_install=None,
        output_stream=output,
        payload={"hook_event_name": "permissionRequest", "tool_name": "danger-lab/shell_exec"},
        runtime_workspace=workspace,
        store=store,
        fresh_tool_call_authority_provider=lambda: (
            fresh_config,
            fresh_artifact,
            fresh_hash,
            fresh_arguments,
        ),
    )

    response = json.loads(output.getvalue())
    decision = observed_decisions[-1]
    authority = decision.post_claim_authority
    receipt = store.list_receipts(limit=1)[0]
    inventory = store.find_inventory_item(fresh_artifact.artifact_id)
    event = store.list_events(limit=1, event_name="runtime_tool_call_blocked")[0]
    evaluation = cast(dict[str, object], queue_call["evaluation"])
    queued_artifact = cast(list[dict[str, object]], evaluation["artifacts"])[0]

    assert result == 0
    assert decision.action == "require-reapproval"
    assert authority is not None
    assert authority.config is fresh_config
    assert authority.artifact is fresh_artifact
    assert authority.artifact_hash == fresh_hash
    assert authority.arguments is fresh_arguments
    assert response["behavior"] == "deny"
    assert response["interrupt"] is True
    assert fresh_artifact.name in response["message"]
    assert response["approval_reuse"]["reason_code"] == "approval_reuse_context_changed_after_claim"
    assert queue_call["redaction_level"] == "none"
    assert queued_artifact["artifact_name"] == fresh_artifact.name
    assert queued_artifact["artifact_hash"] == fresh_hash
    assert queued_artifact["config_path"] == fresh_artifact.config_path
    assert queued_artifact["launch_target"] == json.dumps(fresh_arguments, sort_keys=True)
    assert receipt["artifact_name"] == fresh_artifact.name
    assert receipt["artifact_hash"] == fresh_hash
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["raw_command_text"] == fresh_arguments["command"]
    assert inventory is not None
    assert inventory["artifact_name"] == fresh_artifact.name
    assert inventory["artifact_hash"] == fresh_hash
    assert inventory["config_path"] == fresh_artifact.config_path
    assert inventory["last_policy_action"] == "require-reapproval"
    assert event["payload"]["artifact_hash"] == fresh_hash
    assert event["payload"]["policy_action"] == "require-reapproval"


@pytest.mark.parametrize(
    ("flow", "action"),
    (
        ("pretool", "sandbox-required"),
        ("permission", "sandbox-required"),
        ("permission", "require-reapproval"),
    ),
)
def test_copilot_nonallow_action_is_consistent_across_native_receipt_inventory_and_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flow: str,
    action: GuardAction,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name="consistency-lab",
        tool_name="shell_exec",
        source_scope="project",
        config_path=str(workspace / ".vscode" / "mcp.json"),
        transport="stdio",
    )
    arguments = {"command": f"rm {action}-target"}
    artifact_hash = f"guard-approval-context:v1:{action}-consistency"
    decision = ToolCallDecision(
        action=action,
        source="policy",
        signals=("test consistency signal",),
        summary=f"Current policy requires {action}.",
        risk_categories=("command_execution",),
        current_action=action,
    )
    queued: list[dict[str, object]] = []

    def unavailable_daemon_client(_guard_home: Path) -> object:
        raise RuntimeError("test uses the local approval queue")

    def capture_queue(**kwargs: object) -> list[dict[str, object]]:
        queued.append(cast(dict[str, object], kwargs["evaluation"]))
        return [{"request_id": "consistent-request"}]

    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", lambda **_kwargs: decision)
    monkeypatch.setattr(copilot_hook, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(copilot_hook, "load_guard_surface_daemon_client", unavailable_daemon_client)
    monkeypatch.setattr(copilot_hook, "queue_blocked_approvals", capture_queue)
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)
    output = io.StringIO()
    args = _hook_args("copilot", json_output=False)
    config = GuardConfig(guard_home=guard_home, workspace=workspace, mode="prompt")

    if flow == "pretool":
        result = copilot_hook._run_hook_copilot_pretool(
            args,
            action_envelope=None,
            config=config,
            context=HarnessContext(tmp_path, workspace, guard_home),
            copilot_hook_stage="pretooluse",
            copilot_runtime_tool_call=(artifact, artifact_hash, arguments),
            output_stream=output,
            payload={"hook_event_name": "PreToolUse", "tool_name": "consistency-lab/shell_exec"},
            runtime_workspace=workspace,
            store=store,
        )
    else:
        result = copilot_hook._run_hook_copilot_permission_request(
            args,
            action_envelope=None,
            config=config,
            context=HarnessContext(tmp_path, workspace, guard_home),
            copilot_permission_request=(artifact, artifact_hash, arguments),
            guard_home=guard_home,
            managed_install=None,
            output_stream=output,
            payload={"hook_event_name": "permissionRequest", "tool_name": "consistency-lab/shell_exec"},
            runtime_workspace=workspace,
            store=store,
        )

    response = json.loads(output.getvalue())
    receipt = store.list_receipts(limit=1)[0]
    inventory = store.find_inventory_item(artifact.artifact_id)
    event = store.list_events(limit=1, event_name="runtime_tool_call_blocked")[0]
    native_action = response.get("permissionDecision", response.get("behavior"))

    assert result == 0
    assert native_action == "deny"
    assert receipt["policy_decision"] == action
    assert receipt["artifact_hash"] == artifact_hash
    assert inventory is not None
    assert inventory["last_policy_action"] == action
    assert inventory["artifact_hash"] == artifact_hash
    assert event["payload"]["policy_action"] == action
    assert event["payload"]["artifact_hash"] == artifact_hash
    assert bool(queued) is (action == "require-reapproval")


def _insert_tampered_broader_block(
    store: GuardStore,
    *,
    harness: str,
) -> None:
    store.upsert_policy(
        PolicyDecision(
            harness=harness,
            scope="global",
            action="block",
            reason="tampered broader authority must not be ignored",
            source="manual",
        ),
        "2026-07-17T00:01:00+00:00",
    )
    broader_block = next(
        item for item in store.list_policy_decisions(harness) if item["scope"] == "global" and item["action"] == "block"
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where decision_id = ?",
            ("00", broader_block["decision_id"]),
        )


def test_runtime_hook_current_allow_and_exact_allow_do_not_hide_tampered_broader_authority(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:allow-integrity-collision",
        name="Codex allowed integrity collision action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="echo",
        args=("allow-integrity-collision",),
        metadata={"guard_default_action": "allow", "action_class": "benign test action"},
    )
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(tmp_path, workspace, guard_home)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo allow-integrity-collision"},
        "source_scope": "project",
    }
    initial = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
    )
    assert not isinstance(initial, int)
    assert initial.response_payload["policy_composition"]["current_composed_action"] == "allow"
    approval_id = store.record_local_once_approval(
        request_id="runtime-current-allow-integrity-collision",
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=initial.runtime_artifact_hash,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    _insert_tampered_broader_block(store, harness="codex")

    result = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
    )
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]

    assert not isinstance(result, int)
    assert result.response_payload["policy_composition"]["current_composed_action"] == "allow"
    assert result.policy_action == "require-reapproval"
    assert result.response_payload["approval_reuse"]["current_action"] == "allow"
    assert result.response_payload["approval_reuse"]["saved_action"] == "allow"
    assert result.response_payload["approval_reuse"]["reason_code"] == "approval_reuse_integrity_failure"
    assert claimed_at is None


def test_mcp_current_allow_and_exact_allow_do_not_hide_tampered_broader_authority(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
    )
    artifact = build_tool_call_artifact(
        harness="copilot",
        server_name="status-lab",
        tool_name="read_status",
        source_scope="project",
        config_path=str(workspace / ".vscode" / "mcp.json"),
        transport="stdio",
    )
    arguments = {"status": "ok"}
    artifact_hash = build_tool_call_hash(
        artifact,
        arguments,
        workspace=workspace,
        config=config,
    )
    approval_id = store.record_local_once_approval(
        request_id="mcp-current-allow-integrity-collision",
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    _insert_tampered_broader_block(store, harness="copilot")

    decision = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
    )
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]

    assert decision.current_action == "allow"
    assert decision.saved_action == "allow"
    assert decision.action == "require-reapproval"
    assert decision.approval_reuse_status == "rejected"
    assert decision.approval_reuse_reason_code == "approval_reuse_integrity_failure"
    assert claimed_at is None
