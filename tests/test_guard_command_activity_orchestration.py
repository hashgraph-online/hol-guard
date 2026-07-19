"""End-to-end orchestration regressions for command activity ownership."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnusedCallResult=false

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook as hook_command
from codex_plugin_scanner.guard.cli import commands_hook_copilot as copilot_hook
from codex_plugin_scanner.guard.cli.commands_support_command_activity import command_activity_was_prompted
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.runtime import command_activity_cursor
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / "guard-home",
    )


def _artifact(tmp_path: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="copilot:project:tool-action:partition",
        name="Copilot partition tool call",
        harness="copilot",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(tmp_path / ".vscode" / "mcp.json"),
        command="git push origin release/2.2 --force",
    )


def _decision(action: GuardAction) -> ToolCallDecision:
    return ToolCallDecision(
        action=action,
        source="heuristic",
        signals=("fixture signal",),
        summary="Fixture decision.",
        risk_categories=("destructive_mutation",),
    )


def _args() -> argparse.Namespace:
    return argparse.Namespace(harness="copilot", json=False)


@pytest.mark.parametrize(
    ("reuse_status", "expected"),
    (
        ("accepted", False),
        ("rejected", True),
        ("not-applicable", True),
    ),
)
def test_prompt_attribution_excludes_accepted_approval_reuse(
    reuse_status: str,
    expected: bool,
) -> None:
    from codex_plugin_scanner.guard.runtime.command_activity_contract import ActivityApprovalReuseStatus

    assert command_activity_was_prompted("review", ActivityApprovalReuseStatus(reuse_status)) is expected


@pytest.mark.parametrize(
    ("current_action", "expected"),
    (("allow", False), ("review", True)),
)
def test_copilot_prompt_attribution_uses_pre_reuse_action(
    current_action: GuardAction,
    expected: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    captured: list[bool] = []
    monkeypatch.setattr(
        copilot_hook,
        "record_pre_hook_command_activity_best_effort",
        lambda **kwargs: captured.append(bool(kwargs["prompted"])),
    )
    decision = ToolCallDecision(
        action="block",
        source="policy",
        signals=("fixture signal",),
        summary="Fixture decision.",
        approval_reuse_status="rejected",
        current_action=current_action,
        saved_action="block",
    )

    copilot_hook._record_copilot_pre_activity(
        store=GuardStore(context.guard_home),
        context=context,
        event="preToolUse",
        payload={"tool_name": "Shell", "tool_input": {"command": "git push origin main --force"}},
        policy_action="block",
        receipt_id="guard-receipt-fixture",
        decision=decision,
        runtime_workspace=context.workspace_dir,
    )

    assert captured == [expected]


def test_copilot_orchestrators_assign_one_owner_for_each_valid_stage_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    artifact = _artifact(tmp_path)
    store = GuardStore(context.guard_home)
    recorded_events: list[str] = []
    current_decision = [_decision("allow")]
    monkeypatch.setattr(copilot_hook, "evaluate_tool_call", lambda **_kwargs: current_decision[0])
    monkeypatch.setattr(
        copilot_hook,
        "_record_copilot_pre_activity",
        lambda **kwargs: recorded_events.append(str(kwargs["event"])),
    )
    monkeypatch.setattr(copilot_hook, "_record_harness_usage_for_hook", lambda **_kwargs: None)
    monkeypatch.setattr(copilot_hook, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")
    monkeypatch.setattr(
        copilot_hook,
        "load_guard_surface_daemon_client",
        lambda _guard_home: (_ for _ in ()).throw(RuntimeError("fixture offline")),
    )
    monkeypatch.setattr(copilot_hook, "queue_blocked_approvals", lambda **_kwargs: [])
    payload = {
        "tool_name": "Shell",
        "tool_input": {"command": "git push origin release/2.2 --force"},
    }
    runtime_call = (artifact, "partition-hash", payload["tool_input"])

    actions: tuple[GuardAction, ...] = ("allow", "block")
    for action in actions:
        current_decision[0] = _decision(action)
        result = copilot_hook._run_hook_copilot_pretool(
            _args(),
            action_envelope=None,
            config=GuardConfig(context.guard_home, context.workspace_dir, mode="prompt"),
            context=context,
            copilot_hook_stage="pretooluse",
            copilot_runtime_tool_call=runtime_call,
            output_stream=io.StringIO(),
            payload=payload,
            runtime_workspace=context.workspace_dir,
            store=store,
        )
        assert result == 0

    current_decision[0] = _decision("review")
    pretool_result = copilot_hook._run_hook_copilot_pretool(
        _args(),
        action_envelope=None,
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="prompt"),
        context=context,
        copilot_hook_stage="pretooluse",
        copilot_runtime_tool_call=runtime_call,
        output_stream=io.StringIO(),
        payload=payload,
        runtime_workspace=context.workspace_dir,
        store=store,
    )
    assert pretool_result == 0
    assert recorded_events == ["preToolUse", "preToolUse"]

    permission_result = copilot_hook._run_hook_copilot_permission_request(
        _args(),
        action_envelope=None,
        config=GuardConfig(context.guard_home, context.workspace_dir, mode="prompt"),
        context=context,
        copilot_permission_request=runtime_call,
        guard_home=context.guard_home,
        managed_install=None,
        output_stream=io.StringIO(),
        payload=payload,
        runtime_workspace=context.workspace_dir,
        store=store,
    )
    assert permission_result == 0
    assert recorded_events == ["preToolUse", "preToolUse", "copilotPermissionRequest"]


def test_repeated_native_pre_hook_with_new_receipt_is_one_logical_activity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    home_dir.mkdir()
    workspace_dir.mkdir()
    (home_dir / "config.toml").write_text("approval_wait_timeout_seconds = 0\n", encoding="utf-8")
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "git push origin release/2.2 --force"},
        "tool_call_id": "toolcall_replayed_abcdef1234567890",
    }
    command = [
        "guard",
        "hook",
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--harness",
        "codex",
        "--policy-action",
        "block",
    ]

    for _ in range(2):
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        assert main(command) == 0
        _ = capsys.readouterr()

    store = GuardStore(home_dir)
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 2
    assert receipts[0]["receipt_id"] != receipts[1]["receipt_id"]
    assert store.count_command_activities() == 1
    health = store.get_command_activity_persistence_health()
    assert health.dropped_event_count == 0
    assert health.persistence_error_count == 0


def test_cursor_observer_verifier_failure_preserves_exact_hook_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(context.guard_home, context.workspace_dir)
    args = argparse.Namespace(
        artifact_id=None,
        artifact_name=None,
        event_file=None,
        harness="cursor",
        json=True,
        policy_action=None,
        runtime_harness=None,
    )
    payload = json.dumps(
        {
            "hook_event_name": "afterShellExecution",
            "conversation_id": "cursor-conversation-abcdef",
            "generation_id": "cursor-generation-abcdef",
            "command": "git push origin release/2.2 --force",
            "cwd": str(context.workspace_dir),
        }
    )
    monkeypatch.setattr(hook_command, "_persist_cursor_native_permission_after_shell", lambda **_kwargs: True)
    monkeypatch.setattr(command_activity_cursor, "cursor_command_activity_observer_trusted", lambda **_kwargs: False)
    baseline = io.StringIO()
    baseline_rc = hook_command._run_guard_hook_command(
        args,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        context=context,
        store=store,
        config=config,
        input_text=payload,
        output_stream=baseline,
    )

    def fail_verification(**_kwargs: object) -> bool:
        raise RuntimeError("fixture verifier failure")

    monkeypatch.setattr(command_activity_cursor, "cursor_command_activity_observer_trusted", fail_verification)
    failed = io.StringIO()
    failed_rc = hook_command._run_guard_hook_command(
        args,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        context=context,
        store=store,
        config=config,
        input_text=payload,
        output_stream=failed,
    )

    assert failed_rc == baseline_rc == 0
    assert failed.getvalue() == baseline.getvalue()
    health = store.get_command_activity_persistence_health()
    assert health.dropped_event_count == 1
    assert health.last_error_code == "cursor_observer_verify_failed"
