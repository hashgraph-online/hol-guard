"""A terminal native denial cannot retain an approval invitation."""

import json
import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_copilot as copilot
from codex_plugin_scanner.guard.cli.commands_hook_native_review import review_native_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_native_state import (
    NativeArtifactHookState,
    record_native_artifact_hook_receipt,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import ToolCallDecision
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_protect_approval_guidance import _pending_package_payload
from tests.test_guard_runtime_mcp_saved_blocks import _context, _package_artifact


@pytest.mark.parametrize("harness", ["zcode", "cursor", "codex"])
def test_native_package_denial_clears_approval_copy(tmp_path, harness):
    context = _context(tmp_path)
    payload = _pending_package_payload()
    payload["supply_chain_evaluation"]["user_copy"]["dashboard_url"] = "http://127.0.0.1:4455/requests/stale"
    artifact = _package_artifact(context=context, harness=harness, config_path="config.json")
    state = NativeArtifactHookState(
        action_envelope=None,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        browser_approval_daemon_client=None,
        changed_capabilities=[],
        decision_signals=(),
        decision_v2_payload={},
        event_name="PreToolUse",
        initial_policy_action="require-reapproval",
        package_evaluation=None,
        policy_action="require-reapproval",
        receipt=build_receipt(
            harness,
            artifact.artifact_id,
            "a" * 64,
            "require-reapproval",
            "package",
            [],
            "test",
            artifact.name,
            "project",
        ),
        requested_policy_action=None,
        response_payload=payload,
        risk_summary="Package integrity changed.",
        runtime_artifact=artifact,
        runtime_artifact_hash="a" * 64,
        scanner_evidence_payload=[],
        stored_policy_action=None,
        guard_home=context.guard_home,
        hook_payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "hol-guard-unmatched-probe --flag"},
            "tool_call_id": "native-unprompted-case",
        },
    )
    store = GuardStore(context.guard_home)
    result = review_native_artifact_hook(
        state,
        SimpleNamespace(harness=harness),
        config=GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        context=context,
        guard_home=context.guard_home,
        managed_install=None,
        payload={},
        store=store,
        workspace=context.workspace_dir,
    )
    assert result is None
    assert state.policy_action == "block"
    assert payload["terminal_action"] == "block"
    copy = payload["supply_chain_evaluation"]["user_copy"]
    assert copy["dashboard_url"] is None
    assert "safe, permitted alternative" in copy["next_step"]
    assert "safe, permitted alternative" in copy["harness_message"]
    assert "safe, permitted alternative" in payload["decision_v2_json"]["harness_message"]
    record_native_artifact_hook_receipt(state, store)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute("select policy_action, prompted from command_activity").fetchone()
    assert row == ("block", 0)


@pytest.mark.parametrize("stage", ["pretool", "permission"])
def test_copilot_native_denial_records_no_prompt(tmp_path, monkeypatch, capsys, stage):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    artifact = _package_artifact(context=context, harness="copilot", config_path="config.json")
    monkeypatch.setattr(
        copilot,
        "evaluate_tool_call",
        lambda **kwargs: ToolCallDecision(action="review", source="policy", signals=(), summary="Review required."),
    )
    request = (artifact, "a" * 64, {})
    options = {
        "action_envelope": None,
        "config": GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir),
        "context": context,
        "payload": {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "hol-guard-unmatched-probe --flag"},
            "tool_call_id": "copilot-unprompted-case",
        },
        "runtime_workspace": context.workspace_dir,
        "store": store,
    }
    args = SimpleNamespace(harness="copilot", json=False)
    if stage == "pretool":
        result = copilot.run_native_copilot_pretool(
            args, copilot_hook_stage="pretooluse", copilot_runtime_tool_call=request, **options
        )
    else:
        result = copilot.run_native_copilot_permission_request(
            args,
            copilot_permission_request=request,
            guard_home=context.guard_home,
            managed_install=None,
            **options,
        )
    assert result == 0
    assert "safe, permitted alternative" in json.dumps(json.loads(capsys.readouterr().out))
    with sqlite3.connect(store.path) as connection:
        row = connection.execute("select policy_action, prompted from command_activity").fetchone()
    assert row == ("block", 0)
    assert store.list_approval_requests() == []
