"""Hook decisions remain visible even when no artifact receipt was created."""

from __future__ import annotations

import argparse
import io

from rich.console import Console

from codex_plugin_scanner.guard.cli import commands_dispatch_records as records
from codex_plugin_scanner.guard.cli.render import _render_receipts
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_decision_receipt import _receipt


def test_native_receipt_list_includes_prompt_and_tool_without_artifact_receipts(tmp_path):
    store = GuardStore(tmp_path)
    tool = _receipt(
        harness="codex",
        event_name="PreToolUse",
        model_output_action="not_applicable",
        decision="deny",
        policy_action="review",
        reason_code="native_command_review_required",
    )
    prompt = _receipt(
        harness="codex",
        event_name="UserPromptSubmit",
        model_output_action="not_applicable",
        decision="deny",
        policy_action="block",
        reason_code="native_prompt_bypass_block",
    )
    for receipt in (tool, prompt):
        assert store.record_native_decision_receipt(receipt)
    assert store.list_receipts() == []
    listed = store.list_native_decision_receipts()
    assert {row["decision_id"] for row in listed} == {tool["decision_id"], prompt["decision_id"]}
    assert all(row["recorded_at"] for row in listed)
    assert len(store.list_native_decision_receipts(limit=1)) == 1
    assert store.list_native_decision_receipts(limit=0) == []
    with store._connect() as connection:
        connection.execute("update native_prompt_decision_receipts set reason_code = 'tampered'")
    assert [row["decision_id"] for row in store.list_native_decision_receipts()] == [tool["decision_id"]]


def test_receipts_cli_preserves_artifacts_and_labels_native_scope(tmp_path, monkeypatch):
    store = GuardStore(tmp_path)
    native = _receipt(
        harness="codex",
        event_name="UserPromptSubmit",
        model_output_action="not_applicable",
        decision="deny",
        policy_action="block",
        reason_code="native_prompt_bypass_block",
    )
    assert store.record_native_decision_receipt(native)
    captured = []
    monkeypatch.setattr(records, "_emit", lambda kind, payload, as_json: captured.append(payload))
    assert (
        records._run_guard_receipts_command(
            argparse.Namespace(json=True), store=store, workspace=tmp_path / "unrelated"
        )
        == 0
    )
    payload = captured[0]
    assert payload["items"] == []
    assert payload["native_decision_scope"] == "guard-home"
    assert payload["native_decisions"][0]["decision_id"] == native["decision_id"]
    stream = io.StringIO()
    _render_receipts(Console(file=stream, width=240), payload)
    output = stream.getvalue()
    assert "UserPromptSubmit" in output
    assert "not workspace-filtered" in output
    assert "not approval resolutions or proof a tool ran" in output
