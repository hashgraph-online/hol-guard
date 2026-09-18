"""Native decisions reach activity storage without retrospective policy evaluation."""

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("accepted", [True, False])
def test_native_receipt_link_requires_writer_acceptance(accepted: bool) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin

    host = SimpleNamespace(
        activity_writer=SimpleNamespace(submit_native_decision_receipt=lambda **kwargs: accepted),
        _last_native_decision_receipt=None,
    )
    receipt = {"decision_id": "native-receipt-example"}
    result = HookWorkerNativeMixin._record_native_decision_receipt(host, receipt)
    assert result == (receipt if accepted else None)
    assert HookWorkerNativeMixin._record_native_decision_receipt(host, None) is None
    assert host._last_native_decision_receipt is None


@pytest.mark.parametrize(
    ("harness", "id_field", "input_field"),
    [
        ("codex", "tool_call_id", "tool_input"),
        ("grok", "toolUseId", "toolInput"),
        ("zcode", "tool_use_id", "tool_input"),
    ],
)
def test_native_pre_and_post_keep_authoritative_decision(
    tmp_path: Path,
    harness: str,
    id_field: str,
    input_field: str,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    payload = {id_field: "call_test_0123456789abcdef", input_field: {"command": "echo example"}}
    try:
        assert writer.submit_command_activity(
            harness=harness,
            event="PreToolUse",
            payload=payload,
            succeeded=True,
            policy_action="warn",
        )
        assert writer.submit_command_activity(
            harness=harness,
            event="PostToolUse",
            payload=payload,
            succeeded=True,
        )
        assert writer.submit_command_activity(
            harness=harness,
            event="PreToolUse",
            payload=payload,
            succeeded=True,
            policy_action="warn",
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        rows = connection.execute(
            "SELECT policy_action, execution_status, parse_confidence, decision_reason_code FROM command_activity"
        ).fetchall()
    assert rows == [("warn", "confirmed_success", None, "policy")]
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        preview = connection.execute("select invocation_preview from command_activity_invocation").fetchone()
    assert preview == ("echo example",)
    journal_path = store.guard_home / "runtime-hook-evidence.jsonl"
    if journal_path.exists():
        assert "echo example" not in journal_path.read_text(encoding="utf-8")
    sidecar_path = store.guard_home / "runtime-hook-evidence.preview.jsonl"
    if sidecar_path.exists():
        assert "echo example" not in sidecar_path.read_text(encoding="utf-8")
    assert writer.stats()["failures"] == 0


def test_approved_retry_preserves_prevented_attempt(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    payload = {"toolUseId": "call_test_0123456789abcdef", "toolInput": {"command": "echo example"}}
    try:
        for action in ("review", "review", "allow"):
            assert writer.submit_command_activity(
                harness="grok",
                event="PreToolUse",
                payload=payload,
                succeeded=True,
                policy_action=action,
                prompted=action == "review",
                approval_reuse_status="accepted" if action == "allow" else "not-applicable",
            )
        assert writer.submit_command_activity(
            harness="grok",
            event="PostToolUse",
            payload=payload,
            succeeded=True,
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        rows = connection.execute(
            "SELECT policy_action, execution_status FROM command_activity ORDER BY policy_action"
        ).fetchall()
    assert rows == [("allow", "confirmed_success"), ("review", "prevented")]
    assert writer.stats()["failures"] == 0


def test_pre_without_decision_never_becomes_execution(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    try:
        assert not writer.submit_command_activity(
            harness="grok",
            event="PreToolUse",
            payload={"command": "echo example"},
            succeeded=True,
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    assert store.count_command_activities() == 0


def test_incompatible_approval_metadata_is_not_queued(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    try:
        assert not writer.submit_command_activity(
            harness="grok",
            event="PreToolUse",
            payload={"command": "echo example"},
            succeeded=True,
            policy_action="allow",
            prompted=True,
            approval_reuse_status="accepted",
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    assert writer.stats()["failures"] == 0
    assert store.count_command_activities() == 0


@pytest.mark.parametrize("action", ["review", "block", "warn", "allow"])
def test_native_restrictive_decisions_keep_receipt_and_prompt(tmp_path: Path, action: str) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = RuntimeHookEvidenceWriter(store=store)
    try:
        assert writer.submit_command_activity(
            harness="grok",
            event="PreToolUse",
            payload={"command": "echo example"},
            succeeded=False,
            policy_action=action,
            receipt_id="native-receipt-example",
            prompted=action == "review",
            approval_reuse_status="accepted" if action == "allow" else "not-applicable",
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        row = connection.execute(
            "SELECT policy_action, receipt_id, prompted, approval_reuse_status FROM command_activity"
        ).fetchone()
    assert row == (
        action,
        "native-receipt-example",
        int(action == "review"),
        "accepted" if action == "allow" else "not-applicable",
    )
    assert writer.stats()["failures"] == 0


def test_grok_failure_normalization_preserves_failure() -> None:
    from codex_plugin_scanner.guard.adapters.grok_hooks import prepare_grok_hook_payload
    from codex_plugin_scanner.guard.cli.commands_support_command_activity import hook_post_succeeded

    payload = prepare_grok_hook_payload({"hookEventName": "post_tool_use_failure"})
    assert not hook_post_succeeded(str(payload["hook_event_name"]), payload)
