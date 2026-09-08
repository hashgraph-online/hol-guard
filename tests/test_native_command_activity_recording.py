"""Native decisions reach activity storage without retrospective policy evaluation."""

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore


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
