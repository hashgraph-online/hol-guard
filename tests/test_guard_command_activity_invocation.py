"""Local invocation preview for command-activity evidence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    record_pre_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.runtime.command_activity_api_contract import CommandActivityListQuery
from codex_plugin_scanner.guard.runtime.command_activity_display import (
    build_invocation_preview,
    build_invocation_preview_from_payload,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_display_schema import (
    COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION,
)
from tests.guard_command_activity_api_support import evidence


def test_invocation_preview_redacts_secrets_and_keeps_the_command() -> None:
    preview = build_invocation_preview(
        "git push origin release/2.2 --force # ghp_0123456789FORBIDDEN",
        home_dir=None,
    )
    assert preview is not None
    assert "git push origin release/2.2 --force" in preview
    assert "ghp_0123456789FORBIDDEN" not in preview


def test_payload_preview_reads_native_tool_input() -> None:
    preview = build_invocation_preview_from_payload(
        {"toolUseId": "call_test_0123456789abcdef", "toolInput": {"command": "echo example"}}
    )
    assert preview == "echo example"


def test_recorded_command_activity_exposes_local_preview(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=store.guard_home,
        harness="codex",
        event="PreToolUse",
        payload={"tool_name": "Shell", "tool_input": {"command": "git status"}, "tool_call_id": "toolcall_preview_abcdef1234567890"},
        policy_action="warn",
        receipt_id=None,
        prompted=False,
    )
    page = store.list_command_activity_page(CommandActivityListQuery())
    assert [item["invocation_preview"] for item in page["items"]] == ["git status"]
    with sqlite3.connect(store.path) as connection:
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION,),
        ).fetchone()
    assert version == (COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION,)


def test_legacy_activity_rows_report_missing_command(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity(evidence("activity:01", minute=1))
    page = store.list_command_activity_page(CommandActivityListQuery())
    assert page["items"][0]["invocation_preview"] is None
