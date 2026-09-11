"""Local invocation preview for command-activity evidence."""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    record_pre_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_journal import (
    _CommandActivityRecord,
    append_journal,
    recover_journal_records,
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


def test_invocation_preview_scrubs_spaced_heredocs_urls_and_quoted_secrets() -> None:
    heredoc = build_invocation_preview("git push origin main << EOF\nHEREDOC_PRIVATE\nEOF")
    assert heredoc is not None
    assert "git push origin main" in heredoc
    assert "HEREDOC_PRIVATE" not in heredoc
    quoted = build_invocation_preview("AWS_SECRET_ACCESS_KEY='alpha beta' git status")
    assert quoted is not None
    assert "git status" in quoted
    assert "alpha beta" not in quoted
    remote = build_invocation_preview("git push ssh://internal.example/path")
    assert remote is not None
    assert "git push" in remote
    assert "ssh://internal.example/path" not in remote
    posix_path = build_invocation_preview("cat /etc/passwd")
    assert posix_path is not None
    assert "/etc/passwd" not in posix_path
    windows_path = build_invocation_preview(r"type C:\Secrets\token.txt")
    assert windows_path is not None
    assert r"C:\Secrets\token.txt" not in windows_path
    windows_slash = build_invocation_preview("type C:/Secrets/token.txt")
    assert windows_slash is not None
    assert "C:/Secrets/token.txt" not in windows_slash
    quoted_windows = build_invocation_preview(r'type "C:/Docs/alice/My Documents/token.txt"')
    assert quoted_windows is not None
    assert "Documents/token.txt" not in quoted_windows
    assert "My Documents" not in quoted_windows
    quoted_windows_backslash = build_invocation_preview(
        r"type 'C:\Docs\alice\My Documents\token.txt'"
    )
    assert quoted_windows_backslash is not None
    assert r"Documents\token.txt" not in quoted_windows_backslash
    quoted_posix = build_invocation_preview('cat "/var/secret dir/token.txt"')
    assert quoted_posix is not None
    assert "secret dir/token.txt" not in quoted_posix
    punctuated = build_invocation_preview("git push origin main << 'end.json'\nHEREDOC_PRIVATE\nend.json")
    assert punctuated is not None
    assert "HEREDOC_PRIVATE" not in punctuated


def test_payload_preview_reads_native_tool_input() -> None:
    preview = build_invocation_preview_from_payload(
        {"toolUseId": "call_test_0123456789abcdef", "toolInput": {"command": "echo example"}}
    )
    assert preview == "echo example"


def test_payload_preview_reads_codex_tool_calls() -> None:
    preview = build_invocation_preview_from_payload(
        {
            "toolCalls": [
                {"name": "Bash", "args": {"command": "git status"}},
            ]
        }
    )
    assert preview == "git status"


def test_recorded_command_activity_exposes_local_preview(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=store.guard_home,
        harness="codex",
        event="PreToolUse",
        payload={
            "tool_name": "Shell",
            "tool_input": {"command": "git status"},
            "tool_call_id": "toolcall_preview_abcdef1234567890",
        },
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
    assert store._schema_is_current() is True  # pyright: ignore[reportPrivateUsage]


def test_legacy_activity_rows_report_missing_command(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity(evidence("activity:01", minute=1))
    page = store.list_command_activity_page(CommandActivityListQuery())
    assert page["items"][0]["invocation_preview"] is None


def test_compaction_deletes_invocation_preview(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    old = date(2026, 1, 1)
    store.record_command_activity(
        evidence("activity:old", minute=1, occurred_on=old),
        invocation_preview="git status",
    )
    now = datetime(2026, 7, 18, tzinfo=timezone.utc)
    while True:
        result = store.maintain_command_activity(now=now, detail_retain_days=30, batch_size=10)
        if result.completed or not result.ran:
            break
    with sqlite3.connect(store.path) as connection:
        remaining = connection.execute("select count(*) from command_activity_invocation").fetchone()
    assert remaining == (0,)


def test_preview_sidecar_restores_preview_without_writing_the_journal(tmp_path: Path) -> None:
    path = tmp_path / "runtime-hook-evidence.jsonl"
    record = _CommandActivityRecord(
        record_id="previewrecordabcdef1234567890aa",
        harness="codex",
        event="PreToolUse",
        correlation=None,
        has_command=True,
        succeeded=True,
        payload_bytes=1,
        policy_action="warn",
        occurred_at="2026-07-18T20:01:00+00:00",
        invocation_preview="git status",
    )
    append_journal(path, record)
    assert "git status" not in path.read_text(encoding="utf-8")
    recovered, invalid = recover_journal_records(path, max_bytes=1_000_000)
    assert invalid == 0
    assert isinstance(recovered[0], _CommandActivityRecord)
    assert recovered[0].invocation_preview == "git status"
