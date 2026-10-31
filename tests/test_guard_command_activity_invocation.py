"""Storage of the local invocation preview beside command-activity evidence."""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_activity_api_contract import CommandActivityListQuery
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_command_activity_api_support import evidence


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
