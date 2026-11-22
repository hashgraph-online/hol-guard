"""The raw approval request row and the queue clear run in the native store."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard.store import GuardStore


def _insert_request(store: GuardStore, request_id: str, *, harness: str, status: str) -> None:
    """A stored request with every required column filled."""

    with sqlite3.connect(store.path) as connection:
        columns = connection.execute("pragma table_info(approval_requests)").fetchall()
        values: dict[str, object] = {}
        for _cid, name, column_type, not_null, default, _pk in columns:
            if not_null and default is None:
                values[name] = 0 if "int" in str(column_type).lower() else "x"
        values.update({"request_id": request_id, "harness": harness, "status": status})
        names = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        connection.execute(f"insert into approval_requests ({names}) values ({marks})", tuple(values.values()))
        connection.execute(
            "insert into guard_request_resumes (request_id, harness, strategy, status, created_at, updated_at) "
            "values (?, ?, 'manual-only', 'skipped', 't1', 't1')",
            (request_id, harness),
        )


def _count(store: GuardStore, table: str) -> int:
    with sqlite3.connect(store.path) as connection:
        return int(connection.execute(f"select count(*) from {table}").fetchone()[0])


def test_the_raw_row_carries_the_stored_columns(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _insert_request(store, "req-raw", harness="codex", status="pending")

    row = store.get_raw_approval_request_snapshot("req-raw")

    assert isinstance(row, dict)
    assert (row["request_id"], row["harness"], row["status"]) == ("req-raw", "codex", "pending")
    assert "artifact_hash" in row
    assert store.get_raw_approval_request_snapshot("missing") is None


def test_clearing_removes_the_matching_requests_and_their_resumes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _insert_request(store, "codex-resolved", harness="codex", status="resolved")
    _insert_request(store, "codex-pending", harness="codex", status="pending")
    _insert_request(store, "claude-resolved", harness="claude-code", status="resolved")

    assert store.clear_approval_requests(harness="codex", status="resolved") == 1
    assert store.get_raw_approval_request_snapshot("codex-resolved") is None
    assert _count(store, "approval_requests") == 2
    assert _count(store, "guard_request_resumes") == 2
    assert store.clear_approval_requests() == 2
    assert _count(store, "guard_request_resumes") == 0
