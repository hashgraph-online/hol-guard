"""Route test approval writes through the native resident writer.

The native ``add_approval_request`` op opens the store's sqlite file itself,
so tests use a file-backed :class:`GuardStore` and commit any pending
connection writes before each native call.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_STORES: dict[str, GuardStore] = {}


def native_approval_connection(guard_home: Path | None = None) -> sqlite3.Connection:
    """Return a row-factory connection to a fresh file-backed Guard store."""
    home = guard_home or Path(tempfile.mkdtemp(prefix="hol-guard-approval-home-"))
    store = GuardStore(home)
    _STORES[str(Path(store.path).resolve())] = store
    conn = sqlite3.connect(store.path)
    conn.row_factory = sqlite3.Row
    return conn


def _store_for(conn: sqlite3.Connection) -> GuardStore:
    rows = conn.execute("pragma database_list").fetchall()
    path = next((row[2] for row in rows if row[1] == "main"), "")
    if not path:
        raise AssertionError("native approval writes need a file-backed store connection")
    key = str(Path(path).resolve())
    store = _STORES.get(key)
    if store is None:
        store = GuardStore(Path(path).parent)
        if str(Path(store.path).resolve()) != key:
            raise AssertionError(f"connection {path} is not a Guard store database")
        _STORES[key] = store
    return store


def add_approval_request(conn: sqlite3.Connection, request: GuardApprovalRequest, now: str) -> str:
    """Commit ``conn`` and write ``request`` through the native resident."""
    conn.commit()
    return _store_for(conn).add_approval_request(request, now)


def seed_pending_approval_rows(conn: sqlite3.Connection, total: int, *, workspace: str = "ws-a") -> None:
    """Bulk-insert ``total`` distinct pending rows directly for scale fixtures."""
    rows = []
    for index in range(total):
        timestamp = f"2026-01-01T00:00:00.{index:06d}Z"
        rows.append(
            (
                f"req-{index:06d}",
                "codex",
                f"codex:project:tool-{index:06d}",
                f"tool-{index:06d}",
                "mcp_server",
                f"hash-{index:06d}",
                None,
                "require-reapproval",
                "session",
                '["args"]',
                "project",
                "/tmp/config.toml",
                workspace,
                f"run tool {index:06d}",
                f"run tool {index:06d}",
                f"identity-{index:06d}",
                f"approval-group:v1:{index:064d}",
                1,
                timestamp,
                "stdio",
                "risk",
                "[]",
                None,
                None,
                None,
                None,
                None,
                None,
                f'{{"command":"run tool {index:06d}"}}',
                None,
                None,
                f"hol-guard review req-{index:06d}",
                f"http://localhost:4455/approve/req-{index:06d}",
                "pending",
                None,
                None,
                None,
                timestamp,
                None,
            )
        )
    conn.executemany(
        """
        insert into approval_requests (
          request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
          recommended_scope, changed_fields_json, source_scope, config_path, workspace,
          launch_target, normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at,
          transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
          launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
          review_command, approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        )
        values (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        rows,
    )
    conn.commit()
