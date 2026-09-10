"""Security regressions for native-review approval consumption."""

from __future__ import annotations

import sqlite3

from codex_plugin_scanner.guard.store_native_review_approvals import consume_native_review_approval

_HASH = "a" * 64


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        create table approval_requests (
            request_id text primary key,
            status text not null,
            harness text not null,
            artifact_id text not null,
            artifact_name text not null,
            artifact_hash text not null,
            launch_target text not null,
            workspace text,
            resolved_at text,
            resolution_action text,
            resolution_scope text
        );
        create table guard_continuation_effects (
            effect_key text primary key,
            request_id text not null,
            evidence_id text not null,
            event_name text not null,
            created_at text not null
        );
        """
    )
    return connection


def _insert_resolution(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    resolved_at: str,
    action: str,
) -> None:
    connection.execute(
        """insert into approval_requests
           (request_id, status, harness, artifact_id, artifact_name, artifact_hash,
            launch_target, workspace, resolved_at, resolution_action, resolution_scope)
           values (?, 'resolved', 'cursor', 'cursor:native-pretool:Bash', 'Bash', ?,
                   'bash check.sh', '/workspace', ?, ?, 'artifact')""",
        (request_id, _HASH, resolved_at, action),
    )


def _consume(connection: sqlite3.Connection, *, now: str) -> bool:
    return consume_native_review_approval(
        connection,
        harness="cursor",
        artifact_id="cursor:native-pretool:Bash",
        artifact_name="Bash",
        artifact_hash=_HASH,
        launch_target="bash check.sh",
        workspace="/workspace",
        now=now,
    )


def test_newer_denial_with_different_offset_supersedes_older_allow() -> None:
    connection = _connection()
    # Lexically, 12:04-04:00 sorts after 16:05Z, but chronologically it is older.
    _insert_resolution(
        connection,
        request_id="older-allow",
        resolved_at="2026-09-10T12:04:00-04:00",
        action="allow",
    )
    _insert_resolution(
        connection,
        request_id="newer-deny",
        resolved_at="2026-09-10T16:05:00+00:00",
        action="block",
    )

    assert _consume(connection, now="2026-09-10T16:06:00+00:00") is False


def test_latest_matching_allow_is_one_use_after_utc_normalization() -> None:
    connection = _connection()
    _insert_resolution(
        connection,
        request_id="allow",
        resolved_at="2026-09-10T12:04:00-04:00",
        action="allow",
    )

    assert _consume(connection, now="2026-09-10T16:05:00+00:00") is True
    connection.commit()
    assert _consume(connection, now="2026-09-10T16:05:30+00:00") is False


def test_invalid_matching_timestamp_fails_closed() -> None:
    connection = _connection()
    _insert_resolution(
        connection,
        request_id="allow",
        resolved_at="not-a-timestamp",
        action="allow",
    )

    assert _consume(connection, now="2026-09-10T16:05:00+00:00") is False
