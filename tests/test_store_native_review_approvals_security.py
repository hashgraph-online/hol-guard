"""Security regressions for native-review approval consumption."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_binding import NATIVE_REVIEW_BINDING_FIELD
from codex_plugin_scanner.guard.store_native_review_approvals import consume_native_review_approval

_BINDING = f"native-review-v4:{'a' * 64}:deny:review:review:native_sensitive_access_review"


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
            resolution_scope text,
            action_envelope_json text,
            continuation_snapshot_json text
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
                   'cat .env', '/workspace', ?, ?, 'artifact')""",
        (request_id, _BINDING, resolved_at, action),
    )


def _consume(
    connection: sqlite3.Connection,
    *,
    now: str,
    harness: str = "cursor",
    policy_binding: Mapping[str, object] | None = None,
) -> bool:
    return consume_native_review_approval(
        connection,
        harness=harness,
        artifact_id=f"{harness}:native-pretool:Bash",
        artifact_name="Bash",
        artifact_hash=_BINDING,
        launch_target="cat .env",
        workspace="/workspace",
        now=now,
        policy_binding=policy_binding,
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


def test_equal_timestamp_allow_and_denial_fail_closed() -> None:
    connection = _connection()
    timestamp = "2026-09-10T16:05:00+00:00"
    _insert_resolution(connection, request_id="allow", resolved_at=timestamp, action="allow")
    _insert_resolution(connection, request_id="deny", resolved_at=timestamp, action="block")

    assert _consume(connection, now="2026-09-10T16:05:30+00:00") is False


def test_duplicate_same_timestamp_allows_are_one_logical_capability() -> None:
    connection = _connection()
    timestamp = "2026-09-10T16:05:00+00:00"
    _insert_resolution(connection, request_id="allow-a", resolved_at=timestamp, action="allow")
    _insert_resolution(connection, request_id="allow-b", resolved_at=timestamp, action="allow")

    assert _consume(connection, now="2026-09-10T16:05:30+00:00") is True
    connection.commit()
    assert _consume(connection, now="2026-09-10T16:05:40+00:00") is False


def test_legacy_unbound_hash_cannot_authorize_retry() -> None:
    connection = _connection()
    connection.execute(
        """insert into approval_requests
           (request_id, status, harness, artifact_id, artifact_name, artifact_hash,
            launch_target, workspace, resolved_at, resolution_action, resolution_scope)
           values ('legacy', 'resolved', 'cursor', 'cursor:native-pretool:Bash', 'Bash', ?,
                   'cat .env', '/workspace', '2026-09-10T16:05:00+00:00', 'allow', 'artifact')""",
        ("a" * 64,),
    )

    assert (
        consume_native_review_approval(
            connection,
            harness="cursor",
            artifact_id="cursor:native-pretool:Bash",
            artifact_name="Bash",
            artifact_hash="a" * 64,
            launch_target="cat .env",
            workspace="/workspace",
            now="2026-09-10T16:05:30+00:00",
        )
        is False
    )


def test_policy_mismatch_does_not_spend_the_atomic_retry() -> None:
    connection = _connection()
    _insert_resolution(connection, request_id="bound", resolved_at="2026-09-10T16:05:00+00:00", action="allow")
    recorded = {"policy_digest": "a" * 64}
    connection.execute(
        "update approval_requests set action_envelope_json = ?",
        (json.dumps({NATIVE_REVIEW_BINDING_FIELD: recorded}),),
    )
    assert not _consume(connection, now="2026-09-10T16:05:30+00:00", policy_binding={"policy_digest": "b" * 64})
    assert connection.execute("select count(*) from guard_continuation_effects").fetchone()[0] == 0
    connection.commit()
    assert _consume(connection, now="2026-09-10T16:05:30+00:00", policy_binding=recorded)
    connection.commit()
    assert not _consume(connection, now="2026-09-10T16:05:30+00:00", policy_binding=recorded)


@pytest.mark.parametrize("field,value", [
    ("action_envelope_json", "malformed"),
    ("action_envelope_json", "[]"),
    ("continuation_snapshot_json", "malformed"),
    ("continuation_snapshot_json", "[]"),
])
def test_invalid_stored_security_metadata_cannot_authorize_retry(field: str, value: str) -> None:
    connection = _connection()
    _insert_resolution(connection, request_id="invalid", resolved_at="2026-09-10T16:05:00+00:00", action="allow")
    assert field in {"action_envelope_json", "continuation_snapshot_json"}
    connection.execute(f"update approval_requests set {field} = ?", (value,))
    assert not _consume(connection, now="2026-09-10T16:05:30+00:00")
    assert connection.execute("select count(*) from guard_continuation_effects").fetchone()[0] == 0


def test_codex_suspended_response_cannot_be_spent_as_a_local_retry() -> None:
    connection = _connection()
    _insert_resolution(connection, request_id="live", resolved_at="2026-09-10T16:05:00+00:00", action="allow")
    connection.execute(
        """update approval_requests set harness = 'codex', artifact_id = 'codex:native-pretool:Bash',
           continuation_snapshot_json = ?""",
        (json.dumps({"capability": "suspended-response"}),),
    )
    assert not _consume(connection, now="2026-09-10T16:05:30+00:00", harness="codex")
    assert connection.execute("select count(*) from guard_continuation_effects").fetchone()[0] == 0
