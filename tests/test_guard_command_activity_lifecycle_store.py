"""Transactional lifecycle and health tests for command activity persistence."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_command_activity_health_schema as health_schema
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
)
from codex_plugin_scanner.guard.store import GuardStore

_NOW = datetime(2026, 7, 18, 22, 0, tzinfo=timezone.utc)


def _request(digest: str = "a" * 64) -> CorrelationHandle:
    return CorrelationHandle(CorrelationKind.REQUEST, "codex", "key.v1", digest)


def _activity(
    *,
    activity_id: str = "activity:01",
    request: CorrelationHandle | None = None,
) -> CommandActivity:
    return CommandActivity(
        activity_id=activity_id,
        occurred_at=_NOW,
        harness="codex",
        hook_phase=CommandHookPhase.PRE,
        execution_status=CommandExecutionStatus.ALLOWED_UNCONFIRMED,
        proof_level=CommandProofLevel.PRE_HOOK,
        policy_action="allow",
        decision_reason_code=ActivityDecisionReason.NO_MATCH,
        controlling_rule_id=None,
        parse_confidence=ActivityParseConfidence.EXACT,
        uncertainty_class=None,
        match_count=0,
        prompted=False,
        approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
        request_correlation=request or _request(),
        session_correlation=None,
        receipt_link_status=ReceiptLinkStatus.NOT_APPLICABLE,
        receipt_id=None,
        evaluation_latency_bucket=ActivityLatencyBucket.LE_2_MS,
        persistence_latency_bucket=ActivityLatencyBucket.LE_1_MS,
    )


def _confirmed(activity: CommandActivity, *, succeeded: bool) -> CommandActivity:
    return replace(
        activity,
        hook_phase=CommandHookPhase.POST_SUCCESS if succeeded else CommandHookPhase.POST_FAILURE,
        execution_status=(
            CommandExecutionStatus.CONFIRMED_SUCCESS if succeeded else CommandExecutionStatus.CONFIRMED_FAILURE
        ),
        proof_level=CommandProofLevel.POST_HOOK,
        persistence_latency_bucket=ActivityLatencyBucket.LE_2_MS,
    )


def _attempt_transition(guard_home: Path, current: CommandActivity) -> str:
    store = GuardStore(guard_home, prime_policy_integrity=False)
    try:
        return "updated" if store.transition_command_activity(current) else "replayed"
    except ValueError:
        return "rejected"


def test_health_migration_is_v14_atomic_and_reopens(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    first = GuardStore(guard_home, prime_policy_integrity=False)
    initial = first.get_command_activity_persistence_health()
    reopened = GuardStore(guard_home, prime_policy_integrity=False)

    with sqlite3.connect(first.path) as connection:
        migration = connection.execute(
            "select version from schema_migrations where version = ?",
            (health_schema.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
        ).fetchone()

    assert migration == (health_schema.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,)
    assert initial == reopened.get_command_activity_persistence_health()
    assert initial.dropped_event_count == 0
    assert initial.schema_version == health_schema.COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION


def test_health_migration_failure_rolls_back_table_and_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "migration.db"
    with sqlite3.connect(path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        monkeypatch.setattr(health_schema, "_HEALTH_TABLE_SQL", "create table")
        with pytest.raises(sqlite3.OperationalError):
            health_schema.ensure_command_activity_health_schema(connection, applied_at=_NOW.isoformat())

        tables = connection.execute("select name from sqlite_schema where name = 'command_activity_health'").fetchall()
        migration = connection.execute(
            "select version from schema_migrations where version = ?",
            (health_schema.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
        ).fetchone()

    assert tables == []
    assert migration is None


def test_health_migration_rejects_weakened_existing_schema(tmp_path: Path) -> None:
    path = tmp_path / "incompatible.db"
    weakened = health_schema._HEALTH_TABLE_SQL.replace(
        " check (dropped_event_count between 0 and 9223372036854775807)",
        "",
    )
    with sqlite3.connect(path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute(weakened)

        with pytest.raises(RuntimeError, match="incompatible command_activity_health schema object"):
            health_schema.ensure_command_activity_health_schema(connection, applied_at=_NOW.isoformat())

        migration = connection.execute(
            "select version from schema_migrations where version = ?",
            (health_schema.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
        ).fetchone()

    assert migration is None


def test_health_migration_repairs_only_legacy_post_record_failures(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "delete from schema_migrations where version = ?",
            (health_schema.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
        )
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (11, ?)",
            (_NOW.isoformat(),),
        )
        connection.execute(
            """
            update command_activity_health
            set dropped_event_count = 68, persistence_error_count = 68,
                last_error_code = 'post_record_failed', last_error_at = ?
            where singleton = 1
            """,
            (_NOW.isoformat(),),
        )

    reopened = GuardStore(guard_home, prime_policy_integrity=False)
    health = reopened.get_command_activity_persistence_health()
    assert health.dropped_event_count == 0
    assert health.persistence_error_count == 0
    assert health.last_error_code is None

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "delete from schema_migrations where version = ?",
            (health_schema.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
        )
        connection.execute(
            """
            update command_activity_health
            set dropped_event_count = 1, persistence_error_count = 1,
                last_error_code = 'sqlite.busy', last_error_at = ?
            where singleton = 1
            """,
            (_NOW.isoformat(),),
        )

    unrelated = GuardStore(guard_home, prime_policy_integrity=False).get_command_activity_persistence_health()
    assert unrelated.dropped_event_count == 1
    assert unrelated.persistence_error_count == 1
    assert unrelated.last_error_code == "sqlite.busy"


def test_health_migration_rejects_incompatible_existing_singleton(tmp_path: Path) -> None:
    path = tmp_path / "incompatible-row.db"
    with sqlite3.connect(path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute(health_schema._HEALTH_TABLE_SQL)
        connection.execute(
            """
            insert into command_activity_health values (1, 0, 0, null, null, '0.0.0')
            """
        )
        with pytest.raises(RuntimeError, match="incompatible command_activity_health singleton"):
            health_schema.ensure_command_activity_health_schema(connection, applied_at=_NOW.isoformat())
        migration = connection.execute(
            "select version from schema_migrations where version = ?",
            (health_schema.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
        ).fetchone()

    assert migration is None


def test_lookup_requires_exact_request_handle_and_hides_activity_id_lookup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    activity = _activity()
    store.record_command_activity(CommandActivityEvidence(activity, ()))

    assert store.get_command_activity_by_request_correlation(_request()) == activity
    assert store.get_command_activity_by_request_correlation(_request("b" * 64)) is None
    with pytest.raises(ValueError, match="request CorrelationHandle"):
        store.get_command_activity_by_request_correlation(
            CorrelationHandle(CorrelationKind.SESSION, "codex", "key.v1", "b" * 64)
        )


def test_transition_is_atomic_idempotent_and_rejects_conflicting_terminal(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    activity = _activity()
    succeeded = _confirmed(activity, succeeded=True)
    failed = _confirmed(activity, succeeded=False)
    store.record_command_activity(CommandActivityEvidence(activity, ()))

    assert store.transition_command_activity(succeeded) is True
    assert store.transition_command_activity(succeeded) is False
    with pytest.raises(ValueError, match="invalid or conflicting"):
        store.transition_command_activity(failed)
    assert store.get_command_activity_by_request_correlation(_request()) == succeeded


def test_competing_terminal_transitions_commit_exactly_one_outcome(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    activity = _activity()
    store.record_command_activity(CommandActivityEvidence(activity, ()))

    with ThreadPoolExecutor(max_workers=2) as executor:
        success = executor.submit(_attempt_transition, guard_home, _confirmed(activity, succeeded=True))
        failure = executor.submit(_attempt_transition, guard_home, _confirmed(activity, succeeded=False))
        outcomes = (success.result(), failure.result())

    assert sorted(outcomes) == ["rejected", "updated"]
    persisted = store.get_command_activity_by_request_correlation(_request())
    assert persisted is not None
    assert persisted.execution_status in {
        CommandExecutionStatus.CONFIRMED_SUCCESS,
        CommandExecutionStatus.CONFIRMED_FAILURE,
    }


def test_transition_rejects_fact_changes_and_unknown_correlations(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    activity = _activity()
    store.record_command_activity(CommandActivityEvidence(activity, ()))

    with pytest.raises(ValueError, match="cannot change"):
        store.transition_command_activity(
            replace(_confirmed(activity, succeeded=True), occurred_at=_NOW + timedelta(seconds=1))
        )
    unknown = _activity(activity_id="activity:02", request=_request("b" * 64))
    with pytest.raises(ValueError, match="does not identify"):
        store.transition_command_activity(_confirmed(unknown, succeeded=True))


def test_health_failure_counts_are_bounded_and_store_no_error_details(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity_persistence_failure(error_code="sqlite.busy", occurred_at=_NOW)

    health = store.get_command_activity_persistence_health()
    assert health.dropped_event_count == 1
    assert health.persistence_error_count == 1
    assert health.last_error_code == "sqlite.busy"
    assert health.last_error_at == _NOW

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            update command_activity_health
            set dropped_event_count = 9223372036854775807,
                persistence_error_count = 9223372036854775807
            where singleton = 1
            """
        )
    store.record_command_activity_persistence_failure(error_code="store.failure", occurred_at=_NOW)
    saturated = store.get_command_activity_persistence_health()
    assert saturated.dropped_event_count == 9_223_372_036_854_775_807
    assert saturated.persistence_error_count == 9_223_372_036_854_775_807

    with pytest.raises(ValueError, match="bounded stable identifier"):
        store.record_command_activity_persistence_failure(error_code="raw /private/path", occurred_at=_NOW)
