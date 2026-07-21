"""Migration and idempotency tests for command activity persistence."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from multiprocessing import get_context
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_command_activity_schema as activity_schema
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityMatchClass,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandActivityMatch,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
)
from codex_plugin_scanner.guard.runtime.command_activity_privacy import FORBIDDEN_ACTIVITY_FIELD_NAMES
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind
from codex_plugin_scanner.guard.runtime.extension_evidence import EvidenceSeverity, ExtensionRuleIdentity
from codex_plugin_scanner.guard.store import GuardStore


def _correlation(kind: CorrelationKind, digest: str) -> CorrelationHandle:
    return CorrelationHandle(kind, "codex", "key.v1", digest)


def _evidence(
    *,
    activity_id: str = "activity:01",
    two_matches: bool = True,
    request_digest: str = "a" * 64,
    session_digest: str = "b" * 64,
) -> CommandActivityEvidence:
    activity = CommandActivity(
        activity_id=activity_id,
        occurred_at=datetime(2026, 7, 18, 20, 0, tzinfo=timezone.utc),
        harness="codex",
        hook_phase=CommandHookPhase.PRE,
        execution_status=CommandExecutionStatus.ALLOWED_UNCONFIRMED,
        proof_level=CommandProofLevel.PRE_HOOK,
        policy_action="allow",
        decision_reason_code=ActivityDecisionReason.EXTENSION_MATCH,
        controlling_rule_id="command.git.push",
        parse_confidence=ActivityParseConfidence.EXACT,
        uncertainty_class=None,
        match_count=2 if two_matches else 1,
        prompted=False,
        approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
        request_correlation=_correlation(CorrelationKind.REQUEST, request_digest),
        session_correlation=_correlation(CorrelationKind.SESSION, session_digest),
        receipt_link_status=ReceiptLinkStatus.NOT_APPLICABLE,
        receipt_id=None,
        evaluation_latency_bucket=ActivityLatencyBucket.LE_5_MS,
        persistence_latency_bucket=ActivityLatencyBucket.LE_2_MS,
    )
    matches = [
        CommandActivityMatch(
            activity_id=activity_id,
            ordinal=0,
            identity=ExtensionRuleIdentity("command.git", "2.2.0", "command.git.push", "1.0.0"),
            match_class=ActivityMatchClass.UNSAFE,
            severity=EvidenceSeverity.HIGH,
            default_floor="review",
            effect_claims=frozenset({EffectKind.REMOTE_STATE_MUTATION}),
        )
    ]
    if two_matches:
        matches.append(
            CommandActivityMatch(
                activity_id=activity_id,
                ordinal=1,
                identity=ExtensionRuleIdentity(
                    "command.package",
                    "2.2.0",
                    "command.package.install",
                    "1.0.0",
                ),
                match_class=ActivityMatchClass.UNSAFE,
                severity=EvidenceSeverity.CRITICAL,
                default_floor="require-reapproval",
                effect_claims=frozenset({EffectKind.PACKAGE_OR_SOURCE_INSTALLATION}),
            )
        )
    return CommandActivityEvidence(activity, tuple(matches))


def _table_names(path: Path) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[0]) for row in connection.execute("select name from sqlite_schema where type = 'table'").fetchall()
        }


def _record_in_process(guard_home: str, evidence: CommandActivityEvidence) -> bool:
    store = GuardStore(Path(guard_home), prime_policy_integrity=False)
    return store.record_command_activity(evidence)


def test_command_activity_migration_is_forward_safe_and_reopens(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    with sqlite3.connect(guard_home / "guard.db") as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("insert into schema_migrations values (9, '2026-07-17T20:00:00+00:00')")
    first = GuardStore(guard_home, prime_policy_integrity=False)
    expected = {
        "command_activity",
        "command_activity_matches",
        "command_activity_match_effects",
        "command_activity_correlations",
        "command_activity_daily_totals",
        "command_activity_daily_rollups",
    }

    assert expected.issubset(_table_names(first.path))
    with sqlite3.connect(first.path) as connection:
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (activity_schema.COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION,),
        ).fetchone()
    assert version == (activity_schema.COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION,)

    evidence = _evidence()
    first.record_command_activity(evidence)
    reopened = GuardStore(guard_home, prime_policy_integrity=False)
    assert expected.issubset(_table_names(reopened.path))
    assert reopened.record_command_activity(evidence) is False
    assert reopened.count_command_activities() == 1


def test_command_activity_migration_repairs_a_missing_table_on_reopen(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop table command_activity_daily_rollups")

    GuardStore(guard_home, prime_policy_integrity=False)

    assert "command_activity_daily_rollups" in _table_names(store.path)


def test_command_activity_migration_failure_rolls_back_schema_and_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "migration.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        statements = activity_schema.command_activity_schema_statements()
        monkeypatch.setattr(
            activity_schema,
            "command_activity_schema_statements",
            lambda: (statements[0], "create table"),
        )
        with pytest.raises(sqlite3.OperationalError):
            activity_schema.ensure_command_activity_schema(connection, applied_at="2026-07-18T20:00:00+00:00")
        tables = {
            str(row[0]) for row in connection.execute("select name from sqlite_schema where type = 'table'").fetchall()
        }
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (activity_schema.COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION,),
        ).fetchone()

        monkeypatch.setattr(activity_schema, "command_activity_schema_statements", lambda: statements)
        activity_schema.ensure_command_activity_schema(connection, applied_at="2026-07-18T20:01:00+00:00")
        recovered_version = connection.execute(
            "select version from schema_migrations where version = ?",
            (activity_schema.COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION,),
        ).fetchone()

    assert "command_activity" not in tables
    assert version is None
    assert recovered_version == (activity_schema.COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION,)


def test_command_activity_migration_rejects_an_incompatible_existing_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "incompatible.db"
    statements = activity_schema.command_activity_schema_statements()
    incompatible_activity = statements[0].replace(
        "match_count integer not null check (match_count >= 0)",
        "match_count integer not null",
    )
    with sqlite3.connect(database_path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute(incompatible_activity)

        with pytest.raises(RuntimeError, match="incompatible command activity schema object"):
            activity_schema.ensure_command_activity_schema(connection, applied_at="2026-07-18T20:00:00+00:00")

        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (activity_schema.COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION,),
        ).fetchone()

    assert version is None


def test_activity_persistence_counts_one_command_and_each_rule_hit(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence = _evidence()

    assert store.record_command_activity(evidence) is True
    assert store.count_command_activities() == 1
    assert store.count_command_activity_rule_hits() == 2
    assert store.count_command_activity_rule_hits("command.git.push") == 1
    assert store.count_command_activity_rule_hits("command.package.install") == 1


def test_exact_activity_replay_is_an_idempotent_noop(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence = _evidence()

    assert store.record_command_activity(evidence) is True
    assert store.record_command_activity(evidence) is False
    assert store.count_command_activities() == 1
    assert store.count_command_activity_rule_hits() == 2


def test_two_processes_cannot_duplicate_one_activity(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    first = GuardStore(guard_home, prime_policy_integrity=False)
    evidence = _evidence()

    with ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) as executor:
        futures = [executor.submit(_record_in_process, str(guard_home), evidence) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]

    assert sorted(results) == [False, True]
    assert first.count_command_activities() == 1
    assert first.count_command_activity_rule_hits() == 2


def test_request_correlation_is_unique_but_session_correlation_is_shareable(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity(_evidence(activity_id="activity:01"))

    with pytest.raises(sqlite3.IntegrityError):
        store.record_command_activity(_evidence(activity_id="activity:02", session_digest="c" * 64))
    assert store.record_command_activity(
        _evidence(activity_id="activity:03", request_digest="c" * 64),
    )

    assert store.count_command_activities() == 2
    assert store.count_command_activity_rule_hits() == 4


def test_conflicting_activity_replay_is_rejected_without_mutation(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence = _evidence()
    store.record_command_activity(evidence)
    conflicts = (
        CommandActivityEvidence(replace(evidence.activity, prompted=True), evidence.matches),
        CommandActivityEvidence(
            evidence.activity,
            (replace(evidence.matches[0], severity=EvidenceSeverity.LOW), evidence.matches[1]),
        ),
        CommandActivityEvidence(
            evidence.activity,
            (
                replace(evidence.matches[0], effect_claims=frozenset({EffectKind.NETWORK_WRITE})),
                evidence.matches[1],
            ),
        ),
        CommandActivityEvidence(
            replace(
                evidence.activity,
                request_correlation=_correlation(CorrelationKind.REQUEST, "c" * 64),
            ),
            evidence.matches,
        ),
    )

    for conflicting in conflicts:
        with pytest.raises(ValueError, match="conflicting command activity replay"):
            store.record_command_activity(conflicting)

    assert store.count_command_activities() == 1
    assert store.count_command_activity_rule_hits() == 2


def test_match_failure_rolls_back_the_parent_activity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            create trigger fail_command_activity_match
            before insert on command_activity_matches
            begin
              select raise(abort, 'injected match failure');
            end
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected match failure"):
        store.record_command_activity(_evidence())

    assert store.count_command_activities() == 0
    assert store.count_command_activity_rule_hits() == 0


def test_command_activity_integrity_rejects_orphans_and_cascades(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence = _evidence()
    store.record_command_activity(evidence)

    with store._connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                insert into command_activity_match_effects (activity_id, ordinal, effect_class)
                values ('missing', 0, 'network-write')
                """
            )
        connection.execute("delete from command_activity where activity_id = ?", (evidence.activity.activity_id,))

    with sqlite3.connect(store.path) as connection:
        child_counts = tuple(
            int(connection.execute(f"select count(*) from {table}").fetchone()[0])
            for table in (
                "command_activity_matches",
                "command_activity_match_effects",
                "command_activity_correlations",
            )
        )
    assert child_counts == (0, 0, 0)


def test_command_activity_parent_keys_cannot_be_updated(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence = _evidence()
    store.record_command_activity(evidence)

    updates = (
        "update command_activity set activity_id = 'moved' where activity_id = 'activity:01'",
        "update command_activity_matches set activity_id = 'moved' where activity_id = 'activity:01'",
        "update command_activity_match_effects set ordinal = 9 where activity_id = 'activity:01'",
        "update command_activity_correlations set activity_id = 'moved' where activity_id = 'activity:01'",
    )
    for statement in updates:
        with store._connect() as connection, pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(statement)

    assert store.count_command_activities() == 1
    assert store.count_command_activity_rule_hits() == 2


def test_activity_schema_has_no_forbidden_privacy_columns(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    tables = (
        "command_activity",
        "command_activity_matches",
        "command_activity_match_effects",
        "command_activity_correlations",
    )
    with sqlite3.connect(store.path) as connection:
        columns = {
            str(row[1]) for table in tables for row in connection.execute(f"pragma table_info({table})").fetchall()
        }

    assert columns.isdisjoint(FORBIDDEN_ACTIVITY_FIELD_NAMES)
