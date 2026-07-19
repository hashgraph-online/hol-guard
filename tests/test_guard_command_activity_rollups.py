"""Transactional rollup and bounded retention evidence for command activity."""

# pyright: reportAny=false, reportMissingImports=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_command_activity as activity_store
from codex_plugin_scanner.guard import store_command_activity_maintenance as activity_maintenance
from codex_plugin_scanner.guard import store_command_activity_maintenance_schema as maintenance_schema
from codex_plugin_scanner.guard.models import GuardAction
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
from codex_plugin_scanner.guard.runtime.command_activity_privacy import (
    MIN_CLOUD_AGGREGATE_COUNT,
    CloudAggregateDimension,
    CloudCommandActivityAggregate,
)
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind
from codex_plugin_scanner.guard.runtime.extension_evidence import EvidenceSeverity, ExtensionRuleIdentity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_maintenance import CommandActivityMaintenanceResult
from codex_plugin_scanner.guard.store_command_activity_rollups import COMMAND_ACTIVITY_ROLLUP_DIMENSIONS

_NOW = datetime(2026, 7, 18, 20, 0, tzinfo=timezone.utc)


def _evidence(
    activity_id: str,
    *,
    occurred_at: datetime = _NOW,
    action: GuardAction | None = "allow",
    prompted: bool = False,
    matches: int = 0,
) -> CommandActivityEvidence:
    unpaired = action is None
    activity = CommandActivity(
        activity_id=activity_id,
        occurred_at=occurred_at,
        harness="codex",
        hook_phase=CommandHookPhase.POST_SUCCESS if unpaired else CommandHookPhase.PRE,
        execution_status=(
            CommandExecutionStatus.UNPAIRED_POST if unpaired else CommandExecutionStatus.ALLOWED_UNCONFIRMED
        ),
        proof_level=CommandProofLevel.UNPAIRED_POST if unpaired else CommandProofLevel.PRE_HOOK,
        policy_action=action,
        decision_reason_code=(
            None if unpaired else ActivityDecisionReason.EXTENSION_MATCH if matches else ActivityDecisionReason.NO_MATCH
        ),
        controlling_rule_id="command.git.push" if matches else None,
        parse_confidence=None if unpaired else ActivityParseConfidence.EXACT,
        uncertainty_class=None,
        match_count=matches,
        prompted=False if unpaired else prompted,
        approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
        request_correlation=(
            None
            if unpaired
            else CorrelationHandle(
                CorrelationKind.REQUEST,
                "codex",
                "key.v1",
                f"{int(activity_id.split(':')[-1]):064x}",
            )
        ),
        session_correlation=None,
        receipt_link_status=ReceiptLinkStatus.NOT_APPLICABLE,
        receipt_id=None,
        evaluation_latency_bucket=ActivityLatencyBucket.NOT_MEASURED if unpaired else ActivityLatencyBucket.LE_5_MS,
        persistence_latency_bucket=ActivityLatencyBucket.LE_2_MS,
    )
    rule_hits = tuple(
        CommandActivityMatch(
            activity_id=activity_id,
            ordinal=ordinal,
            identity=ExtensionRuleIdentity(
                "command.git",
                "2.2.0",
                "command.git.push" if ordinal == 0 else "command.git.force-push",
                "1.0.0",
            ),
            match_class=ActivityMatchClass.UNSAFE,
            severity=EvidenceSeverity.HIGH,
            default_floor="review",
            effect_claims=frozenset({EffectKind.REMOTE_STATE_MUTATION}),
        )
        for ordinal in range(matches)
    )
    return CommandActivityEvidence(activity, rule_hits)


def _rollups(store: GuardStore) -> dict[tuple[str, str, str], int]:
    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            "select day, dimension, dimension_value, count from command_activity_daily_rollups"
        ).fetchall()
    return {(str(day), str(dimension), str(value)): int(count) for day, dimension, value, count in rows}


def _total(store: GuardStore, day: str) -> int:
    with sqlite3.connect(store.path) as connection:
        row = connection.execute("select total from command_activity_daily_totals where day = ?", (day,)).fetchone()
    return int(row[0]) if row is not None else 0


def test_v12_schema_is_strict_atomic_and_rejects_orphan_membership(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    with sqlite3.connect(store.path) as connection:
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (maintenance_schema.COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_MIGRATION_VERSION,),
        ).fetchone()
        with pytest.raises(sqlite3.IntegrityError, match="parent is missing"):
            connection.execute(
                """
                insert into command_activity_rollup_membership (activity_id, day, occurred_at, rolled_at)
                values ('missing', '2026-07-18', ?, ?)
                """,
                (_NOW.isoformat(), _NOW.isoformat()),
            )
    assert version == (12,)


def test_v12_schema_failure_rolls_back_objects_and_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "migration.db"
    with sqlite3.connect(path) as connection:
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("create table command_activity (activity_id text primary key)")
        statements = maintenance_schema.command_activity_maintenance_schema_statements()
        monkeypatch.setattr(
            maintenance_schema,
            "command_activity_maintenance_schema_statements",
            lambda: (statements[0], "create table"),
        )
        with pytest.raises(sqlite3.OperationalError):
            maintenance_schema.ensure_command_activity_maintenance_schema(connection, applied_at=_NOW.isoformat())
        table = connection.execute(
            "select 1 from sqlite_schema where name = 'command_activity_rollup_membership'"
        ).fetchone()
        version = connection.execute("select 1 from schema_migrations where version = 12").fetchone()
    assert table is None
    assert version is None


def test_record_and_transition_update_exact_bounded_cells_once(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    first = _evidence("activity:1", matches=2)
    second = _evidence("activity:2", action=None)
    third = _evidence("activity:3", prompted=True)
    assert store.record_command_activity(first) is True
    assert store.record_command_activity(first) is False
    assert store.record_command_activity(second) is True
    assert store.record_command_activity(third) is True

    cells = _rollups(store)
    day = _NOW.date().isoformat()
    assert _total(store, day) == 3
    assert cells[(day, "extension", "command.git")] == 1
    assert cells[(day, "rule", "command.git.push")] == 1
    assert cells[(day, "rule", "command.git.force-push")] == 1
    assert (day, "disposition", "not_applicable") not in cells
    assert cells[(day, "prompt_status", "not_prompted")] == 2
    assert cells[(day, "prompt_status", "prompted")] == 1
    assert cells[(day, "latency", "evaluation.le_5_ms")] == 2
    assert cells[(day, "latency", "evaluation.not_measured")] == 1
    assert cells[(day, "latency", "persistence.le_2_ms")] == 3
    assert set(COMMAND_ACTIVITY_ROLLUP_DIMENSIONS) == {
        item.value for item in CloudAggregateDimension if item is not CloudAggregateDimension.TOTAL
    }

    current = replace(
        first.activity,
        hook_phase=CommandHookPhase.POST_SUCCESS,
        execution_status=CommandExecutionStatus.CONFIRMED_SUCCESS,
        proof_level=CommandProofLevel.POST_HOOK,
        persistence_latency_bucket=ActivityLatencyBucket.LE_5_MS,
    )
    assert store.transition_command_activity(current) is True
    assert store.transition_command_activity(current) is False
    transitioned = _rollups(store)
    assert transitioned[(day, "execution_status", "confirmed_success")] == 1
    assert transitioned[(day, "proof_level", "post_hook")] == 1
    assert transitioned[(day, "latency", "evaluation.le_5_ms")] == 2
    assert transitioned[(day, "latency", "persistence.le_2_ms")] == 2
    assert transitioned[(day, "latency", "persistence.le_5_ms")] == 1
    assert _total(store, day) == 3


def test_latency_cells_have_explicit_bounded_cloud_semantics() -> None:
    for value in ("evaluation.le_5_ms", "persistence.le_2_ms"):
        aggregate = CloudCommandActivityAggregate(
            day=_NOW.date(),
            dimension=CloudAggregateDimension.LATENCY,
            dimension_value=value,
            count=MIN_CLOUD_AGGREGATE_COUNT,
        )
        assert aggregate.dimension_value == value
    with pytest.raises(ValueError, match="bounded aggregate dimension"):
        CloudCommandActivityAggregate(
            day=_NOW.date(),
            dimension=CloudAggregateDimension.LATENCY,
            dimension_value="le_5_ms",
            count=MIN_CLOUD_AGGREGATE_COUNT,
        )


def test_rollup_failure_rolls_back_parent_and_children(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    def fail(_connection: sqlite3.Connection, _evidence: CommandActivityEvidence) -> bool:
        raise RuntimeError("injected rollup failure")

    monkeypatch.setattr(activity_store, "record_command_activity_rollups", fail)
    with pytest.raises(RuntimeError, match="injected"):
        store.record_command_activity(_evidence("activity:1", matches=2))
    assert store.count_command_activities() == 0
    assert store.count_command_activity_rule_hits() == 0


def test_rebuild_reconciles_one_hundred_thousand_rows(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    template = _evidence("activity:1")
    store.record_command_activity(template)
    with sqlite3.connect(store.path) as connection:
        row = list[object](connection.execute("select * from command_activity").fetchone() or ())
        connection.execute("delete from command_activity")
        connection.execute("delete from command_activity_rollup_membership")
        connection.execute("delete from command_activity_daily_rollups")
        connection.execute("delete from command_activity_daily_totals")
        insert = "insert into command_activity values (" + ",".join("?" for _ in row) + ")"
        for start in range(0, 100_000, 10_000):
            batch: list[tuple[object, ...]] = []
            for index in range(start, start + 10_000):
                values = list(row)
                values[0] = f"bulk:{index:06d}"
                values[1] = (_NOW - timedelta(days=400 + index % 10)).isoformat()
                batch.append(tuple(values))
            connection.executemany(insert, batch)
        detail_plan = connection.execute(
            """
            explain query plan select membership.activity_id
            from command_activity_rollup_membership membership
            join command_activity activity on activity.activity_id = membership.activity_id
            where membership.detail_present = 1 and membership.occurred_at < ?
            order by membership.occurred_at, membership.activity_id limit ?
            """,
            (_NOW.isoformat(), 1_000),
        ).fetchall()
        assert connection.execute("select count(*) from command_activity_rollup_membership").fetchone() == (0,)
    assert any("idx_command_activity_rollup_membership_occurred_at" in str(item) for item in detail_plan)
    assert not any("SCAN activity" in str(item) for item in detail_plan)

    first_page = store.maintain_command_activity(now=_NOW, detail_retain_days=1_000, batch_size=1_000)
    assert 0 < first_page.backfilled_rows <= 1_000
    assert first_page.completed is False
    with sqlite3.connect(store.path) as connection:
        cursor = connection.execute(
            """
            select rollup_backfill_cursor_occurred_at, rollup_backfill_cursor_activity_id,
                   rollup_backfill_complete
            from command_activity_maintenance where singleton = 1
            """
        ).fetchone()
        assert cursor is not None
        plan = connection.execute(
            """
            explain query plan select * from command_activity
            where (occurred_at, activity_id) > (?, ?)
            order by occurred_at, activity_id limit ?
            """,
            (cursor[0], cursor[1], 1_000),
        ).fetchall()
    assert cursor[2] == 0
    assert any("idx_command_activity_occurred_at" in str(row) for row in plan)

    store.rebuild_command_activity_rollups(now=_NOW)
    assert store.count_command_activities() == 100_000
    assert store.command_activity_rollups_are_reconciled() is True
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("select sum(total) from command_activity_daily_totals").fetchone() == (100_000,)
        assert connection.execute("select count(*) from command_activity_rollup_membership").fetchone() == (100_000,)
    retained = store.maintain_command_activity(now=_NOW, detail_retain_days=1_000, batch_size=1_000)
    assert retained.completed is True
    assert retained.detail_rows_deleted == 0
    assert retained.aggregate_rows_deleted > 0
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("select count(*) from command_activity_rollup_membership").fetchone() == (100_000,)
        plan = connection.execute(
            """
            explain query plan select rowid from command_activity_rollup_membership
            where detail_present = 0 and day < ? order by day, activity_id limit ?
            """,
            ("2025-07-01", 1_000),
        ).fetchall()
    assert any("idx_command_activity_rollup_membership_day" in str(row) for row in plan)

    store.rebuild_command_activity_rollups(now=_NOW)
    same_day = store.maintain_command_activity(now=_NOW, detail_retain_days=1_000, batch_size=1_000)
    assert same_day.aggregate_rows_deleted > 0
    values = list(row)
    values[0] = "bulk:backdated"
    values[1] = (_NOW - timedelta(days=500)).isoformat()
    with sqlite3.connect(store.path) as connection:
        connection.execute(insert, tuple(values))
        assert connection.execute("select count(*) from command_activity_rollup_pending").fetchone() == (1,)
        pending_plan = connection.execute(
            """explain query plan select activity.* from command_activity_rollup_pending pending
            join command_activity activity on activity.activity_id = pending.activity_id
            order by pending.activity_id limit 1000"""
        ).fetchall()
    assert not any("SCAN activity" in str(item) for item in pending_plan)
    late = store.maintain_command_activity(now=_NOW, detail_retain_days=1_000, batch_size=1_000)
    assert late.backfilled_rows == 1
    assert late.completed is True

    maintenance = store.maintain_command_activity(
        now=_NOW + timedelta(days=1),
        detail_retain_days=30,
        batch_size=1_000,
    )
    assert maintenance.detail_rows_deleted == 1_000
    assert maintenance.completed is False
    assert store.count_command_activities() == 99_001


def test_compaction_is_bounded_preserves_history_and_delayed_replay_dedupes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    old = _NOW - timedelta(days=60)
    for index in range(5):
        store.record_command_activity(_evidence(f"activity:{index + 1}", occurred_at=old))
    old_day = old.date().isoformat()

    results: list[CommandActivityMaintenanceResult] = []
    while not results or not results[-1].completed:
        results.append(store.maintain_command_activity(now=_NOW, detail_retain_days=30, batch_size=2))
    assert all(result.detail_rows_deleted <= 2 for result in results)
    assert sum(result.correlation_rows_deleted for result in results) == 5
    assert store.count_command_activities() == 0
    assert _total(store, old_day) == 5
    assert results[-1].completed is True
    assert store.maintain_command_activity(now=_NOW, detail_retain_days=30, batch_size=2).ran is False
    assert store.command_activity_rollups_are_reconciled() is False
    with pytest.raises(RuntimeError, match="after detail compaction"):
        store.rebuild_command_activity_rollups(now=_NOW)

    assert store.record_command_activity(_evidence("activity:1", occurred_at=old)) is False
    assert store.count_command_activities() == 0
    assert _total(store, old_day) == 5


def test_aggregate_and_membership_retention_is_thirteen_calendar_months_and_bounded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    cutoff = date(2025, 7, 1)
    with sqlite3.connect(store.path) as connection:
        for index in range(7):
            connection.execute(
                "insert into command_activity_daily_rollups values (?, 'harness', ?, 1)",
                ((cutoff - timedelta(days=index + 1)).isoformat(), f"old-{index}"),
            )
        connection.execute("insert into command_activity_daily_totals values ('2025-06-30', 7)")
        connection.execute("insert into command_activity_daily_totals values ('2025-07-01', 1)")

    deleted: list[int] = []
    while True:
        result = store.maintain_command_activity(now=_NOW, detail_retain_days=30, batch_size=3)
        deleted.append(result.aggregate_rows_deleted)
        if result.completed:
            break
    assert all(count <= 3 for count in deleted)
    assert sum(deleted) == 8
    assert _total(store, "2025-06-30") == 0
    assert _total(store, "2025-07-01") == 1


def test_maintenance_failure_rolls_back_all_mutations_and_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    old = _NOW - timedelta(days=60)
    store.record_command_activity(_evidence("activity:1", occurred_at=old))

    def fail_aggregate(
        _connection: sqlite3.Connection,
        *,
        now: datetime,
        batch_size: int,
    ) -> int:
        del now, batch_size
        raise RuntimeError("injected aggregate failure")

    monkeypatch.setattr(activity_maintenance, "_delete_expired_aggregates", fail_aggregate)
    with pytest.raises(RuntimeError, match="injected"):
        store.maintain_command_activity(now=_NOW, detail_retain_days=30, batch_size=2)
    assert store.count_command_activities() == 1
    assert _total(store, old.date().isoformat()) == 1
