"""Atomic storage, replay, migration, and privacy tests for command shadow evidence."""

# pyright: reportAny=false, reportMissingImports=false, reportPrivateUsage=false
# pyright: reportUnknownMemberType=false, reportUnknownParameterType=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from multiprocessing import get_context
from pathlib import Path
from threading import Event
from typing import cast

import pytest

from codex_plugin_scanner.guard import store_command_shadow as shadow_store
from codex_plugin_scanner.guard import store_command_shadow_schema as shadow_schema
from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity_support
from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    record_pre_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
)
from codex_plugin_scanner.guard.runtime.command_activity_lifecycle import (
    CommandActivityDecisionFacts,
    build_pre_hook_evidence,
)
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    COMMAND_SHADOW_SCHEMA_VERSION,
    CommandShadowCohort,
    CommandShadowControl,
    CommandShadowProposal,
    build_command_shadow_observation,
)
from codex_plugin_scanner.guard.store import GuardStore

_OCCURRED_AT = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _evidence_and_shadow(*, activity_id: str = "activity:shadow"):
    evaluation = evaluate_command("git push origin release/2.2 --force")
    evidence = build_pre_hook_evidence(
        evaluation,
        CommandActivityDecisionFacts(
            policy_action="allow",
            decision_reason_code=ActivityDecisionReason.EXTENSION_MATCH,
            prompted=False,
            approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
            receipt_id=None,
        ),
        activity_id=activity_id,
        occurred_at=_OCCURRED_AT,
        harness="codex",
        request_correlation=None,
    )
    cohorts = frozenset({CommandShadowCohort.BASELINE, CommandShadowCohort.REMOTE_MUTATION_FLOORS})
    proposal = CommandShadowProposal(evaluation.decision_plane, cohorts, "proposal.multi.v1")
    control = CommandShadowControl(True, False, cohorts, frozenset(), 10_000)
    shadow = build_command_shadow_observation(
        evaluation,
        authoritative_action="allow",
        proposal=proposal,
        activity_id=activity_id,
        occurred_at=_OCCURRED_AT,
        control=control,
    )
    assert shadow is not None
    return evidence, shadow


def _record_in_process(guard_home: str) -> bool:
    store = GuardStore(Path(guard_home), prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()
    return store.record_command_activity(evidence, shadow=shadow)


def test_migration_creates_validated_normalized_schema(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    with sqlite3.connect(store.path) as connection:
        tables = {str(row[0]) for row in connection.execute("select name from sqlite_master").fetchall()}
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
        ).fetchone()

    assert "command_activity_shadow_evaluations" in tables
    assert "command_activity_shadow_cohorts" in tables
    assert version == (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,)


def test_migration_rolls_back_objects_and_version_on_validation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "migration.db"
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("create table command_activity (activity_id text primary key) strict")
        statements = shadow_schema._SCHEMA_STATEMENTS
        monkeypatch.setattr(shadow_schema, "_SCHEMA_STATEMENTS", (*statements, "create table"))
        with pytest.raises(sqlite3.OperationalError):
            shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())
        tables = {str(row[0]) for row in connection.execute("select name from sqlite_master").fetchall()}
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
        ).fetchone()

    assert "command_activity_shadow_evaluations" not in tables
    assert "command_activity_shadow_cohorts" not in tables
    assert version is None


def test_activity_and_multi_cohort_shadow_are_atomic_and_replay_exactly(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()

    assert store.record_command_activity(evidence, shadow=shadow)
    assert not store.record_command_activity(evidence, shadow=shadow)
    assert store.count_command_activities() == 1
    assert store.count_command_shadow_observations() == 1
    assert store.list_command_shadow_observations() == (shadow,)

    with pytest.raises(ValueError, match="shadow replay conflicts"):
        store.record_command_activity(evidence, shadow=replace(shadow, proposal_version="proposal.changed.v1"))


def test_shadow_cannot_be_added_after_parent_replay(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()
    store.record_command_activity(evidence)

    with pytest.raises(ValueError, match="missing persisted evidence"):
        store.record_command_activity(evidence, shadow=shadow)


def test_concurrent_exact_shadow_replay_persists_once(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    GuardStore(guard_home, prime_policy_integrity=False)

    with ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) as executor:
        results = tuple(executor.map(_record_in_process, (str(guard_home), str(guard_home))))

    store = GuardStore(guard_home, prime_policy_integrity=False)
    assert sorted(results) == [False, True]
    assert store.count_command_activities() == 1
    assert store.count_command_shadow_observations() == 1


def test_list_uses_consistent_snapshot_during_concurrent_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()
    store.record_command_activity(evidence, shadow=shadow)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma journal_mode=wal").fetchone() == ("wal",)
    parent_read = Event()
    continue_read = Event()
    original = shadow_store._observation_from_row

    def pause_after_parent(connection: sqlite3.Connection, row: sqlite3.Row):
        parent_read.set()
        assert continue_read.wait(timeout=5)
        return original(connection, row)

    monkeypatch.setattr(shadow_store, "_observation_from_row", pause_after_parent)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(store.list_command_shadow_observations)
        assert parent_read.wait(timeout=5)
        store.clear_command_activity_evidence()
        continue_read.set()
        assert future.result(timeout=5) == (shadow,)

    assert store.count_command_shadow_observations() == 0


def test_schema_rejects_orphans_and_direct_parent_delete_cascades(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()
    store.record_command_activity(evidence, shadow=shadow)

    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="activity_missing"):
            connection.execute(
                """
                insert into command_activity_shadow_evaluations
                select 'activity:orphan', occurred_at, authoritative_action, current_action,
                  current_disposition, proposed_action, proposed_disposition, comparison,
                  proposal_version, evaluator_schema_version, control_generation,
                  sample_basis_points, schema_version
                from command_activity_shadow_evaluations where activity_id = ?
                """,
                (evidence.activity.activity_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="evaluation_missing"):
            connection.execute("insert into command_activity_shadow_cohorts values ('activity:orphan', 0, 'baseline')")
        connection.execute(
            """
            insert into command_activity
            select 'activity:comparison', occurred_at, harness, hook_phase, execution_status,
              proof_level, policy_action, decision_reason_code, controlling_rule_id,
              parse_confidence, uncertainty_class, match_count, prompted,
              approval_reuse_status, receipt_link_status, receipt_id,
              evaluation_latency_bucket, persistence_latency_bucket, schema_version
            from command_activity where activity_id = ?
            """,
            (evidence.activity.activity_id,),
        )
        with pytest.raises(sqlite3.IntegrityError, match="comparison_invalid"):
            connection.execute(
                """
                insert into command_activity_shadow_evaluations
                select 'activity:comparison', occurred_at, authoritative_action, current_action,
                  current_disposition, proposed_action, proposed_disposition, 'lowered',
                  proposal_version, evaluator_schema_version, control_generation,
                  sample_basis_points, schema_version
                from command_activity_shadow_evaluations where activity_id = ?
                """,
                (evidence.activity.activity_id,),
            )
        connection.execute("delete from command_activity where activity_id = ?", (evidence.activity.activity_id,))
        evaluation_count = connection.execute("select count(*) from command_activity_shadow_evaluations").fetchone()
        cohort_count = connection.execute("select count(*) from command_activity_shadow_cohorts").fetchone()

    assert evaluation_count == (0,)
    assert cohort_count == (0,)


def test_shadow_failure_rolls_back_parent_activity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop table command_activity_shadow_cohorts")

    with pytest.raises(sqlite3.OperationalError):
        store.record_command_activity(evidence, shadow=shadow)
    assert store.count_command_activities() == 0


def test_parent_deletion_cascades_and_privacy_clear_counts_shadow_rows(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()
    store.record_command_activity(evidence, shadow=shadow)

    diagnostics = store.command_activity_diagnostics()
    schemas = cast(dict[str, str], diagnostics["schemas"])
    counts = cast(dict[str, int], diagnostics["counts"])
    assert schemas["shadow"] == COMMAND_SHADOW_SCHEMA_VERSION
    assert counts["shadow_evaluations"] == 1
    assert counts["shadow_cohorts"] == 2
    deleted = cast(dict[str, int], store.clear_command_activity_evidence()["deleted"])
    assert deleted["shadow_evaluations"] == 1
    assert deleted["shadow_cohorts"] == 2
    assert store.count_command_shadow_observations() == 0


def test_retention_deletes_shadow_with_expired_parent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    evidence, shadow = _evidence_and_shadow()
    store.record_command_activity(evidence, shadow=shadow)

    result = store.maintain_command_activity(
        now=datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc),
        detail_retain_days=1,
    )

    assert result.detail_rows_deleted == 1
    assert store.count_command_shadow_observations() == 0


def test_proposal_failure_records_activity_without_changing_hook_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)

    def fail_proposal(_evaluation: object) -> None:
        raise RuntimeError("injected proposal failure")

    monkeypatch.setattr(activity_support, "baseline_command_shadow_proposal", fail_proposal)
    result = record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload={
            "tool_name": "Shell",
            "tool_input": {"command": "git push origin release/2.2 --force"},
            "tool_call_id": "toolcall_shadow_failure_abcdef1234567890",
        },
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )

    health = store.get_command_activity_persistence_health()
    assert (
        result,
        store.count_command_activities(),
        health.persistence_error_count,
        health.last_error_code,
    ) == (
        True,
        1,
        1,
        "shadow_evaluation_failed",
    )
    assert store.count_command_activities() == 1
    assert store.count_command_shadow_observations() == 0
    assert health.persistence_error_count == 1
    assert health.last_error_code == "shadow_evaluation_failed"
