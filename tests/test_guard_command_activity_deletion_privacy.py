"""Deletion, diagnostics, and forbidden-sentinel assurance for command activity."""

# pyright: reportAny=false, reportArgumentType=false, reportMissingImports=false
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
# pyright: reportUnknownParameterType=false, reportUnknownVariableType=false, reportUnusedCallResult=false

from __future__ import annotations

import json
import sqlite3
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    record_pre_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_activity_api_contract import (
    COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    CommandActivityFeedbackLabel,
)
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    COMMAND_ACTIVITY_SCHEMA_VERSION,
    CommandProofLevel,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_health_schema import (
    COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.store_command_activity_maintenance_schema import (
    COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.store_command_activity_privacy import (
    COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
    _stable_distinct,
)
from tests.guard_command_activity_api_support import seed

_COMMAND_TABLES = (
    "command_activity",
    "command_activity_matches",
    "command_activity_match_effects",
    "command_activity_correlations",
    "command_activity_daily_totals",
    "command_activity_daily_rollups",
    "command_activity_rollup_membership",
    "command_activity_rollup_pending",
    "command_activity_feedback",
    "command_activity_invalidations",
)


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)


def _all_command_rows(store: GuardStore) -> dict[str, list[list[object]]]:
    with sqlite3.connect(store.path) as connection:
        return {
            table: [list(row) for row in connection.execute(f"select * from {table}").fetchall()]
            for table in _COMMAND_TABLES
        }


def _maintenance_state(store: GuardStore) -> tuple[object, ...]:
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            """
            select last_completed_day, last_run_at, detail_compaction_started_at,
                   rollup_backfill_cursor_occurred_at, rollup_backfill_cursor_activity_id,
                   rollup_backfill_complete, last_backfilled_rows,
                   last_detail_rows_deleted, last_correlation_rows_deleted,
                   last_aggregate_rows_deleted
            from command_activity_maintenance where singleton = 1
            """
        ).fetchone()
    assert row is not None
    return tuple(row)


def _seed_clear_state(store: GuardStore) -> None:
    store.record_command_activity_feedback(
        activity_id="activity:01",
        label=CommandActivityFeedbackLabel.SHOULD_NOT_HAVE_INTERRUPTED,
        recorded_at=datetime(2026, 7, 18, 22, 0, tzinfo=timezone.utc),
    )
    store.record_command_activity_persistence_failure(
        error_code="pre_record_failed",
        occurred_at=datetime(2026, 7, 18, 22, 1, tzinfo=timezone.utc),
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            insert into command_activity_correlations (activity_id, kind, harness, key_id, digest)
            values ('activity:01', 'request', 'codex', 'correlation.v1', ?)
            """,
            ("a" * 64,),
        )
        connection.execute(
            """
            insert into command_activity_rollup_pending (activity_id, occurred_at)
            values ('activity:01', '2026-07-18T20:00:00+00:00')
            """
        )
        connection.execute(
            """
            update command_activity_maintenance
            set last_completed_day = '2026-07-17',
                last_run_at = '2026-07-18T22:00:00+00:00',
                detail_compaction_started_at = '2026-07-18T22:00:00+00:00',
                rollup_backfill_cursor_occurred_at = '2026-07-18T20:00:00+00:00',
                rollup_backfill_cursor_activity_id = 'activity:01',
                rollup_backfill_complete = 1,
                last_backfilled_rows = 3,
                last_detail_rows_deleted = 2,
                last_correlation_rows_deleted = 1,
                last_aggregate_rows_deleted = 4
            where singleton = 1
            """
        )


def _raw_get(daemon: GuardDaemonServer, path: str, *, token: str) -> bytes:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        headers={"X-Guard-Token": token},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read()


def test_diagnostics_has_an_exact_bounded_allowlist(tmp_path: Path) -> None:
    store = _store(tmp_path)
    seed(store)
    store.record_command_activity_persistence_failure(
        error_code="pre_record_failed",
        occurred_at=datetime(2026, 7, 18, 22, 0, tzinfo=timezone.utc),
    )

    diagnostics = store.command_activity_diagnostics()

    assert set(diagnostics) == {
        "schema_version",
        "schemas",
        "counts",
        "proof_coverage",
        "stable_ids",
        "error_classes",
    }
    assert diagnostics["schema_version"] == COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION
    assert diagnostics["schemas"] == {
        "activity": COMMAND_ACTIVITY_SCHEMA_VERSION,
        "api": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
        "health": COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION,
        "maintenance": COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION,
    }
    assert diagnostics["counts"] == {
        "activities": 3,
        "matches": 3,
        "effects": 3,
        "correlations": 0,
        "rollup_days": 1,
        "rollup_cells": 11,
        "rollup_memberships": 3,
        "rollup_pending": 0,
        "feedback": 0,
        "invalidations": 3,
        "dropped_events": 1,
        "persistence_errors": 1,
    }
    assert diagnostics["proof_coverage"] == [
        {"proof_level": level.value, "count": 3 if level is CommandProofLevel.PRE_HOOK else 0}
        for level in CommandProofLevel
    ]
    assert diagnostics["stable_ids"] == {
        "harnesses": ["codex"],
        "extensions": ["command.git"],
        "rules": [],
    }
    assert diagnostics["error_classes"] == [{"error_class": "pre_record_failed", "count": 1}]
    serialized = json.dumps(diagnostics, sort_keys=True)
    for forbidden in ("activity:01", "receipt:", "occurred_at", "last_error_at", "digest"):
        assert forbidden not in serialized

    with store._connect() as connection:
        assert _stable_distinct(connection, "command_activity", "harness", allowed=frozenset()) == []


def test_diagnostics_omits_corrupt_unbounded_identifiers(tmp_path: Path) -> None:
    store = _store(tmp_path)
    seed(store)
    forbidden = "alice-private-secret"
    with sqlite3.connect(store.path) as connection:
        connection.execute("pragma ignore_check_constraints = on")
        corrupt_rows = tuple((f"corrupt:{index}", f"private-secret-{index}") for index in range(1_000))
        connection.executemany(
            """
            insert into command_activity
            select ?, occurred_at, ?, hook_phase, execution_status, proof_level,
              policy_action, decision_reason_code, controlling_rule_id,
              parse_confidence, uncertainty_class, match_count, prompted,
              approval_reuse_status, receipt_link_status, receipt_id,
              evaluation_latency_bucket, persistence_latency_bucket, schema_version
            from command_activity where activity_id = 'activity:01'
            """,
            corrupt_rows,
        )
        connection.executemany(
            """
            insert into command_activity_matches
            select ?, ordinal, ?, extension_version, ?, rule_version, match_class,
              severity, default_floor, safe_variant_id, schema_version
            from command_activity_matches where activity_id = 'activity:01'
            """,
            ((activity_id, identifier, identifier) for activity_id, identifier in corrupt_rows),
        )
        connection.execute(
            "update command_activity set harness = ? where activity_id like 'activity:%'",
            (forbidden,),
        )
        connection.execute("update command_activity_matches set extension_id = ?, rule_id = ?", (forbidden, forbidden))
        connection.execute(
            """
            update command_activity_health set dropped_event_count = ?,
              persistence_error_count = ?, last_error_code = ? where singleton = 1
            """,
            (forbidden, forbidden, forbidden),
        )

    diagnostics = store.command_activity_diagnostics()
    serialized = json.dumps(diagnostics, sort_keys=True)
    assert forbidden not in serialized
    assert "private-secret-" not in serialized
    assert '"harnesses": []' in serialized
    assert '"error_classes": []' in serialized
    counts = cast(dict[str, int], diagnostics["counts"])
    assert counts["dropped_events"] == counts["persistence_errors"] == 0

    with sqlite3.connect(store.path) as connection:
        connection.execute("delete from command_activity_health where singleton = 1")
    missing_health = store.command_activity_diagnostics()
    missing_counts = cast(dict[str, int], missing_health["counts"])
    assert missing_counts["dropped_events"] == missing_counts["persistence_errors"] == 0
    assert missing_health["error_classes"] == []


def test_clear_is_atomic_and_preserves_unrelated_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    seed(store)
    _seed_clear_state(store)
    store.add_event("unrelated.event", {"value": "preserve"}, "2026-07-18T22:00:00+00:00")
    before = store.command_activity_diagnostics()
    before_rows = _all_command_rows(store)
    before_maintenance = _maintenance_state(store)
    before_counts = cast(dict[str, int], before["counts"])
    assert all(before_counts[key] > 0 for key in before_counts)
    assert before_maintenance == (
        "2026-07-17",
        "2026-07-18T22:00:00+00:00",
        "2026-07-18T22:00:00+00:00",
        "2026-07-18T20:00:00+00:00",
        "activity:01",
        1,
        3,
        2,
        1,
        4,
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            create trigger fail_command_clear before update on command_activity_maintenance
            begin select raise(abort, 'injected clear failure'); end
            """
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected clear failure"):
        store.clear_command_activity_evidence()
    assert store.command_activity_diagnostics() == before
    assert _all_command_rows(store) == before_rows
    assert _maintenance_state(store) == before_maintenance

    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger fail_command_clear")
    cleared = store.clear_command_activity_evidence()

    assert cleared["schema_version"] == COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION
    assert cleared["deleted"] == {
        key: value for key, value in before_counts.items() if key not in {"dropped_events", "persistence_errors"}
    }
    assert all(not rows for rows in _all_command_rows(store).values())
    assert store.command_activity_diagnostics()["counts"] == {key: 0 for key in cast(dict[str, int], before["counts"])}
    assert _maintenance_state(store) == (None, None, None, None, None, 0, 0, 0, 0, 0)
    assert store.list_events_after(0) == [
        {
            "event_id": 1,
            "event_name": "unrelated.event",
            "payload": {"value": "preserve"},
            "occurred_at": "2026-07-18T22:00:00+00:00",
        }
    ]


def test_forbidden_sentinels_never_reach_command_activity_surfaces(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _store(tmp_path)
    sentinels = (
        "ghp_0123456789FORBIDDEN",
        "/private/example/.env",
        "alice-private@example.invalid",
        "https://private.example.invalid/callback",
        "2>/private/example/error.log",
        "HEREDOC_PRIVATE_SENTINEL",
        "AWS_SECRET_ACCESS_KEY=ENV_PRIVATE_SENTINEL",
    )
    commands = (
        f"git push origin release/2.2 --force # {sentinels[0]}",
        f"git push origin release/2.2 --force # {sentinels[1]}",
        f"git push origin release/2.2 --force # {sentinels[2]}",
        f"git push {sentinels[3]} release/2.2 --force",
        f"git push origin release/2.2 --force {sentinels[4]}",
        f"git push origin release/2.2 --force <<'EOF'\n{sentinels[5]}\nEOF",
        f"{sentinels[6]} git push origin release/2.2 --force",
    )
    assert all(sentinel in json.dumps(commands) for sentinel in sentinels)
    with caplog.at_level("DEBUG"):
        for index, command in enumerate(commands):
            payload: dict[str, object] = {
                "tool_name": "Shell",
                "tool_input": {"command": command},
                "tool_call_id": f"toolcall_privacy_{index}_abcdef1234567890",
            }
            assert record_pre_hook_command_activity_best_effort(
                store=store,
                guard_home=store.guard_home,
                harness="codex",
                event="PreToolUse",
                payload=payload,
                policy_action="allow",
                receipt_id=None,
                prompted=True,
            ), command

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    token = daemon._server.auth_token
    response = None
    try:
        raw_activity = _raw_get(daemon, "/v1/command-activity", token=token)
        raw_analytics = _raw_get(daemon, "/v1/command-activity/analytics?days=7", token=token)
        raw_extensions = _raw_get(daemon, "/v1/command-extensions", token=token)
        raw_diagnostics = _raw_get(daemon, "/v1/command-activity/diagnostics", token=token)
        diagnostics = cast(dict[str, object], json.loads(raw_diagnostics))
        response = urllib.request.urlopen(
            urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/command-activity/events?cursor=0",
                headers={"X-Guard-Token": token},
            ),
            timeout=5,
        )
        raw_sse = response.readline() + response.readline() + response.readline()
    finally:
        if response is not None:
            response.close()
        daemon.stop()

    surfaces = {
        "database": json.dumps(_all_command_rows(store), sort_keys=True).encode(),
        "api": raw_activity + raw_analytics,
        "sse": raw_sse,
        "export": raw_diagnostics,
        "logs": caplog.text.encode(),
        "dashboard": raw_activity + raw_analytics + raw_extensions + raw_diagnostics,
    }
    assert store.count_command_activities() == len(commands)
    stable_ids = cast(dict[str, list[str]], diagnostics["stable_ids"])
    assert stable_ids["extensions"]
    assert stable_ids["rules"]
    for surface, serialized in surfaces.items():
        for sentinel in sentinels:
            assert sentinel.encode() not in serialized, f"{surface} leaked {sentinel}"
        for command in commands:
            assert command.encode() not in serialized, f"{surface} leaked the raw command"
