"""Store and query contract tests for the command-activity API."""

# pyright: reportAny=false, reportArgumentType=false, reportGeneralTypeIssues=false
# pyright: reportIndexIssue=false, reportMissingImports=false, reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportUnknownParameterType=false, reportUntypedFunctionDecorator=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_command_activity_api_schema as api_schema
from codex_plugin_scanner.guard.runtime.command_activity_api_contract import (
    CommandActivityAnalyticsQuery,
    CommandActivityFeedbackLabel,
    CommandActivityListQuery,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity_api import (
    CommandActivityNotFoundError,
    _activity_page_query,
)
from tests.guard_command_activity_api_support import evidence, seed


def test_api_schema_is_atomic_strict_and_reopens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    with sqlite3.connect(store.path) as connection:
        tables = {
            str(row[0]) for row in connection.execute("select name from sqlite_schema where type = 'table'").fetchall()
        }
        migration = connection.execute("select version from schema_migrations where version = 13").fetchone()
    assert {"command_activity_feedback", "command_activity_invalidations"} <= tables
    assert migration == (13,)
    GuardStore(store.guard_home, prime_policy_integrity=False)

    database = tmp_path / "failure.db"
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("create table command_activity (activity_id text primary key)")
        statements = api_schema.command_activity_api_schema_statements()
        monkeypatch.setattr(
            api_schema,
            "command_activity_api_schema_statements",
            lambda: (statements[0], "create table"),
        )
        with pytest.raises(sqlite3.OperationalError):
            api_schema.ensure_command_activity_api_schema(connection, applied_at="2026-07-18T20:00:00+00:00")
        assert connection.execute("select 1 from schema_migrations where version = 13").fetchone() is None
        assert (
            connection.execute("select 1 from sqlite_schema where name = 'command_activity_feedback'").fetchone()
            is None
        )


def test_activity_page_is_deterministic_filter_bounded_and_private(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)

    first = store.list_command_activity_page(CommandActivityListQuery(limit=2))
    assert [item["activity_id"] for item in first["items"]] == ["activity:03", "activity:02"]
    assert first["next_marker"] == ("2026-07-18T20:01:00+00:00", "activity:02")
    serialized = repr(first)
    for forbidden in ("correlation", "digest", "command_text", "raw_command", "cwd", "environment"):
        assert forbidden not in serialized

    second = store.list_command_activity_page(
        CommandActivityListQuery(limit=2),
        cursor=("2026-07-18T20:01:00+00:00", "activity:02"),
    )
    assert [item["activity_id"] for item in second["items"]] == ["activity:01"]
    prompted = store.list_command_activity_page(CommandActivityListQuery(prompted=True))
    assert [item["activity_id"] for item in prompted["items"]] == ["activity:02"]
    extension = store.list_command_activity_page(CommandActivityListQuery(extension_id="command.git"))
    assert len(extension["items"]) == 3
    missing_rule = store.list_command_activity_page(CommandActivityListQuery(rule_id="command.git.fetch"))
    assert missing_rule["items"] == []
    through_max = store.list_command_activity_page(CommandActivityListQuery(occurred_through=date.max))
    assert len(through_max["items"]) == 3


@pytest.mark.parametrize(
    "kwargs,error",
    [
        ({"limit": 0}, "limit_out_of_range"),
        ({"harness": "unknown"}, "invalid_harness"),
        ({"execution_status": "executed"}, "invalid_execution_status"),
        ({"proof_level": "guessed"}, "invalid_proof_level"),
        ({"extension_id": "../../private"}, "invalid_extension_id"),
        (
            {"occurred_from": date(2026, 7, 19), "occurred_through": date(2026, 7, 18)},
            "invalid_date_range",
        ),
        (
            {"occurred_from": date(2025, 1, 1), "occurred_through": date(2026, 7, 18)},
            "date_range_out_of_range",
        ),
    ],
)
def test_activity_query_rejects_unbounded_or_unknown_values(kwargs: dict[str, object], error: str) -> None:
    with pytest.raises(ValueError, match=error):
        CommandActivityListQuery(**kwargs)


def test_analytics_reconciles_rollups_and_exposes_bounded_health(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)

    payload = store.command_activity_analytics(
        CommandActivityAnalyticsQuery(days=7, top_limit=5),
        as_of=date(2026, 7, 18),
    )
    assert payload["commands_checked"] == 3
    assert payload["trend"] == [{"day": "2026-07-18", "count": 3}]
    assert payload["dimensions"]["harness"] == [{"value": "codex", "count": 3}]
    assert payload["dimensions"]["extension"] == [{"value": "command.git", "count": 3}]
    assert payload["health"] == {
        "status": "healthy",
        "dropped_events": 0,
        "persistence_errors": 0,
        "last_error_class": None,
        "last_error_at": None,
    }

    filtered = store.command_activity_analytics(
        CommandActivityAnalyticsQuery(days=7, dimension="harness", dimension_value="codex"),
        as_of=date(2026, 7, 18),
    )
    assert filtered["commands_checked"] == 3
    assert filtered["scope"] == {"dimension": "harness", "dimension_value": "codex"}


def test_filtered_analytics_excludes_out_of_scope_feedback(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    store.record_command_activity(evidence("activity:claude", minute=4, harness="claude-code"))
    store.record_command_activity_feedback(
        activity_id="activity:claude",
        label=CommandActivityFeedbackLabel.EXPECTED_GUARD_TO_STOP_THIS,
        recorded_at=datetime(2026, 7, 18, 21, 0, tzinfo=timezone.utc),
    )

    codex = store.command_activity_analytics(
        CommandActivityAnalyticsQuery(days=7, dimension="harness", dimension_value="codex"),
        as_of=date(2026, 7, 18),
    )
    claude = store.command_activity_analytics(
        CommandActivityAnalyticsQuery(days=7, dimension="harness", dimension_value="claude-code"),
        as_of=date(2026, 7, 18),
    )
    assert codex["feedback"] == []
    assert claude["feedback"] == [{"label": "expected_guard_to_stop_this", "count": 1}]


def test_feedback_is_fixed_vocabulary_idempotent_and_never_mutates_activity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    before = store.list_command_activity_page(CommandActivityListQuery())
    recorded_at = datetime(2026, 7, 18, 21, 0, tzinfo=timezone.utc)

    first = store.record_command_activity_feedback(
        activity_id="activity:02",
        label=CommandActivityFeedbackLabel.SHOULD_NOT_HAVE_INTERRUPTED,
        recorded_at=recorded_at,
    )
    replay = store.record_command_activity_feedback(
        activity_id="activity:02",
        label=CommandActivityFeedbackLabel.SHOULD_NOT_HAVE_INTERRUPTED,
        recorded_at=datetime(2026, 7, 18, 22, 0, tzinfo=timezone.utc),
    )
    assert first["changed"] is True
    assert replay["changed"] is False
    after = store.list_command_activity_page(CommandActivityListQuery())
    before_item = next(item for item in before["items"] if item["activity_id"] == "activity:02")
    after_item = next(item for item in after["items"] if item["activity_id"] == "activity:02")
    assert {key: value for key, value in before_item.items() if key != "feedback_label"} == {
        key: value for key, value in after_item.items() if key != "feedback_label"
    }
    assert after_item["feedback_label"] == "should_not_have_interrupted"

    with pytest.raises(CommandActivityNotFoundError):
        store.record_command_activity_feedback(
            activity_id="activity:missing",
            label=CommandActivityFeedbackLabel.EXPECTED_GUARD_TO_STOP_THIS,
            recorded_at=recorded_at,
        )


def test_invalidation_log_is_capped_and_id_only(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    initial_page = store.list_command_activity_invalidations(0)
    items = initial_page["items"]
    assert items
    assert initial_page["reset_required"] is False
    assert all(set(item) == {"sequence", "activity_id"} for item in items)
    store.record_command_activity_feedback(
        activity_id="activity:01",
        label=CommandActivityFeedbackLabel.SHOULD_NOT_HAVE_INTERRUPTED,
        recorded_at=datetime(2026, 7, 18, 21, 0, tzinfo=timezone.utc),
    )
    with sqlite3.connect(store.path) as connection:
        connection.executemany(
            "update command_activity_feedback set updated_at = ? where activity_id = 'activity:01'",
            ((f"2026-07-19T00:00:{index:05d}+00:00",) for index in range(10_100)),
        )
        count = connection.execute("select count(*) from command_activity_invalidations").fetchone()
    assert count is not None
    assert count[0] <= api_schema.COMMAND_ACTIVITY_INVALIDATION_LIMIT
    gap_page = store.list_command_activity_invalidations(0)
    assert gap_page["reset_required"] is True
    assert isinstance(gap_page["reset_cursor"], int)
    assert gap_page["reset_cursor"] > 0


def test_empty_invalidation_log_resets_an_ahead_cursor(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    page = store.list_command_activity_invalidations(42)
    assert page == {"reset_required": True, "reset_cursor": 0, "items": []}


def test_filtered_query_plans_are_index_driven(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    with sqlite3.connect(store.path) as connection:
        status_sql, status_params = _activity_page_query(
            CommandActivityListQuery(execution_status="confirmed_failure"),
            cursor=None,
        )
        status_plan = " ".join(
            str(row[3]) for row in connection.execute(f"explain query plan {status_sql}", status_params).fetchall()
        )
        rule_sql, rule_params = _activity_page_query(
            CommandActivityListQuery(rule_id="command.git.missing"),
            cursor=None,
        )
        rule_plan = " ".join(
            str(row[3]) for row in connection.execute(f"explain query plan {rule_sql}", rule_params).fetchall()
        )
    assert "idx_command_activity_execution_status_occurred_at" in status_plan
    assert "idx_command_activity_match_rule" in rule_plan
    assert "SCAN activity USING INDEX idx_command_activity_occurred_at" not in status_plan
    assert "SCAN activity USING INDEX idx_command_activity_occurred_at" not in rule_plan
