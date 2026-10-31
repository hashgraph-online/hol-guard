"""Recovery semantics for current command-activity persistence health."""

# pyright: reportAny=false, reportIndexIssue=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.runtime.command_activity_api_contract import CommandActivityAnalyticsQuery
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_command_activity_api_support import evidence, seed

_NOW = datetime(2026, 7, 18, 20, 4, tzinfo=timezone.utc)


def _health(store: GuardStore) -> dict[str, object]:
    payload = store.command_activity_analytics(
        CommandActivityAnalyticsQuery(days=7),
        as_of=date(2026, 7, 18),
    )
    return cast(dict[str, object], payload["health"])


def test_command_health_recovers_by_write_order_without_resetting_counters(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    store.record_command_activity(evidence("activity:future-event", minute=10))
    store.record_command_activity_persistence_failure(error_code="post_record_failed", occurred_at=_NOW)
    assert _health(store)["status"] == "degraded"

    store.record_command_activity(evidence("activity:delayed-event", minute=3))
    recovered = _health(store)
    assert recovered["status"] == "healthy"
    assert recovered["dropped_events"] == recovered["persistence_errors"] == 1
    assert recovered["last_error_class"] == "post_record_failed"


def test_interleaved_failure_domains_recover_independently(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity_persistence_failure(error_code="maintenance_failed", occurred_at=_NOW)
    store.record_command_activity_persistence_failure(error_code="post_record_failed", occurred_at=_NOW)
    store.record_command_activity(evidence("activity:command-recovered", minute=5))
    assert _health(store)["status"] == "degraded"

    store.maintain_command_activity(now=_NOW, detail_retain_days=30)
    recovered = _health(store)
    assert recovered["status"] == "healthy"
    assert recovered["dropped_events"] == recovered["persistence_errors"] == 2


def test_command_write_does_not_mask_maintenance_failure(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    store.record_command_activity_persistence_failure(error_code="maintenance_failed", occurred_at=_NOW)
    store.record_command_activity(evidence("activity:command-success", minute=5))
    assert _health(store)["status"] == "degraded"
