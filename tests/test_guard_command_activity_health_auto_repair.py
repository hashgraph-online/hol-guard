"""The dashboard read path repairs stale command-activity health on its own."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon import command_activity_health_repair
from codex_plugin_scanner.guard.daemon.command_activity_api import handle_command_activity_analytics
from codex_plugin_scanner.guard.daemon.command_activity_health_repair import (
    COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS,
    COMMAND_ACTIVITY_REPAIR_QUIET_SECONDS,
    auto_repair_command_activity_health,
    auto_repair_command_activity_health_if_degraded,
    reset_command_activity_auto_repair,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_command_activity_api_support import seed

_FAILED_AT = datetime(2026, 7, 18, 20, 4, tzinfo=timezone.utc)


class _Handler:
    def __init__(self, store: GuardStore) -> None:
        self.server = SimpleNamespace(store=store, auth_token="token")
        self.responses: list[tuple[dict[str, object], int]] = []

    def _write_json(self, payload: dict[str, object], status: int = 200) -> None:
        self.responses.append((payload, status))


@pytest.fixture(autouse=True)
def _clean_limiter() -> None:
    reset_command_activity_auto_repair()


def _degraded_store(tmp_path: Path, failed_at: datetime = _FAILED_AT) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    store.record_command_activity_persistence_failure(error_code="pre_record_failed", occurred_at=failed_at)
    return store


def _count_probes(monkeypatch: pytest.MonkeyPatch) -> list[GuardStore]:
    calls: list[GuardStore] = []

    def probe(target: GuardStore) -> None:
        calls.append(target)

    monkeypatch.setattr(command_activity_health_repair, "_repair_command_activity_persistence_health", probe)
    return calls


def _ticks(*values: float):
    ticks = iter(values)
    return lambda: next(ticks)


def _analytics_health(store: GuardStore) -> dict[str, object]:
    handler = _Handler(store)
    handle_command_activity_analytics(handler, "days=7")
    payload, status = handler.responses[-1]
    assert status == 200
    return cast(dict[str, object], payload["health"])


def test_degraded_health_from_a_past_failure_clears_on_the_next_dashboard_read(tmp_path: Path) -> None:
    store = _degraded_store(tmp_path)

    health = _analytics_health(store)

    assert health["status"] == "healthy"
    # The failure stays on record; only the stale active flag is cleared.
    assert health["persistence_errors"] == 1
    assert health["last_error_class"] == "pre_record_failed"
    assert store.get_command_activity_persistence_health().active_error_count == 0


def test_healthy_reads_do_not_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    calls: list[GuardStore] = []
    monkeypatch.setattr(
        command_activity_health_repair,
        "_repair_command_activity_persistence_health",
        lambda target: calls.append(target),
    )

    assert _analytics_health(store)["status"] == "healthy"
    assert calls == []


def test_a_store_that_stays_broken_is_probed_once_per_interval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _degraded_store(tmp_path)
    calls = _count_probes(monkeypatch)
    monkeypatch.setattr(store, "maintain_command_activity", lambda **_kwargs: None)
    clock = _ticks(
        100.0,
        100.0 + COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS / 2,
        100.0 + COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS,
    )

    assert auto_repair_command_activity_health(store, clock=clock) is True
    assert auto_repair_command_activity_health(store, clock=clock) is False
    assert auto_repair_command_activity_health(store, clock=clock) is True
    assert len(calls) == 2


def test_a_recent_failure_stays_visible_until_failures_stop(tmp_path: Path) -> None:
    failed_at = datetime(2026, 7, 18, 20, 4, tzinfo=timezone.utc)
    store = _degraded_store(tmp_path, failed_at)
    quiet = timedelta(seconds=COMMAND_ACTIVITY_REPAIR_QUIET_SECONDS)
    wall = iter([failed_at + quiet / 2, failed_at + quiet, failed_at + quiet])

    def now() -> datetime:
        return next(wall)

    clock = _ticks(10.0, 10.0 + COMMAND_ACTIVITY_REPAIR_QUIET_SECONDS / 2)

    assert auto_repair_command_activity_health(store, clock=clock, now=now) is False
    assert store.get_command_activity_persistence_health().active_error_count == 1
    assert auto_repair_command_activity_health(store, clock=clock, now=now) is True
    assert store.get_command_activity_persistence_health().active_error_count == 0


def test_a_failing_probe_leaves_the_read_degraded_instead_of_erroring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _degraded_store(tmp_path)

    def broken(_target: GuardStore) -> None:
        raise RuntimeError("store unavailable")

    monkeypatch.setattr(command_activity_health_repair, "_repair_command_activity_persistence_health", broken)

    health = _analytics_health(store)

    assert health["status"] == "degraded"
    assert health["last_error_class"] == "pre_record_failed"


def test_runtime_reads_check_stored_health_once_per_interval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _degraded_store(tmp_path)
    calls = _count_probes(monkeypatch)
    monkeypatch.setattr(store, "maintain_command_activity", lambda **_kwargs: None)
    # check and attempt, then a second check inside the check interval
    clock = _ticks(10.0, 10.0, 11.0)

    assert auto_repair_command_activity_health_if_degraded(store, clock=clock) is True
    assert auto_repair_command_activity_health_if_degraded(store, clock=clock) is False
    assert len(calls) == 1


def test_runtime_reads_leave_healthy_stores_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    seed(store)
    monkeypatch.setattr(
        command_activity_health_repair,
        "_repair_command_activity_persistence_health",
        lambda _target: pytest.fail("a healthy store must not be probed"),
    )

    assert auto_repair_command_activity_health_if_degraded(store) is False
