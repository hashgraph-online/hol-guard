from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import codex_plugin_scanner.guard.native_runtime_supervisor as supervisor
from codex_plugin_scanner.guard.native_runtime_supervisor import (
    native_supervisor_journal,
    native_supervisor_record_ready,
    native_supervisor_record_start_failed,
    native_supervisor_request_start,
    native_supervisor_snapshot,
)


def _identity(character: str) -> str:
    return character * 64


def test_native_start_is_single_flight_under_concurrency(tmp_path: Path) -> None:
    identity = _identity("a")
    with ThreadPoolExecutor(max_workers=64) as executor:
        permits = list(
            executor.map(
                lambda _index: native_supervisor_request_start(identity, tmp_path),
                range(64),
            )
        )
    allowed = [permit for permit in permits if permit.allowed]
    assert len(allowed) == 1
    assert all(permit.reason in {"native_starting", "native_start_in_flight"} for permit in permits)


def test_success_resets_restart_streak_but_keeps_lifetime_totals(
    tmp_path: Path,
    monkeypatch,
) -> None:
    now = [100.0]
    monkeypatch.setattr(supervisor.time, "monotonic", lambda: now[0])
    identity = _identity("b")

    first = native_supervisor_request_start(identity, tmp_path)
    assert first.allowed
    native_supervisor_record_start_failed(
        identity,
        tmp_path,
        generation=first.generation,
        reason="native_start_failed",
    )
    failed = native_supervisor_snapshot(identity, tmp_path)
    assert failed.failures == 1
    assert failed.consecutive_failures == 1

    now[0] += 1.0
    second = native_supervisor_request_start(identity, tmp_path)
    assert second.allowed
    native_supervisor_record_ready(
        identity,
        tmp_path,
        generation=second.generation,
    )
    healthy = native_supervisor_snapshot(identity, tmp_path)
    assert healthy.failures == 1
    assert healthy.consecutive_failures == 0
    assert healthy.state == "healthy"


def test_restart_budget_opens_then_half_opens_circuit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    now = [1_000.0]
    monkeypatch.setattr(supervisor.time, "monotonic", lambda: now[0])
    identity = _identity("c")

    for failure_index in range(6):
        permit = native_supervisor_request_start(identity, tmp_path)
        assert permit.allowed, (failure_index, permit)
        native_supervisor_record_start_failed(
            identity,
            tmp_path,
            generation=permit.generation,
            reason="native_start_failed",
        )
        now[0] += 3.0

    opened = native_supervisor_snapshot(identity, tmp_path)
    assert opened.state == "circuit_open"
    assert opened.circuit_open is True
    blocked = native_supervisor_request_start(identity, tmp_path)
    assert blocked.allowed is False
    assert blocked.reason == "native_supervisor_circuit_open"

    now[0] += 16.0
    half_open = native_supervisor_request_start(identity, tmp_path)
    assert half_open.allowed is True
    assert half_open.reason == "native_restarting"


def test_supervisor_journal_is_aggregate_only_and_bounded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    now = [2_000.0]
    monkeypatch.setattr(supervisor.time, "monotonic", lambda: now[0])
    identity = _identity("d")
    permit = native_supervisor_request_start(identity, tmp_path)
    assert permit.allowed
    native_supervisor_record_start_failed(
        identity,
        tmp_path,
        generation=permit.generation,
        reason="unsafe reason /private/path with spaces",
    )
    journal = native_supervisor_journal(identity, tmp_path)
    assert journal
    assert len(journal) <= 64
    serialized = repr(journal)
    assert "/private/path" not in serialized
    assert "unsafe reason" not in serialized
    assert journal[-1].reason == "native_start_failed"
