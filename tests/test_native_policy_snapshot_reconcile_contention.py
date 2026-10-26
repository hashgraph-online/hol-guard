"""A locked store during reconcile republishes instead of ending the publisher."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_reconcile import reconcile_policy_inputs
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _DeterministicClock


def _acked_publisher(tmp_path: Path, clock: _DeterministicClock, mode: str) -> NativePolicySnapshotPublisher:
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.01,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    publisher._snapshot = {
        "mode": mode,
        "generation": 7,
        "config_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "expires_at_ms": int(clock.wall * 1_000) + 60_000,
    }
    publisher._acked = True
    return publisher


def _locked_store(**_kwargs: object) -> bool:
    raise sqlite3.OperationalError("locking protocol")


def test_unreadable_policy_input_withdraws_enforce_readiness_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _acked_publisher(tmp_path, clock, "enforce")
    lane_closures: list[None] = []
    fingerprint = publisher._current_input_fingerprint()
    publisher._input_fingerprint = fingerprint
    monkeypatch.setattr(publisher, "_current_input_fingerprint", lambda: fingerprint)
    monkeypatch.setattr(publisher, "_policy_input_changed", lambda changed_paths=None: _locked_store())
    monkeypatch.setattr(publisher, "_close_direct_lane_ack", lambda: lane_closures.append(None))
    publisher._reconcile_due_monotonic = clock.monotonic
    try:
        reconcile_policy_inputs(publisher)

        assert not publisher.is_ready(), "an unreadable input may be a stricter policy"
        assert publisher._publish_event.is_set()
        assert len(lane_closures) == 1

        publisher._publish_event.clear()
        publisher._failure_count = 3
        retry_at = clock.monotonic + 30.0
        publisher._retry_not_before_monotonic = retry_at
        clock.monotonic += 1.5
        reconcile_policy_inputs(publisher)

        assert not publisher.is_ready()
        assert publisher._failure_count == 3, "a pending publish keeps its retry backoff"
        assert publisher._retry_not_before_monotonic == retry_at
        assert not publisher._publish_event.is_set()
        assert len(lane_closures) == 2
    finally:
        publisher.close()


def test_unreadable_fingerprint_keeps_the_last_known_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _acked_publisher(tmp_path, clock, "observe")
    previous = publisher._current_input_fingerprint()
    publisher._input_fingerprint = previous

    def unreadable_fingerprint() -> object:
        raise OSError("sharing violation")

    monkeypatch.setattr(publisher, "_current_input_fingerprint", unreadable_fingerprint)
    try:
        reconcile_policy_inputs(publisher)

        assert publisher._input_fingerprint == previous
        assert publisher._renewal_after_generation == 7, "Watch refreshes under its existing ACK"
        assert publisher._publish_event.is_set()
    finally:
        publisher.close()


def test_publisher_thread_survives_a_locked_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _acked_publisher(tmp_path, clock, "enforce")
    attempts = 0
    retried = threading.Event()

    def locked_fingerprint() -> object:
        nonlocal attempts
        attempts += 1
        if attempts >= 3:
            retried.set()
        raise sqlite3.OperationalError("locking protocol")

    monkeypatch.setattr(publisher, "_provision_verifier_key", lambda: None)
    monkeypatch.setattr(publisher, "_publish_once", lambda **_kwargs: None)
    monkeypatch.setattr(publisher, "_current_input_fingerprint", locked_fingerprint)
    try:
        publisher.start()

        assert retried.wait(timeout=10.0), "the publisher must keep polling after a store error"
        assert publisher._thread is not None
        assert publisher._thread.is_alive()
        assert not publisher.is_ready()
    finally:
        publisher.close()
