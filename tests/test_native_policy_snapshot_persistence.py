"""Durability, retry, recovery, and renewal tests for native snapshots."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
from codex_plugin_scanner.guard.native_policy_snapshot import (
    NATIVE_POLICY_SNAPSHOT_CACHE_NAME,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
    NativePolicySnapshotPublisher,
    snapshot_bytes_v3,
)
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _config, _DeterministicClock, _status

# Split modules are implementation containers; the compatibility façade imports
# their test functions so the historical test path keeps identical collection.
__test__ = False


@pytest.mark.parametrize("boundary", ("cache", "state", "cleanup"))
def test_snapshot_transaction_recovers_each_persistence_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    master = b"z" * 32
    future_ms = int(time.time() * 1_000) + 60_000
    original_cache_writer = snapshot_module._write_v3_snapshot_cache
    original_state_writer = snapshot_module._write_v3_generation_state
    original_cleanup = snapshot_module._clear_v3_snapshot_pending

    def fail_once(*_args: object, **_kwargs: object) -> bytes:
        raise snapshot_module.NativePolicySnapshotError("injected_persistence_crash")

    if boundary == "cache":
        monkeypatch.setattr(snapshot_module, "_write_v3_snapshot_cache", fail_once)
    elif boundary == "state":
        monkeypatch.setattr(snapshot_module, "_write_v3_generation_state", fail_once)
    else:
        monkeypatch.setattr(snapshot_module, "_clear_v3_snapshot_pending", fail_once)
    with pytest.raises(snapshot_module.NativePolicySnapshotError, match="injected_persistence_crash"):
        snapshot_module.native_policy_snapshot_v3(
            config=_config(),
            guard_home=guard_home,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            policy_integrity_key=master,
            issued_at_ms=future_ms,
            expires_at_ms=future_ms + 60_000,
        )
    monkeypatch.setattr(snapshot_module, "_write_v3_snapshot_cache", original_cache_writer)
    monkeypatch.setattr(snapshot_module, "_write_v3_generation_state", original_state_writer)
    monkeypatch.setattr(snapshot_module, "_clear_v3_snapshot_pending", original_cleanup)

    recovered = snapshot_module.native_policy_snapshot_v3(
        config=_config(),
        guard_home=guard_home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        policy_integrity_key=master,
        issued_at_ms=future_ms + 10_000,
        expires_at_ms=future_ms + 70_000,
    )
    cache_path = guard_home / "native-runtime" / NATIVE_POLICY_SNAPSHOT_CACHE_NAME
    pending_path = guard_home / "native-runtime" / "policy-snapshot-publisher-v3.pending.json"
    assert recovered["generation"] == 1
    assert cache_path.read_bytes() == snapshot_bytes_v3(recovered)
    assert not pending_path.exists()


def test_lost_ack_retries_identical_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"v" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return None if len(calls) == 1 else _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 2.0)
        assert len(calls) >= 2
        assert calls[1] == calls[0]
    finally:
        publisher.close()


def test_floor_only_ack_materializes_strictly_new_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"f" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        snapshot = json.loads(payload)["request"]["snapshot"]
        if len(calls) == 1:
            return json.dumps(
                {
                    "status": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
                    "generation": snapshot["generation"],
                    "policy_digest": "d" * 64,
                    "idempotent": False,
                    "resident_generation": 1,
                }
            ).encode()
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    try:
        publisher._publish_once()
        snapshot = publisher.current_snapshot()
        assert snapshot is not None
        assert snapshot["generation"] == 2
        assert json.loads(calls[1])["request"]["snapshot"]["generation"] == 2
        assert calls[1] != calls[0]
        assert publisher.is_ready()
    finally:
        publisher.close()


@pytest.mark.parametrize(
    "response",
    (
        {"error": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION, "retryable": False},
        {
            "status": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
            "generation": 1,
            "policy_digest": "d" * 64,
            "idempotent": True,
            "resident_generation": 1,
        },
        {
            "status": POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
            "generation": 1,
            "policy_digest": "d" * 64,
            "idempotent": False,
            "resident_generation": 1,
            "unexpected": True,
        },
    ),
)
def test_floor_recovery_requires_exact_typed_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, object],
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"g" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls = 0

    def client_request(**_kwargs: object) -> bytes:
        nonlocal calls
        calls += 1
        return json.dumps(response).encode()

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    try:
        publisher._publish_once()
        assert calls == 1
        assert not publisher.is_ready()
        assert publisher.last_error == "native_policy_snapshot_ack_invalid"
    finally:
        publisher.close()


def test_publisher_surfaces_resident_start_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"s" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))

    def client_request(**_kwargs: object) -> bytes:
        return b'{"error":"native_resident_start_timeout","retryable":false}'

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
    )
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_resident_start_timeout"
    finally:
        publisher.close()


def test_publisher_process_restart_reuses_cached_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"w" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    first_calls: list[bytes] = []

    def first_client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        first_calls.append(payload)
        return _ack(payload)

    first_publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=first_client,
        poll_interval_seconds=0.05,
    )
    first_publisher.start()
    assert first_publisher.wait_until_ready(time.monotonic() + 2.0)
    first_publisher.close()

    second_calls: list[bytes] = []

    def second_client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        second_calls.append(payload)
        return _ack(payload)

    second_publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=second_client,
        poll_interval_seconds=0.05,
    )
    second_publisher.start()
    try:
        assert second_publisher.wait_until_ready(time.monotonic() + 2.0)
        assert first_calls and second_calls
        assert second_calls[0] == first_calls[0]
    finally:
        second_publisher.close()


def test_renewal_materializes_higher_generation_before_expiry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"x" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    clock = _DeterministicClock()
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        publisher._publish_once()
        first = publisher.current_snapshot()
        assert first is not None
        due = publisher._renewal_due_monotonic
        assert due is not None
        assert due < clock.monotonic + 24 * 60 * 60

        clock.monotonic = due + 0.001
        clock.wall += 1.0
        publisher._publish_once(renew_after_generation=first["generation"])
        renewed = publisher.current_snapshot()
        assert renewed is not None
        assert renewed["generation"] > first["generation"]
        assert renewed["expires_at_ms"] > first["expires_at_ms"]
        assert len(calls) == 2
    finally:
        publisher.close()


def test_renewal_failure_keeps_barrier_closed_at_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"y" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    clock = _DeterministicClock()
    calls = 0

    def client_request(**kwargs: object) -> bytes | None:
        nonlocal calls
        calls += 1
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload) if calls == 1 else None

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        publisher._publish_once()
        first = publisher.current_snapshot()
        assert first is not None
        publisher._publish_once(renew_after_generation=first["generation"])
        assert publisher.is_ready()
        clock.wall = first["expires_at_ms"] / 1_000
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_renewal_retry_reuses_candidate_with_bounded_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"q" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    clock = _DeterministicClock()
    calls: list[bytes] = []

    def client_request(**kwargs: object) -> bytes | None:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        calls.append(payload)
        return _ack(payload) if len(calls) != 2 else None

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        publisher._publish_once()
        first = publisher.current_snapshot()
        assert first is not None
        publisher._publish_once(renew_after_generation=first["generation"])
        retry_at = publisher._retry_not_before_monotonic
        assert retry_at is not None
        assert clock.monotonic < retry_at <= clock.monotonic + 0.2
        clock.monotonic = retry_at + 0.001
        publisher._publish_once(renew_after_generation=first["generation"])
        renewed = publisher.current_snapshot()
        assert renewed is not None
        assert renewed["generation"] > first["generation"]
        assert len(calls) == 3
        assert calls[2] == calls[1]
    finally:
        publisher.close()
