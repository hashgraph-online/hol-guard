"""Regression coverage for resident-fence retry backoff."""

from __future__ import annotations

from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publisher as publisher_module
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _DeterministicClock


def test_resident_fingerprint_mismatch_enters_bounded_retry_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    clock = _DeterministicClock()
    publisher = NativePolicySnapshotPublisher(
        store=store,
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    publisher._snapshot = {"expires_at_ms": int(clock.wall * 1_000) + 60_000, "generation": 1}
    publisher._acked = True
    assert publisher.is_ready()
    publisher._retry_not_before_monotonic = clock.monotonic - 1.0
    stale_fingerprint = (
        (),
        (("resident-v3-stale/generation-00000000000000000001.json", 1, 1),),
    )
    fingerprints = iter((stale_fingerprint, stale_fingerprint))
    monkeypatch.setattr(publisher, "_current_input_fingerprint", lambda: next(fingerprints))
    monkeypatch.setattr(
        publisher,
        "_publication_context",
        lambda: (None, None, b"key", {}, lambda **_kwargs: b"unused"),
    )
    monkeypatch.setattr(
        publisher_module,
        "_publish_snapshot_v3",
        lambda **_kwargs: ({}, 2),
    )
    try:
        publisher._publish_once()
        retry_deadline = publisher._retry_not_before_monotonic
        assert publisher.last_error == "native_policy_snapshot_resident_changed"
        assert not publisher.is_ready()
        assert publisher._failure_count == 1
        assert retry_deadline is not None and retry_deadline > clock.monotonic
    finally:
        publisher.close()


def test_run_loop_backs_off_after_resident_mismatch_at_expired_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    resident_fingerprint = (
        (),
        (("resident-v3-stale/generation-00000000000000000001.json", 1, 1),),
    )
    publisher._input_fingerprint = resident_fingerprint
    publisher._snapshot = {"expires_at_ms": int(clock.wall * 1_000) + 60_000, "generation": 1}
    publisher._acked = True
    publisher._renewal_after_generation = 1
    publisher._retry_not_before_monotonic = clock.monotonic - 1.0
    monkeypatch.setattr(publisher, "_current_input_fingerprint", lambda: resident_fingerprint)
    monkeypatch.setattr(
        publisher,
        "_publication_context",
        lambda: (None, None, b"key", {}, lambda **_kwargs: b"unused"),
    )
    monkeypatch.setattr(publisher_module, "_publish_snapshot_v3", lambda **_kwargs: ({}, 2))

    class StopAfterResidentRetry:
        def __init__(self) -> None:
            self.wait_timeouts: list[float] = []
            self.ready_before_close: bool | None = None

        def wait(self, timeout: float | None = None) -> bool:
            assert timeout is not None
            self.wait_timeouts.append(timeout)
            if len(self.wait_timeouts) == 2:
                self.ready_before_close = publisher.is_ready()
                publisher.close()
            return False

        def clear(self) -> None:
            return

        def set(self) -> None:
            return

    event = StopAfterResidentRetry()
    monkeypatch.setattr(publisher, "_publish_event", event)
    try:
        assert publisher.is_ready()
        publisher._run()
        assert event.wait_timeouts[0] == 0.0
        assert len(event.wait_timeouts) == 2
        assert event.wait_timeouts[1] > 0.0
        assert event.ready_before_close is False
        assert publisher.last_error == "native_policy_snapshot_resident_changed"
    finally:
        publisher.close()


def test_run_loop_preserves_failed_retry_backoff_across_stable_database_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    database_path = str(publisher.guard_home / "guard.db-wal")
    baseline = (((database_path, (1, 1, 1, 1)),), ())
    changed_inputs = iter(
        (
            (((database_path, (2, 1, 1, 1)),), ()),
            (((database_path, (3, 1, 1, 1)),), ()),
        )
    )
    policy = {"mode": "enforce", "blocked_capabilities": ["network"]}
    publisher._input_fingerprint = baseline
    monkeypatch.setattr(publisher, "_current_input_fingerprint", lambda: next(changed_inputs))
    monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda: policy)
    attempts: list[float | None] = []
    request_count = 0
    original_request_publish = publisher.request_publish

    def request_publish() -> None:
        nonlocal request_count
        request_count += 1
        original_request_publish()

    def failed_publish(**_kwargs: object) -> None:
        publisher._record_error("native_policy_snapshot_resident_changed")
        attempts.append(publisher._retry_not_before_monotonic)

    class StopAfterSecondWait:
        def __init__(self) -> None:
            self.wait_timeouts: list[float] = []
            self.set_calls = 0

        def wait(self, timeout: float | None = None) -> bool:
            assert timeout is not None
            self.wait_timeouts.append(timeout)
            if len(self.wait_timeouts) == 2:
                publisher.close()
            return False

        def clear(self) -> None:
            return

        def set(self) -> None:
            self.set_calls += 1

    event = StopAfterSecondWait()
    monkeypatch.setattr(publisher, "request_publish", request_publish)
    monkeypatch.setattr(publisher, "_publish_once", failed_publish)
    monkeypatch.setattr(publisher, "_publish_event", event)
    try:
        publisher._run()
        assert len(event.wait_timeouts) == 2
        assert request_count == 1
        assert len(attempts) == 1
        assert attempts[0] is not None and attempts[0] > clock.monotonic
        assert publisher._retry_not_before_monotonic == attempts[0]
        assert publisher._failure_count == 1
    finally:
        publisher.close()


def test_stable_database_heartbeat_does_not_reset_failed_retry_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
    )
    policy = {"mode": "enforce", "blocked_capabilities": ["network"]}
    database_change = {str(publisher.guard_home / "guard.db-wal")}
    monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda: policy)
    try:
        assert publisher._policy_input_changed(database_change)
        publisher._record_error("native_policy_snapshot_resident_changed")
        retry_deadline = publisher._retry_not_before_monotonic

        assert not publisher._policy_input_changed(database_change)
        assert publisher._retry_not_before_monotonic == retry_deadline
    finally:
        publisher.close()


def test_non_database_policy_change_records_observation_before_failed_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
    )
    enforce_policy = {"mode": "enforce", "blocked_capabilities": ["network"]}
    observe_policy = {"mode": "observe", "blocked_capabilities": ["network"]}
    database_change = {str(publisher.guard_home / "guard.db-wal")}
    external_change = {str(publisher.guard_home / "managed-policy-cache.json")}
    policies = iter((enforce_policy, observe_policy, observe_policy))
    monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda: next(policies))
    try:
        assert publisher._policy_input_changed(database_change)
        assert publisher._policy_input_changed(external_change)
        publisher._record_error("native_policy_snapshot_resident_changed")
        retry_deadline = publisher._retry_not_before_monotonic

        assert not publisher._policy_input_changed(database_change)
        assert publisher._retry_not_before_monotonic == retry_deadline
        assert publisher._failure_count == 1
    finally:
        publisher.close()


def test_non_database_policy_change_revokes_readiness_before_compilation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    publisher._snapshot = {"expires_at_ms": int(clock.wall * 1_000) + 60_000, "generation": 1}
    publisher._acked = True

    def compile_policy() -> dict[str, object]:
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        return {"mode": "enforce", "blocked_capabilities": ["network"]}

    monkeypatch.setattr(publisher, "_compiled_effective_policy", compile_policy)
    try:
        assert publisher.is_ready()
        assert publisher._policy_input_changed({str(tmp_path / ".hol-guard.toml")})
        assert not publisher.is_ready()
    finally:
        publisher.close()


@pytest.mark.parametrize("config_mode", ["enforce", "observe"])
def test_config_change_revokes_readiness_before_compilation_and_preserves_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_mode: str,
) -> None:
    clock = _DeterministicClock()
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    enforce_policy = {"mode": "enforce", "blocked_capabilities": ["network"]}
    config_policy = {"mode": config_mode, "blocked_capabilities": ["network"]}
    database_change = {str(publisher.guard_home / "guard.db-wal")}
    config_change = {str(publisher.guard_home / "config.toml")}
    policies = iter((enforce_policy, config_policy, config_policy))

    def compile_policy() -> dict[str, object]:
        policy = next(policies)
        if policy is config_policy:
            assert not publisher.is_ready()
            assert publisher.current_snapshot_binding() is None
        return policy

    monkeypatch.setattr(publisher, "_compiled_effective_policy", compile_policy)
    publisher._snapshot = {"expires_at_ms": int(clock.wall * 1_000) + 60_000, "generation": 1}
    try:
        assert publisher._policy_input_changed(database_change)
        publisher._acked = True
        assert publisher.is_ready()
        assert publisher.current_snapshot_binding() is not None

        assert publisher._policy_input_changed(config_change)
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None

        publisher._record_error("native_policy_snapshot_resident_changed")
        retry_deadline = publisher._retry_not_before_monotonic
        assert retry_deadline is not None

        assert not publisher._policy_input_changed(database_change)
        assert publisher._retry_not_before_monotonic == retry_deadline
        assert publisher._failure_count == 1
    finally:
        publisher.close()


def test_invalid_policy_observation_then_valid_recovery_rearms_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
    )
    policy = {"mode": "enforce", "blocked_capabilities": ["network"]}
    database_change = {str(publisher.guard_home / "guard.db-wal")}
    observations: list[object] = [OSError("invalid policy"), OSError("invalid policy"), policy, policy]

    def observe_policy() -> dict[str, object]:
        observation = observations.pop(0)
        if isinstance(observation, BaseException):
            raise observation
        return observation

    monkeypatch.setattr(publisher, "_compiled_effective_policy", observe_policy)
    try:
        assert publisher._policy_input_changed(database_change)
        assert not publisher._policy_input_changed(database_change)
        assert publisher._policy_input_changed(database_change)
        assert not publisher._policy_input_changed(database_change)

        mode_only_policy = {**policy, "mode": "observe"}
        monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda: mode_only_policy)
        assert publisher._policy_input_changed(database_change)
        assert not publisher._policy_input_changed(database_change)
    finally:
        publisher.close()
