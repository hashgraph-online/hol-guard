"""A resident that stops answering is revived and waited for inside the hook budget."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_policy_admission import _native_policy_not_ready_reason
from codex_plugin_scanner.guard.daemon.hook_worker_readiness import prepare_workspace_policy
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_resident_recovery import (
    RESIDENT_FAIL_FAST_STREAK,
    RESIDENT_NUDGE_MIN_INTERVAL_SECONDS,
    RESIDENT_REVIVE_COOLDOWN_SECONDS,
    RESIDENT_REVIVE_FAILURE_STREAK,
    RESIDENT_REVIVE_MAX_ATTEMPTS,
    is_resident_class_error,
)
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _DeterministicClock, _status

_TIMED_OUT = json.dumps({"error": "native_client_timed_out", "retryable": True}).encode()


def _idle_publisher(
    tmp_path: Path, clock: _DeterministicClock, *, poll_interval_seconds: float = 0.05
) -> NativePolicySnapshotPublisher:
    return NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=poll_interval_seconds,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )


def test_only_resident_transport_failures_count_as_resident_class() -> None:
    for code in (
        "native_client_timed_out",
        "native_client_connect_failed",
        "native_frame_timeout_failed",
        "native_resident_restart_circuit_open",
    ):
        assert is_resident_class_error(code), code
    for code in (
        None,
        "",
        "native_policy_snapshot_ack_mismatch",
        "native_policy_snapshot_resident_changed",
        "native_command_program_binding_mismatch",
        "OSError",
    ):
        assert not is_resident_class_error(code), code


def test_repeated_resident_failures_revive_the_resident_once_per_cooldown(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock)
    revived = threading.Event()
    calls: list[Path] = []

    def reviver(guard_home: Path) -> bool:
        calls.append(guard_home)
        revived.set()
        return True

    publisher._resident_reviver = reviver
    try:
        for _ in range(RESIDENT_REVIVE_FAILURE_STREAK - 1):
            publisher._record_error("native_client_timed_out")
        assert not revived.wait(0.2)
        publisher._record_error("native_client_timed_out")
        assert revived.wait(2.0)
        assert calls == [publisher.guard_home]

        # A revival that did not help is not repeated inside the cooldown.
        revived.clear()
        for _ in range(3):
            publisher._record_error("native_client_timed_out")
        assert not revived.wait(0.2)

        clock.monotonic += RESIDENT_REVIVE_COOLDOWN_SECONDS + 1.0
        publisher._record_error("native_client_timed_out")
        assert revived.wait(2.0)
        assert len(calls) == 2
    finally:
        publisher.close()


def test_failures_that_are_not_the_resident_never_revive_it(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock)
    revived = threading.Event()
    publisher._resident_reviver = lambda _home: revived.set() or True
    try:
        for _ in range(RESIDENT_REVIVE_FAILURE_STREAK + 2):
            publisher._record_error("native_policy_snapshot_ack_mismatch")
        assert not revived.wait(0.2)
        assert publisher.resident_failure_streak() == 0
    finally:
        publisher.close()


def test_a_resident_that_never_comes_back_stops_being_revived(tmp_path: Path) -> None:
    """Revival resets the crash-loop budget, so it cannot run forever without an acknowledgement."""
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock)
    calls: list[Path] = []
    publisher._resident_reviver = lambda home: calls.append(home) is None
    try:
        for _ in range(RESIDENT_REVIVE_FAILURE_STREAK):
            publisher._record_error("native_client_timed_out")
        for _ in range(RESIDENT_REVIVE_MAX_ATTEMPTS + 3):
            clock.monotonic += RESIDENT_REVIVE_COOLDOWN_SECONDS + 1.0
            publisher._record_error("native_client_timed_out")
        deadline = time.monotonic() + 2.0
        while len(calls) < RESIDENT_REVIVE_MAX_ATTEMPTS and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.2)
        assert len(calls) == RESIDENT_REVIVE_MAX_ATTEMPTS

        # An acknowledgement refills the budget.
        with publisher._condition:
            publisher._note_resident_acknowledged_locked()
        for _ in range(RESIDENT_REVIVE_FAILURE_STREAK):
            clock.monotonic += RESIDENT_REVIVE_COOLDOWN_SECONDS + 1.0
            publisher._record_error("native_client_timed_out")
        deadline = time.monotonic() + 2.0
        while len(calls) == RESIDENT_REVIVE_MAX_ATTEMPTS and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(calls) == RESIDENT_REVIVE_MAX_ATTEMPTS + 1
    finally:
        publisher.close()


def test_a_failure_the_resident_answered_ends_the_run_of_resident_failures(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock)
    revived = threading.Event()
    publisher._resident_reviver = lambda _home: revived.set() or True
    try:
        for _ in range(RESIDENT_REVIVE_FAILURE_STREAK - 1):
            publisher._record_error("native_client_timed_out")
        publisher._record_error("native_policy_snapshot_ack_mismatch")
        assert publisher.resident_failure_streak() == 0
        publisher._record_error("native_client_timed_out")
        assert publisher.resident_failure_streak() == 1
        assert not revived.wait(0.2)
    finally:
        publisher.close()


def test_a_revival_that_fails_or_does_not_help_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock)
    outcomes = iter([False, OSError("runtime missing")])

    def reviver(_home: Path) -> bool:
        outcome = next(outcomes)
        if isinstance(outcome, OSError):
            raise outcome
        return outcome

    publisher._resident_reviver = reviver
    try:
        with caplog.at_level("INFO", logger="codex_plugin_scanner.guard.native_policy_snapshot_resident_recovery"):
            for _ in range(RESIDENT_REVIVE_FAILURE_STREAK):
                publisher._record_error("native_client_timed_out")
            thread = publisher._start_resident_revival()
            assert thread is not None
            thread.join(2.0)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and not (
                "did not bring the resident back" in caplog.text and "revival failed: OSError" in caplog.text
            ):
                time.sleep(0.01)
        assert "did not bring the resident back" in caplog.text
        assert "revival failed: OSError" in caplog.text
    finally:
        publisher.close()


def test_a_failing_reviver_cannot_break_the_publisher(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock)
    attempted = threading.Event()

    def reviver(_home: Path) -> bool:
        attempted.set()
        raise OSError("runtime missing")

    publisher._resident_reviver = reviver
    try:
        for _ in range(RESIDENT_REVIVE_FAILURE_STREAK):
            publisher._record_error("native_client_timed_out")
        assert attempted.wait(2.0)
        assert publisher.last_error == "native_client_timed_out"
    finally:
        publisher.close()


def test_nudge_pulls_the_retry_forward_and_is_rate_limited(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock, poll_interval_seconds=2.0)
    try:
        # The first attempt is still in flight, so there is nothing to retry.
        assert not publisher.nudge_retry()

        publisher._record_error("native_client_timed_out")
        retry_at = publisher._retry_not_before_monotonic
        assert retry_at is not None and retry_at > clock.monotonic
        publisher._note_publish_attempt()
        assert not publisher.nudge_retry()
        assert publisher._retry_not_before_monotonic == retry_at

        clock.monotonic += RESIDENT_NUDGE_MIN_INTERVAL_SECONDS + 0.01
        assert publisher.nudge_retry()
        assert publisher._retry_not_before_monotonic == clock.monotonic
        assert publisher._publish_event.is_set()
    finally:
        publisher.close()


def test_nudge_does_nothing_for_failures_a_retry_cannot_clear(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _idle_publisher(tmp_path, clock)
    try:
        publisher._record_error("native_command_program_binding_mismatch")
        clock.monotonic += 10.0
        publisher._publish_event.clear()
        assert not publisher.nudge_retry()
        assert not publisher._publish_event.is_set()
    finally:
        publisher.close()


def _publisher_with_flaky_resident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    failures: int,
    poll_interval_seconds: float,
) -> tuple[NativePolicySnapshotPublisher, list[int]]:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"k" * 32
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (master, "master-id"))
    calls: list[int] = []

    def client_request(**kwargs: object) -> bytes:
        calls.append(len(calls))
        if len(calls) <= failures:
            return _TIMED_OUT
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=poll_interval_seconds,
    )
    return publisher, calls


def test_publisher_recovers_after_failures_and_clears_the_streak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher, calls = _publisher_with_flaky_resident(
        tmp_path, monkeypatch, failures=RESIDENT_REVIVE_FAILURE_STREAK, poll_interval_seconds=0.05
    )
    revived = threading.Event()
    publisher._resident_reviver = lambda _home: revived.set() or True
    publisher.start()
    try:
        assert publisher.wait_until_ready(time.monotonic() + 10.0)
        assert revived.wait(2.0)
        assert len(calls) == RESIDENT_REVIVE_FAILURE_STREAK + 1
        assert publisher.resident_failure_streak() == 0
        assert publisher.last_error is None
    finally:
        publisher.close()


def test_waiting_hook_does_not_sit_out_the_publisher_backoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Without a nudge the publisher backs off for five seconds after the first
    # failure, longer than the hook is willing to wait.
    publisher, calls = _publisher_with_flaky_resident(tmp_path, monkeypatch, failures=2, poll_interval_seconds=5.0)
    worker = SimpleNamespace(_publish_native_policy=True, policy_snapshot_publisher=publisher, store=publisher.store)
    started = time.monotonic()
    try:
        binding = prepare_workspace_policy(worker, None, deadline=started + 4.0, now=started)
        assert binding is not None
        assert time.monotonic() - started < 4.0
        assert len(calls) == 3
    finally:
        publisher.close()


class _StuckPublisher:
    """A publisher whose resident is down; records how the barrier treats it."""

    def __init__(self, *, streak: int, last_error: str = "native_client_timed_out") -> None:
        self.streak = streak
        self.last_error = last_error
        self.waits: list[float] = []
        self.nudges = 0

    def start(self) -> None:
        return None

    def register_workspace(self, _workspace: object) -> None:
        return None

    def workspace_policy_pending(self, _workspace: object) -> bool:
        return False

    def workspace_admissible_without_overlay(self, _workspace: object) -> bool:
        return False

    def resident_failure_streak(self) -> int:
        return self.streak

    def nudge_retry(self) -> bool:
        self.nudges += 1
        return True

    def wait_until_ready(self, deadline: float, **_kwargs: object) -> bool:
        self.waits.append(deadline)
        time.sleep(0.01)
        return False

    def current_snapshot_binding(self) -> None:
        return None

    def current_snapshot(self) -> None:
        return None


def test_closed_publisher_does_not_spin_during_hook_readiness() -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker_readiness import _wait_nudging_publisher

    class Retired:
        closed = True
        last_error = None
        nudges = 0
        waits = 0

        def nudge_retry(self) -> bool:
            self.nudges += 1
            return False

        def wait_until_ready(self, _deadline: float) -> bool:
            self.waits += 1
            return False

    retired = Retired()
    started = time.monotonic()
    _wait_nudging_publisher(retired, retired.wait_until_ready, started + 30.0, workspace=None, pending=False)
    assert retired.nudges == retired.waits == 0
    assert time.monotonic() - started < 1.0


def test_publisher_retired_while_waiting_stops_without_busy_spin() -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker_readiness import _wait_nudging_publisher

    class Retiring:
        closed = False
        last_error = None
        nudges = 0
        waits = 0

        def nudge_retry(self) -> bool:
            self.nudges += 1
            return False

        def wait_until_ready(self, _deadline: float) -> bool:
            self.waits += 1
            self.closed = True
            return False

    retiring = Retiring()
    started = time.monotonic()
    _wait_nudging_publisher(retiring, retiring.wait_until_ready, started + 30.0, workspace=None, pending=False)
    assert retiring.nudges == retiring.waits == 1
    assert time.monotonic() - started < 1.0


def test_repeated_resident_failures_fail_the_hook_fast(tmp_path: Path) -> None:
    publisher = _StuckPublisher(streak=RESIDENT_FAIL_FAST_STREAK)
    worker = SimpleNamespace(_publish_native_policy=True, policy_snapshot_publisher=publisher, store=None)
    started = time.monotonic()

    assert prepare_workspace_policy(worker, None, deadline=started + 30.0, now=started) is None

    assert publisher.waits == []
    assert publisher.nudges == 1  # one more attempt, so the next hook may find the resident back
    assert time.monotonic() - started < 1.0


def test_first_resident_failures_are_waited_for_within_the_deadline(tmp_path: Path) -> None:
    publisher = _StuckPublisher(streak=1)
    worker = SimpleNamespace(_publish_native_policy=True, policy_snapshot_publisher=publisher, store=None)
    started = time.monotonic()
    deadline = started + 0.6

    assert prepare_workspace_policy(worker, None, deadline=deadline, now=started) is None

    assert len(publisher.waits) >= 1
    assert max(publisher.waits) <= deadline
    assert time.monotonic() >= deadline


def test_wait_gives_up_when_the_failures_repeat_midway(tmp_path: Path) -> None:
    publisher = _StuckPublisher(streak=1)
    original_wait = publisher.wait_until_ready

    def escalating_wait(deadline: float, **kwargs: object) -> bool:
        publisher.streak += RESIDENT_FAIL_FAST_STREAK
        return original_wait(deadline, **kwargs)

    publisher.wait_until_ready = escalating_wait  # type: ignore[method-assign]
    worker = SimpleNamespace(_publish_native_policy=True, policy_snapshot_publisher=publisher, store=None)
    started = time.monotonic()

    assert prepare_workspace_policy(worker, None, deadline=started + 30.0, now=started) is None

    assert len(publisher.waits) == 1
    assert time.monotonic() - started < 2.0


def _daemon_with(publisher: object) -> SimpleNamespace:
    return SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))


def test_not_ready_reason_sends_the_user_to_repair_once_failures_repeat() -> None:
    reason = _native_policy_not_ready_reason(_daemon_with(_StuckPublisher(streak=RESIDENT_FAIL_FAST_STREAK)))

    assert "native_client_timed_out" in reason
    assert "hol-guard repair" in reason
    assert "Retry once more" in reason


def test_not_ready_reason_keeps_plain_retry_advice_for_a_first_failure() -> None:
    reason = _native_policy_not_ready_reason(_daemon_with(_StuckPublisher(streak=1)))

    assert "Retry this action." in reason
    assert "hol-guard repair" not in reason


def test_not_ready_reason_ignores_the_streak_for_other_failures() -> None:
    publisher = _StuckPublisher(streak=RESIDENT_FAIL_FAST_STREAK, last_error="native_policy_snapshot_ack_mismatch")

    assert "hol-guard repair" not in _native_policy_not_ready_reason(_daemon_with(publisher))
