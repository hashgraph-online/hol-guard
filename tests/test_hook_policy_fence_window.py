"""A policy update's business-source fence is waited out, never run through."""

from __future__ import annotations

import functools
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters import zcode
from codex_plugin_scanner.guard.daemon import hook_policy_fence_window as fence
from codex_plugin_scanner.guard.daemon import hook_worker_native_review as review
from codex_plugin_scanner.guard.daemon import runtime_hook_deadline
from codex_plugin_scanner.guard.daemon.hook_policy_admission import _native_policy_not_ready_reason
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore

FENCE_CODE = "native_business_source_mutation_in_progress"
STABLE_MESSAGE = "Guard is finishing a policy update; this action was not run. Retry after 8 seconds."


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class _Events:
    def __init__(self) -> None:
        self.recorded: list[tuple[str, dict[str, object]]] = []

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        del now
        self.recorded.append((event_name, payload))


@pytest.fixture
def worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HookWorker:
    result = HookWorker(store=GuardStore(tmp_path / "guard"), start_native_policy=False)
    monkeypatch.setattr(result, "_native_policy_snapshot", Mock(return_value={"generation": 2, "mode": "enforce"}))
    return result


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _FakeClock:
    fake = _FakeClock()
    window = fence.PolicySourceFenceWindow()
    monkeypatch.setattr(
        review,
        "PolicySourceFenceWait",
        functools.partial(fence.PolicySourceFenceWait, window=window, monotonic=fake.monotonic, sleep=fake.sleep),
    )
    return fake


def _call(worker: HookWorker, tmp_path: Path, deadline: float | None, *, harness: str = "grok"):
    return worker._review_native_edge(
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}},
        harness=harness,
        event_name="PreToolUse",
        default_harness=harness,
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=deadline,
        policy_snapshot={"generation": 1, "mode": "enforce"},
    )


def test_fence_that_clears_within_budget_admits_the_same_request(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: _FakeClock
) -> None:
    busy = fence.PolicySourceFenceBusyError(FENCE_CODE)
    native = Mock(side_effect=[busy, busy, ({"policy_action": "allow", "decision": "allow"}, True)])
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    deadline = clock.now + 4.0
    response = _call(worker, tmp_path, deadline)
    assert response["policy_action"] == "allow"
    assert native.call_count == 3
    assert clock.slept == [fence.POLL_SECONDS, fence.POLL_SECONDS]
    # A poll after a wait stops one margin short of the hook deadline.
    assert [call.kwargs["deadline"] for call in native.call_args_list] == [
        deadline,
        deadline - fence.DEADLINE_MARGIN_SECONDS,
        deadline - fence.DEADLINE_MARGIN_SECONDS,
    ]


def test_spent_wait_fails_closed_with_the_stable_message(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: _FakeClock
) -> None:
    native = Mock(side_effect=fence.PolicySourceFenceBusyError(FENCE_CODE))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    deadline = clock.now + 30.0
    response = _call(worker, tmp_path, deadline)
    assert response["decision"] == "deny"
    assert response["policy_action"] != "allow"
    assert response["native_failure_code"] == FENCE_CODE
    assert STABLE_MESSAGE in str(response)
    assert "test" not in STABLE_MESSAGE.lower() and "containment" not in STABLE_MESSAGE.lower()
    # The rebuild bound, not the long deadline, ends the wait.
    assert clock.now - 1_000.0 <= fence.REBUILD_WAIT_SECONDS
    assert native.call_count == len(clock.slept) + 1


def test_missing_deadline_never_waits(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: _FakeClock
) -> None:
    native = Mock(side_effect=fence.PolicySourceFenceBusyError(FENCE_CODE))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    assert _call(worker, tmp_path, None)["decision"] == "deny"
    native.assert_called_once()
    assert clock.slept == []


def test_zcode_wait_stays_inside_its_hook_budget(
    worker: HookWorker, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: _FakeClock
) -> None:
    # ZCode fails open on hook timeout. The daemon deadline it hands a hook is
    # well inside the ZCode timeout, and the wait stops short of that deadline.
    assert runtime_hook_deadline._MAX_EXPLICIT_BUDGET_SECONDS < zcode._GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS
    assert zcode._GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS < zcode._ZCODE_PRETOOL_TIMEOUT_SECONDS
    assert fence.REBUILD_WAIT_SECONDS < zcode._GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS
    native = Mock(side_effect=fence.PolicySourceFenceBusyError(FENCE_CODE))
    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", native)
    deadline = clock.now + runtime_hook_deadline._DEFAULT_BUDGET_SECONDS
    response = _call(worker, tmp_path, deadline, harness="zcode")
    assert response["native_failure_code"] == FENCE_CODE
    assert STABLE_MESSAGE in str(response)
    last_poll = deadline - fence.DEADLINE_MARGIN_SECONDS - fence.ATTEMPT_MARGIN_SECONDS
    assert clock.now <= last_poll
    assert clock.now > last_poll - 2 * fence.POLL_SECONDS


def test_wait_is_the_shorter_of_rebuild_bound_and_budget() -> None:
    assert fence.fence_wait_until(10.0, None) == 10.0
    assert fence.fence_wait_until(10.0, 12.0) == 12.0 - fence.DEADLINE_MARGIN_SECONDS - fence.ATTEMPT_MARGIN_SECONDS
    assert fence.fence_wait_until(10.0, 40.0) == 10.0 + fence.REBUILD_WAIT_SECONDS


def test_sleep_that_runs_late_ends_the_wait_instead_of_polling_again() -> None:
    clock = _FakeClock()
    deadline = clock.now + 2.0

    def late_sleep(seconds: float) -> None:
        clock.sleep(seconds + 5.0)

    wait = fence.PolicySourceFenceWait(
        deadline, store=None, window=fence.PolicySourceFenceWindow(), monotonic=clock.monotonic, sleep=late_sleep
    )
    assert wait.pause() is False
    assert wait.attempt_deadline == deadline - fence.DEADLINE_MARGIN_SECONDS


def test_first_attempt_keeps_the_hook_deadline() -> None:
    clock = _FakeClock()
    deadline = clock.now + 4.0
    wait = fence.PolicySourceFenceWait(
        deadline, store=None, window=fence.PolicySourceFenceWindow(), monotonic=clock.monotonic, sleep=clock.sleep
    )
    assert wait.attempt_deadline == deadline
    assert (
        fence.PolicySourceFenceWait(None, store=None, window=fence.PolicySourceFenceWindow()).attempt_deadline is None
    )


def test_store_failure_is_logged_and_never_reaches_the_hook(caplog: pytest.LogCaptureFixture) -> None:
    class _Broken:
        def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
            raise OSError("database is locked")

    window = fence.PolicySourceFenceWindow()
    window.enter()
    with caplog.at_level(logging.WARNING, logger=fence.__name__):
        window.leave(_Broken(), admitted=True)
    assert "fence window event was not recorded" in caplog.text
    assert any(record.exc_info for record in caplog.records)


def test_direct_wait_joins_an_open_window() -> None:
    events = _Events()
    window = fence.PolicySourceFenceWindow()
    window.enter()
    window.absorb_direct(events, 0.3)
    assert events.recorded == []
    window.leave(events, admitted=False)
    assert len(events.recorded) == 1
    payload = events.recorded[0][1]
    assert payload["absorbed_calls"] == 1
    assert payload["exhausted_calls"] == 1


def test_direct_wait_with_no_open_window_records_its_own() -> None:
    events = _Events()
    window = fence.PolicySourceFenceWindow()
    fence.record_direct_fence_wait(events, 450, window=window)
    assert len(events.recorded) == 1
    name, payload = events.recorded[0]
    assert name == "policy_source_fence_window"
    assert payload["absorbed_calls"] == 1
    assert payload["exhausted_calls"] == 0
    started = datetime.fromisoformat(str(payload["started_at"]))
    ended = datetime.fromisoformat(str(payload["ended_at"]))
    assert ended - started == timedelta(milliseconds=450)


@pytest.mark.parametrize("waited", [None, 0, -5, True, "300", 1.5])
def test_direct_wait_report_must_be_a_positive_integer(waited: object) -> None:
    events = _Events()
    fence.record_direct_fence_wait(events, waited, window=fence.PolicySourceFenceWindow())
    assert events.recorded == []


def test_one_window_event_counts_every_absorbed_call() -> None:
    events = _Events()
    window = fence.PolicySourceFenceWindow()
    clock = _FakeClock()
    waits = [
        fence.PolicySourceFenceWait(
            clock.now + 4.0, store=events, window=window, monotonic=clock.monotonic, sleep=clock.sleep
        )
        for _ in range(3)
    ]
    for wait in waits:
        assert wait.pause()
    waits[0].finish()
    waits[1].finish()
    assert events.recorded == []
    while waits[2].pause():
        pass
    waits[2].finish()
    waits[2].finish()
    assert len(events.recorded) == 1
    name, payload = events.recorded[0]
    assert name == "policy_source_fence_window"
    assert payload["absorbed_calls"] == 2
    assert payload["exhausted_calls"] == 1
    assert payload["started_at"] <= payload["ended_at"]


def test_hook_that_never_met_the_fence_records_no_window() -> None:
    events = _Events()
    wait = fence.PolicySourceFenceWait(time.monotonic() + 4.0, store=events, window=fence.PolicySourceFenceWindow())
    wait.finish()
    assert events.recorded == []


def test_admission_not_ready_during_fence_names_the_policy_update() -> None:
    daemon = SimpleNamespace(
        hook_worker=SimpleNamespace(policy_snapshot_publisher=SimpleNamespace(last_error=FENCE_CODE))
    )
    assert _native_policy_not_ready_reason(daemon) == STABLE_MESSAGE


def test_busy_error_is_limited_to_the_fence_code() -> None:
    with pytest.raises(ValueError):
        fence.PolicySourceFenceBusyError("native_policy_snapshot_not_current")
