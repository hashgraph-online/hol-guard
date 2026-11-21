"""A failed command-queue poll retries quickly while an agent waits on a decision."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import command_queue_loop, review_wait_activity


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class _ClockStop:
    """Stops after a number of polls; each wait advances the fake clock."""

    def __init__(self, clock: _Clock, polls: int) -> None:
        self.clock = clock
        self.polls = polls
        self.poll_times: list[float] = []

    def is_set(self) -> bool:
        return len(self.poll_times) >= self.polls

    def wait(self, seconds: float) -> bool:
        self.clock.now += seconds
        return False


def _run_failing_loop(
    monkeypatch: pytest.MonkeyPatch,
    polls: int,
    *,
    waiting: Callable[[float], bool],
) -> list[float]:
    clock = _Clock()
    stop = _ClockStop(clock, polls)
    monkeypatch.setattr(command_queue_loop, "time", SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(command_queue_loop, "review_wait_recent", lambda: waiting(clock.now))

    def failing_poll(_store: object, _context: object) -> dict[str, object]:
        stop.poll_times.append(clock.now)
        raise OSError("network is unreachable")

    state: dict[str, object] = {}
    command_queue_loop.run_command_queue_loop(
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        stop_event=stop,
        enabled=lambda _store: True,
        poll_once=failing_poll,
        load_state=lambda _store: dict(state),
        save_state=lambda _store, value: state.update(value),
        format_error=str,
        now=lambda: "2026-01-01T00:00:00Z",
    )
    return stop.poll_times


def _gaps(times: list[float]) -> list[float]:
    return [round(later - earlier, 3) for earlier, later in itertools.pairwise(times)]


@pytest.fixture(autouse=True)
def _reset_wait_activity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(review_wait_activity, "_last_wait_at", None)
    monkeypatch.delenv(command_queue_loop.COMMAND_QUEUE_POLL_INTERVAL_ENV, raising=False)
    monkeypatch.delenv(command_queue_loop.COMMAND_QUEUE_ERROR_BACKOFF_ENV, raising=False)


def test_failed_polls_back_off_to_thirty_seconds_when_no_agent_is_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    times = _run_failing_loop(monkeypatch, 7, waiting=lambda _now: False)

    assert _gaps(times) == [2.0, 4.0, 8.0, 16.0, 30.0, 30.0]


def test_failed_polls_retry_every_two_seconds_while_an_agent_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    times = _run_failing_loop(monkeypatch, 7, waiting=lambda _now: True)

    assert _gaps(times) == [2.0] * 6


def test_an_agent_that_starts_waiting_mid_backoff_ends_it_early(monkeypatch: pytest.MonkeyPatch) -> None:
    # Five failures put the worker into its 30 s backoff; the agent starts
    # waiting 5 s into it.
    started_waiting = 1_000.0 + 2.0 + 4.0 + 8.0 + 16.0 + 5.0

    times = _run_failing_loop(monkeypatch, 6, waiting=lambda now: now >= started_waiting)

    assert times[-1] - started_waiting <= 2.0


def test_review_wait_activity_expires_after_the_recent_window() -> None:
    clock = [100.0]

    assert not review_wait_activity.review_wait_recent(monotonic=lambda: clock[0])
    review_wait_activity.note_review_wait(monotonic=lambda: clock[0])
    clock[0] += review_wait_activity.RECENT_REVIEW_WAIT_SECONDS
    assert review_wait_activity.review_wait_recent(monotonic=lambda: clock[0])
    clock[0] += 0.5
    assert not review_wait_activity.review_wait_recent(monotonic=lambda: clock[0])
