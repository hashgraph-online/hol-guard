"""A failed command-queue poll retries quickly while an agent waits on a decision."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime import command_queue_loop, review_wait_activity


class _RecordingStop:
    def __init__(self, polls: int) -> None:
        self.polls = polls
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return len(self.waits) >= self.polls

    def wait(self, seconds: float) -> bool:
        self.waits.append(seconds)
        return self.is_set()


def _failing_poll(_store: object, _context: object) -> dict[str, object]:
    raise OSError("network is unreachable")


def _run_failing_loop(polls: int) -> list[float]:
    stop = _RecordingStop(polls)
    state: dict[str, object] = {}
    command_queue_loop.run_command_queue_loop(
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        stop_event=stop,
        enabled=lambda _store: True,
        poll_once=_failing_poll,
        load_state=lambda _store: dict(state),
        save_state=lambda _store, value: state.update(value),
        format_error=str,
        now=lambda: "2026-01-01T00:00:00Z",
    )
    return stop.waits


@pytest.fixture(autouse=True)
def _reset_wait_activity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(review_wait_activity, "_last_wait_at", None)
    monkeypatch.delenv(command_queue_loop.COMMAND_QUEUE_POLL_INTERVAL_ENV, raising=False)
    monkeypatch.delenv(command_queue_loop.COMMAND_QUEUE_ERROR_BACKOFF_ENV, raising=False)


def test_failed_polls_back_off_to_thirty_seconds_when_no_agent_is_waiting() -> None:
    waits = _run_failing_loop(6)

    assert waits[-1] == 30.0


def test_failed_polls_retry_every_two_seconds_while_an_agent_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(command_queue_loop, "review_wait_recent", lambda: True)

    waits = _run_failing_loop(6)

    assert waits == [2.0] * 6


def test_review_wait_activity_expires_after_the_recent_window() -> None:
    clock = [100.0]

    assert not review_wait_activity.review_wait_recent(monotonic=lambda: clock[0])
    review_wait_activity.note_review_wait(monotonic=lambda: clock[0])
    clock[0] += review_wait_activity.RECENT_REVIEW_WAIT_SECONDS
    assert review_wait_activity.review_wait_recent(monotonic=lambda: clock[0])
    clock[0] += 0.5
    assert not review_wait_activity.review_wait_recent(monotonic=lambda: clock[0])
