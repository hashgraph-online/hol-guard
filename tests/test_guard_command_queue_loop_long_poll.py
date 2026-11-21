from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import command_queue_loop as command_queue_loop_module
from codex_plugin_scanner.guard.runtime.command_queue_activation import COMMAND_QUEUE_LEASE_WAIT_MS_ENV


def _run_empty_polls(monkeypatch: pytest.MonkeyPatch, *, poll_seconds: float, waits_to_record: int) -> list[float]:
    """Run the loop over empty polls that each take `poll_seconds`, returning its waits."""

    clock = [0.0]
    waits: list[float] = []

    class StopAfterWaits:
        def is_set(self) -> bool:
            return False

        def wait(self, seconds: float) -> bool:
            waits.append(seconds)
            clock[0] += seconds
            return len(waits) >= waits_to_record

    def empty_poll(_store: object, _context: object) -> dict[str, object]:
        clock[0] += poll_seconds
        return {"last_poll_was_empty": True}

    monkeypatch.setenv(COMMAND_QUEUE_LEASE_WAIT_MS_ENV, "25000")
    monkeypatch.setenv(command_queue_loop_module.COMMAND_QUEUE_POLL_INTERVAL_ENV, "2")
    monkeypatch.setattr(command_queue_loop_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    command_queue_loop_module.run_command_queue_loop(
        object(),
        object(),
        stop_event=StopAfterWaits(),
        enabled=lambda _store: True,
        poll_once=empty_poll,
        load_state=lambda _store: {},
        save_state=lambda _store, _state: None,
        format_error=str,
        now=lambda: "now",
    )
    return waits


def test_held_empty_long_polls_lease_again_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty lease Cloud held open is followed by the next lease at once.

    Backing off after held leases left an idle device without an open lease
    for up to the poll interval, so a decision made in that gap waited for the
    next poll before it reached the device.
    """

    assert _run_empty_polls(monkeypatch, poll_seconds=25.0, waits_to_record=8) == [0.05] * 8


def test_quick_empty_long_polls_still_back_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty answers that come back at once, as when Cloud is not holding leases, still back off."""

    assert _run_empty_polls(monkeypatch, poll_seconds=0.01, waits_to_record=8) == [
        0.05,
        0.1,
        0.2,
        0.4,
        0.8,
        1.6,
        2.0,
        2.0,
    ]
