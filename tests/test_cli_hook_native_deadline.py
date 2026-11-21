"""A one-shot CLI hook must hand the native review a real bounded deadline."""

from __future__ import annotations

import time

import pytest

from codex_plugin_scanner.guard import native_payload_facts
from codex_plugin_scanner.guard.hook_review.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_payload_facts import native_cli_hook_admission
from codex_plugin_scanner.guard.store import GuardStore

_PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"}}


def test_hinted_deadline_bounds_blocked_policy_readiness(tmp_path):
    class BlockedPublisher:
        last_error = None

        def start(self) -> None:
            return None

        def workspace_policy_pending(self, _workspace) -> bool:
            return True

        def wait_until_ready(self, deadline: float, **_kwargs: object) -> bool:
            time.sleep(max(0.0, deadline - time.monotonic()))
            return False

    worker = HookWorker(
        store=GuardStore(tmp_path / "guard-home"),
        wait_for_native_policy=False,
        publish_native_policy=False,
    )
    worker._publish_native_policy = True
    worker.policy_snapshot_publisher = BlockedPublisher()  # type: ignore[assignment]
    started = time.monotonic()
    try:
        event, deadline = native_cli_hook_admission({**_PAYLOAD, "guard_remaining_ms": 1500}, started_at=started)
        assert event == "PreToolUse"
        snapshot = worker._native_policy_snapshot(tmp_path / "workspace", deadline=deadline)
    finally:
        worker.close()
    assert time.monotonic() - started < 1.5
    assert snapshot is None


def test_non_finite_seconds_leave_the_ms_hint_available():
    started = time.monotonic()
    event, deadline = native_cli_hook_admission(
        {**_PAYLOAD, "guard_remaining_seconds": float("nan"), "guard_remaining_ms": 2000},
        started_at=started,
    )
    assert event == "PreToolUse"
    assert deadline - started == pytest.approx(1.75)


def test_cli_hook_without_a_hint_reviews_under_the_explicit_maximum():
    before = time.monotonic()
    event, deadline = native_cli_hook_admission(_PAYLOAD, started_at=before)
    # The edge's own default is 0.75 s; a one-shot CLI hook gets the full budget.
    assert event == "PreToolUse"
    assert deadline - before == pytest.approx(9.75)


@pytest.mark.parametrize(
    ("hints", "expected_seconds"),
    [
        ({"guard_remaining_ms": 300}, 0.3),
        ({"guard_remaining_seconds": 0.50, "guard_remaining_ms": 300}, 0.5),
        ({"guard_remaining_seconds": -1, "guard_remaining_ms": 300}, 0.3),
        ({"guard_remaining_seconds": 9}, 1.0),
        ({}, 1.0),
    ],
)
def test_cold_cli_lookup_deadline_stays_within_the_harness_budget(monkeypatch, hints, expected_seconds):
    started = 100.0
    deadlines = []

    def unavailable(*_args, deadline, **_kwargs):
        deadlines.append(deadline)
        return None

    monkeypatch.setattr(native_payload_facts, "runtime_answer", unavailable)
    result = native_cli_hook_admission({**_PAYLOAD, **hints}, started_at=started)
    assert deadlines == [pytest.approx(started + expected_seconds)]
    assert result == (None, started)
