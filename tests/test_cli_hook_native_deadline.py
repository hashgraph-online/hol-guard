"""A one-shot CLI hook must hand the native review a real bounded deadline."""

from __future__ import annotations

import time

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import RuntimeHookDeadline
from codex_plugin_scanner.guard.store import GuardStore

_PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"}}


def test_hinted_deadline_bounds_blocked_policy_readiness(tmp_path):
    from codex_plugin_scanner.guard.cli.commands_hook_native_authority import _cli_review_deadline

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
        deadline = _cli_review_deadline({**_PAYLOAD, "guard_remaining_ms": 1500})
        snapshot = worker._native_policy_snapshot(tmp_path / "workspace", deadline=deadline)
    finally:
        worker.close()
    assert time.monotonic() - started < 1.5
    assert snapshot is None


def test_hint_parsing_rejects_non_finite_and_negative_seconds_then_uses_ms():
    clock = lambda: 100.0  # noqa: E731
    nan_then_ms = RuntimeHookDeadline.cli_edge_kwargs(
        {"guard_remaining_seconds": float("nan"), "guard_remaining_ms": 2000}, monotonic=clock
    )
    assert nan_then_ms["deadline"] == pytest.approx(101.75)
    negative_then_ms = RuntimeHookDeadline.cli_edge_kwargs(
        {"guard_remaining_seconds": -5, "guard_remaining_ms": 2000}, monotonic=clock
    )
    assert negative_then_ms["deadline"] == pytest.approx(101.75)
    junk = RuntimeHookDeadline.cli_edge_kwargs({"guard_remaining_seconds": float("inf")}, monotonic=clock)
    assert set(junk) == {"edge_budget_seconds"}
    huge = RuntimeHookDeadline.cli_edge_kwargs({"guard_remaining_seconds": 600}, monotonic=clock)
    assert huge["deadline"] - 100.0 <= 10.0


def test_cli_hook_without_a_hint_reviews_under_the_explicit_maximum():
    from codex_plugin_scanner.guard.cli.commands_hook_native_authority import _cli_review_deadline

    before = time.monotonic()
    deadline = _cli_review_deadline({"hook_event_name": "PreToolUse"})
    # The edge's own default is 0.75 s; a one-shot CLI hook gets the full budget.
    assert 0.75 < deadline - before <= 10.0
    hinted = _cli_review_deadline({"hook_event_name": "PreToolUse", "guard_remaining_ms": 2000})
    assert hinted - before < 2.0
