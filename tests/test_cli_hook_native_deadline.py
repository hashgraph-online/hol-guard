"""A one-shot CLI hook must hand the native edge a real bounded deadline."""

from __future__ import annotations

import time

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import RuntimeHookDeadline
from codex_plugin_scanner.guard.store import GuardStore

_PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"}}


def _review(worker: HookWorker, tmp_path, **timing: float) -> dict[str, object]:
    return worker.review_native_edge_decision(
        payload=dict(_PAYLOAD),
        harness="codex",
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        **timing,
    )


def _worker(tmp_path, monkeypatch, seen: dict[str, object]) -> HookWorker:
    worker = HookWorker(
        store=GuardStore(tmp_path / "guard-home"),
        wait_for_native_policy=False,
        publish_native_policy=False,
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_a, **_k: {"generation": 1})

    def capture(**kwargs: object) -> None:
        seen["deadline"] = kwargs.get("deadline")
        seen["at"] = time.monotonic()

    monkeypatch.setattr(worker, "_review_raw_hook_native", capture)
    return worker


def test_unhinted_budget_reaches_native_edge_and_unavailable_stays_fail_closed(tmp_path, monkeypatch):
    seen: dict[str, object] = {}
    worker = _worker(tmp_path, monkeypatch, seen)
    try:
        timing = RuntimeHookDeadline.cli_edge_kwargs(dict(_PAYLOAD))
        assert set(timing) == {"edge_budget_seconds"}
        edge = _review(worker, tmp_path, **timing)
    finally:
        worker.close()
    deadline = seen["deadline"]
    assert isinstance(deadline, float)
    assert 0.75 < deadline - float(seen["at"]) <= 10.0
    assert edge["result"] is None
    assert edge["failure_reason_code"] == "native_pre_tool_unavailable"


def test_hinted_deadline_bounds_blocked_policy_readiness_and_fails_closed(tmp_path, monkeypatch):
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
    monkeypatch.setattr(worker, "_review_raw_hook_native", lambda **_k: None)
    payload = {**_PAYLOAD, "guard_remaining_ms": 1500}
    started = time.monotonic()
    try:
        timing = RuntimeHookDeadline.cli_edge_kwargs(payload)
        assert set(timing) == {"deadline"}
        edge = _review(worker, tmp_path, **timing)
    finally:
        worker.close()
    assert time.monotonic() - started < 1.5
    assert edge["result"] is None
    assert edge["failure_reason_code"] in {"native_pre_tool_unavailable", "native_review_deadline_exceeded"}


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
