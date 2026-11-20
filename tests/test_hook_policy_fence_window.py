from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_fence_window as fence


class Clock:
    def __init__(self, oversleep: float = 0.0) -> None:
        self.now = 10.0
        self.oversleep = oversleep
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds + self.oversleep


def test_bridge_follows_the_native_plan_and_reports_completion(monkeypatch, tmp_path: Path) -> None:
    clock = Clock()
    monkeypatch.setattr(fence, "time", clock)
    calls = []

    def request(**kwargs):
        calls.append(kwargs)
        payload = kwargs["request"]
        return {
            "result": {
                "request_id": payload["request_id"],
                "poll": {"sleep_ms": 100, "retry_by_ms": 1500, "attempt_budget_ms": 1750},
            }
        }

    monkeypatch.setattr(fence, "_resident_request", request)
    wait = fence.PolicySourceFenceWait(12.0, guard_home=tmp_path)
    assert wait.attempt_deadline == 12.0
    assert wait.pause() is True
    assert wait.attempt_deadline == 11.75
    assert clock.sleeps == [0.1]
    clock.now = 12.5
    wait.finish()
    assert [call["request"]["action"] for call in calls] == ["enter", "wait", "leave"]
    assert calls[1]["required_feature"] == "hook-policy-fence-window-wait-v1"
    assert calls[1]["request"]["remaining_ms"] == 2000
    assert calls[2]["required_feature"] == "hook-policy-fence-window-write-v1"
    assert calls[2]["timeout_seconds"] == 0.1
    request_ids = {call["request"]["request_id"] for call in calls}
    assert len(request_ids) == 1
    assert calls[2]["request"] == {
        "schema": "guard-hook-policy-fence-window-request.v1",
        "request_id": request_ids.pop(),
        "guard_home": str(tmp_path.resolve()),
        "action": "leave",
        "admitted": True,
        "persist_events": True,
    }


@pytest.mark.parametrize("failure", ["outage", "exhausted", "late_reply", "oversleep", "mismatched_id"])
def test_bridge_never_retries_without_a_live_native_plan(monkeypatch, tmp_path: Path, failure: str) -> None:
    clock = Clock(oversleep=1.0 if failure == "oversleep" else 0.0)
    monkeypatch.setattr(fence, "time", clock)
    calls = []

    def request(**kwargs):
        payload = kwargs["request"]
        calls.append(payload)
        request_id = payload["request_id"]
        if payload["action"] != "wait":
            return {"result": {"request_id": request_id}}
        if failure == "outage":
            return None
        if failure == "late_reply":
            clock.now += 0.5
        poll = {"sleep_ms": 100, "retry_by_ms": 250, "attempt_budget_ms": 500}
        return {
            "result": {
                "request_id": "unrelated" if failure == "mismatched_id" else request_id,
                "poll": None if failure == "exhausted" else poll,
            }
        }

    monkeypatch.setattr(fence, "_resident_request", request)
    wait = fence.PolicySourceFenceWait(12.0, guard_home=tmp_path)
    assert wait.pause() is False
    wait.finish()
    assert [call["action"] for call in calls] == ["enter", "wait", "leave"]
    assert calls[2]["admitted"] is False
    assert clock.sleeps == ([0.1] if failure == "oversleep" else [])
