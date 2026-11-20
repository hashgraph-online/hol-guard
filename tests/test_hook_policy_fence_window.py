from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard import native_policy_fence_window
from codex_plugin_scanner.guard.hook_review import hook_policy_fence_window as fence


class Clock:
    def __init__(self) -> None:
        self.now = 10.0
        self.actions: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.actions.append(seconds)
        self.now += seconds


def test_wait_delegates_window_state_to_the_resident(monkeypatch, tmp_path: Path) -> None:
    clock = Clock()
    calls: list[dict[str, object]] = []

    def record(home: Path, **kwargs: object) -> None:
        calls.append({"home": home, **kwargs})

    monkeypatch.setattr(fence, "record_policy_fence_window", record)
    wait = fence.PolicySourceFenceWait(
        clock.monotonic() + 2.0,
        guard_home=tmp_path,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    assert wait.pause() is True
    wait.finish()
    assert [call["action"] for call in calls] == ["enter", "leave"]
    assert calls[0]["deadline"] == 12.0
    assert calls[1]["deadline"] == 12.0
    assert all(call["home"] == tmp_path for call in calls)


def test_bridge_requests_resident_persistence(monkeypatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(native_policy_fence_window, "_resident_request", lambda **kwargs: calls.append(kwargs))
    native_policy_fence_window.record_policy_fence_window(
        tmp_path, action="leave", admitted=False, request_id="fence-sample", deadline=0
    )
    assert len(calls) == 1
    assert calls[0]["required_feature"] == "hook-policy-fence-window-write-v1"
    assert calls[0]["request"] == {
        "schema": "guard-hook-policy-fence-window-request.v1",
        "request_id": "fence-sample",
        "guard_home": str(tmp_path.resolve()),
        "action": "leave",
        "admitted": False,
        "persist_events": True,
    }


def test_wait_exhaustion_is_reported_as_not_admitted(monkeypatch, tmp_path: Path) -> None:
    clock = Clock()
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(fence, "record_policy_fence_window", lambda _home, **kwargs: calls.append(kwargs) or {})
    wait = fence.PolicySourceFenceWait(
        clock.monotonic(),
        guard_home=tmp_path,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    assert wait.pause() is False
    wait.finish()
    assert [call["action"] for call in calls] == ["enter", "leave"]
    assert calls[0]["deadline"] == 10.0
    assert calls[1]["deadline"] == 10.0
    assert calls[1]["admitted"] is False
    assert calls[0]["request_id"] == calls[1]["request_id"]


def test_policy_update_reason_is_stable() -> None:
    assert fence.policy_update_pending_reason(0.1).endswith("Retry after 1 seconds.")


def test_attempt_lease_reaches_the_native_bridge(tmp_path: Path, monkeypatch) -> None:
    clock = Clock()
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(fence, "record_policy_fence_window", lambda _home, **kwargs: calls.append(kwargs) or {})
    wait = fence.PolicySourceFenceWait(
        clock.monotonic() + 2.0,
        guard_home=tmp_path,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    assert wait.pause() is True
    assert wait.attempt_deadline is not None
    assert [call["action"] for call in calls] == ["enter", "attempt"]
    assert isinstance(calls[1]["attempt_until_micros"], int)


def test_wait_deadline_and_attempt_margins_remain_bounded(tmp_path: Path, monkeypatch) -> None:
    assert fence.fence_wait_until(10.0, None) == 10.0
    assert fence.fence_wait_until(10.0, 20.0) == 18.0
    monkeypatch.setattr(fence, "record_policy_fence_window", lambda *_args, **_kwargs: {})
    wait = fence.PolicySourceFenceWait(None, guard_home=tmp_path)
    assert wait.pause() is False
    assert wait.attempt_deadline is None


def test_late_poll_sleep_exhausts_without_an_extra_attempt(tmp_path: Path, monkeypatch) -> None:
    clock = Clock()

    def late_sleep(seconds: float) -> None:
        clock.now += seconds + 1.0

    monkeypatch.setattr(fence, "record_policy_fence_window", lambda *_args, **_kwargs: {})
    wait = fence.PolicySourceFenceWait(
        clock.monotonic() + 0.2,
        guard_home=tmp_path,
        monotonic=clock.monotonic,
        sleep=late_sleep,
    )
    assert wait.pause() is False
