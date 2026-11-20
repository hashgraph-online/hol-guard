from __future__ import annotations

from pathlib import Path

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


class Store:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.events: list[tuple[str, dict[str, object], str]] = []

    def add_event(self, name: str, payload: dict[str, object], now: str) -> None:
        self.events.append((name, payload, now))


def test_wait_delegates_window_state_to_the_resident(monkeypatch, tmp_path: Path) -> None:
    clock = Clock()
    store = Store(tmp_path)
    calls: list[dict[str, object]] = []

    def record(home: Path, **kwargs: object) -> dict[str, object] | None:
        calls.append({"home": home, **kwargs})
        if kwargs["action"] == "leave":
            return {
                "event_name": "policy_source_fence_window",
                "payload": {
                    "started_at": "2026-01-01T00:00:00+00:00",
                    "ended_at": "2026-01-01T00:00:01+00:00",
                    "absorbed_calls": 1,
                    "exhausted_calls": 0,
                },
                "occurred_at": "2026-01-01T00:00:01+00:00",
            }
        return {}

    monkeypatch.setattr(fence, "record_policy_fence_window", record)
    wait = fence.PolicySourceFenceWait(
        clock.monotonic() + 2.0,
        store=store,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )
    assert wait.pause() is True
    wait.finish()
    assert [call["action"] for call in calls] == ["enter", "leave"]
    assert calls[0]["deadline"] == 12.0
    assert calls[1]["deadline"] == 12.0
    assert store.events[0][0] == "policy_source_fence_window"


def test_wait_exhaustion_is_reported_as_not_admitted(monkeypatch, tmp_path: Path) -> None:
    clock = Clock()
    store = Store(tmp_path)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(fence, "record_policy_fence_window", lambda _home, **kwargs: calls.append(kwargs) or {})
    wait = fence.PolicySourceFenceWait(
        clock.monotonic(),
        store=store,
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
        store=Store(tmp_path),
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
    wait = fence.PolicySourceFenceWait(None, store=Store(tmp_path))
    assert wait.pause() is False
    assert wait.attempt_deadline is None


def test_late_poll_sleep_exhausts_without_an_extra_attempt(tmp_path: Path, monkeypatch) -> None:
    clock = Clock()
    store = Store(tmp_path)

    def late_sleep(seconds: float) -> None:
        clock.now += seconds + 1.0

    monkeypatch.setattr(fence, "record_policy_fence_window", lambda *_args, **_kwargs: {})
    wait = fence.PolicySourceFenceWait(
        clock.monotonic() + 0.2,
        store=store,
        monotonic=clock.monotonic,
        sleep=late_sleep,
    )
    assert wait.pause() is False
