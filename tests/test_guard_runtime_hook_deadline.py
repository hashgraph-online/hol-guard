import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import RuntimeHookDeadline
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_deadline_clamps_hint_and_ignores_wall_clock() -> None:
    clock = FakeClock()

    deadline = RuntimeHookDeadline.from_remaining_hint(99.0, monotonic=clock)
    clock.value += 1.0

    assert deadline.expires_at == 103.75
    assert deadline.remaining(monotonic=clock) == 2.75
    assert deadline.remaining_for_work(monotonic=clock) == 2.7


@pytest.mark.parametrize(
    ("hint", "expected"),
    [
        (-1.0, 0.1),
        (0.2, 0.1),
        (float("nan"), 3.75),
        ("private", 3.75),
    ],
)
def test_deadline_hint_boundaries(hint: object, expected: float) -> None:
    clock = FakeClock()

    deadline = RuntimeHookDeadline.from_remaining_hint(hint, monotonic=clock)

    assert deadline.expires_at - clock.value == pytest.approx(expected)


def test_predictive_dispatch_rejects_when_secure_review_cannot_fit() -> None:
    clock = FakeClock()
    scheduler = RuntimeHookScheduler(monotonic=clock)
    deadline = RuntimeHookDeadline(expires_at=clock.value + 0.8)

    admission = scheduler.acquire(
        harness="pi",
        client_key="stable-fingerprint",
        lane="decision",
        payload_bytes=2,
        normalized_payload=b"{}",
        deadline=deadline,
    )

    assert admission.permit is None
    assert admission.reason_code == "daemon_hook_deadline_exhausted"
    assert scheduler.stats()["retained_bytes"] == 0


def test_scheduler_health_dimensions_are_bounded() -> None:
    scheduler = RuntimeHookScheduler(monotonic=FakeClock())
    admission = scheduler.acquire(
        harness="/private/workspace/customer",
        client_key="high-cardinality-session",
        lane="decision",
        payload_bytes=2,
        normalized_payload=b"{}",
        deadline=200.0,
    )
    assert admission.permit is not None
    scheduler.record_retry()

    stats = scheduler.stats()

    assert stats["per_harness_active"] == {"other": 1}
    assert stats["retries"] == 1
    assert set(stats["queue_wait_by_lane_p99_ms"]) == {"decision", "content-security", "evidence"}
    admission.permit.release()
