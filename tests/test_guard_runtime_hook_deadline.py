import pytest

from codex_plugin_scanner.guard.hook_deadline import RuntimeHookDeadline


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
