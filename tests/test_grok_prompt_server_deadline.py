from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.hook_deadline import RuntimeHookDeadline


class _SettledDirectories:
    """Stand in for the directories the runtime settles for one request.

    The handler asks for every candidate at once and reads each verdict back
    by name. Nothing here is a verdict: this test is about the deadline the
    route carries, so each candidate settles as the string it arrived as.
    """

    def __init__(self, candidates):
        self._paths = {candidate[0]: candidate[1] for candidate in candidates}

    def require(self, parameter):
        return self._paths.get(parameter)


def test_shorter_caller_budget_is_preserved() -> None:
    deadline = RuntimeHookDeadline.from_remaining_hint(2, monotonic=lambda: 100.0, maximum_budget_seconds=10)
    assert deadline.expires_at == 101.75
    assert deadline.remaining(monotonic=lambda: 102.0) == 0


@pytest.mark.parametrize("maximum", [True, -1, 11, float("inf"), float("nan")])
def test_explicit_maximum_cannot_remove_the_hard_cap(maximum) -> None:
    with pytest.raises(ValueError):
        RuntimeHookDeadline.from_remaining_hint(999, maximum_budget_seconds=maximum)
