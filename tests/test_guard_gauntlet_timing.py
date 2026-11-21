"""Phase accounting is observable without being an acceptance shortcut."""

import pytest

from ci.gauntlet.timing import PhaseTimings


def test_phases_accumulate_retry_time_and_retain_failure_time() -> None:
    ticks = iter([1.0, 3.0, 4.0, 9.0, 10.0, 11.0])
    timer = PhaseTimings(lambda: next(ticks))
    with timer.measure("live_cases"):
        pass
    with pytest.raises(RuntimeError), timer.measure("live_cases"):
        raise RuntimeError("failed attempt")
    with timer.measure("cleanup"):
        pass
    assert timer.report() == {"live_cases": 7.0, "cleanup": 1.0}
