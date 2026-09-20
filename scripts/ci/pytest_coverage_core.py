"""Fail the coverage lane if branch measurement silently uses a different core."""

from __future__ import annotations

import coverage
import pytest


@pytest.hookimpl(trylast=True)
def pytest_sessionstart() -> None:
    """Inspect the actual pytest-cov measurement after its session setup."""

    measurement = coverage.Coverage.current()
    if measurement is None:
        raise pytest.UsageError("CI requires active sys.monitoring branch coverage")
    core = dict(measurement.sys_info())["core"]
    if core != "SysMonitor" or measurement.get_option("run:branch") is not True:
        raise pytest.UsageError(f"CI requires SysMonitor branch coverage; active core is {core}")
    print("Verified active SysMonitor branch coverage")
