"""Helpers for tests that tolerate coverage-tracing overhead in covered CI runs."""

from __future__ import annotations

import os


def under_coverage_scale(scale: float) -> float:
    """Return `scale` when the CI run traces coverage, else 1.0.

    Traced test processes run slow enough that timing-sensitive budgets
    fail without any product regression; covered CI runs scale their
    budgets, untraced runs keep the real values.
    """
    return scale if os.environ.get("GUARD_PYTEST_UNDER_COVERAGE") == "1" else 1.0
