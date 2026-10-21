"""Shared native-authority mode predicates."""

from __future__ import annotations

import os

_NATIVE_DIAGNOSTIC_ENV = "HOL_GUARD_NATIVE_DIAGNOSTIC"


def _enabled(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes"}


def non_production_diagnostic_enabled() -> bool:
    """Return whether an operator explicitly enabled non-production diagnostics."""

    return _enabled(os.environ.get(_NATIVE_DIAGNOSTIC_ENV))
