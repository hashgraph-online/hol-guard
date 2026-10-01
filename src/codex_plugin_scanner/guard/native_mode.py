"""Shared native-authority mode predicates."""

from __future__ import annotations

import os

_NATIVE_DIAGNOSTIC_ENV = "HOL_GUARD_NATIVE_DIAGNOSTIC"


def _enabled(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes"}


def non_production_diagnostic_enabled() -> bool:
    """Return whether an operator explicitly enabled non-production diagnostics."""

    return _enabled(os.environ.get(_NATIVE_DIAGNOSTIC_ENV))


def native_mode_is_fail_safe_disabled() -> bool:
    """Return whether explicit ``off`` requires fail-safe hook responses."""

    from .native_runtime import native_mode

    return native_mode() == "off"


def native_mode_requires_rust() -> bool:
    """Return whether the configured mode requires native semantic authority."""
    from .native_runtime import native_mode

    return native_mode() in {"auto", "force"}
