"""Shared native-authority mode predicates."""

from __future__ import annotations

import os

_NATIVE_DIAGNOSTIC_ENV = "HOL_GUARD_NATIVE_DIAGNOSTIC"
_PYTHON_ORACLE_ENV = "HOL_GUARD_PYTHON_ORACLE"
_TEST_MODE_ENV = "HOL_GUARD_TEST_MODE"


def _enabled(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes"}


def non_production_diagnostic_enabled() -> bool:
    """Return whether an operator explicitly enabled non-production diagnostics."""

    return _enabled(os.environ.get(_NATIVE_DIAGNOSTIC_ENV))


def python_oracle_enabled() -> bool:
    """Return whether an explicit test-only Python differential oracle is enabled.

    The second condition prevents an inherited or typoed environment variable
    from selecting the oracle in a normal installed runtime. Test runners set
    ``HOL_GUARD_TEST_MODE``; pytest also supplies ``PYTEST_CURRENT_TEST``.
    """

    return _enabled(os.environ.get(_PYTHON_ORACLE_ENV)) and (
        _enabled(os.environ.get(_TEST_MODE_ENV)) or bool(os.environ.get("PYTEST_CURRENT_TEST"))
    )


def shadow_comparison_enabled(mode: str | None = None) -> bool:
    """Return whether shadow comparison may run on an explicit diagnostic surface."""

    if mode is None:
        from .native_runtime import native_mode

        mode = native_mode()
    return mode == "shadow" and non_production_diagnostic_enabled()


def python_oracle_surface_enabled(mode: str | None = None) -> bool:
    """Return whether the explicit oracle is allowed for the configured mode."""

    if not python_oracle_enabled():
        return False
    if mode is None:
        from .native_runtime import native_mode

        mode = native_mode()
    return mode == "off" or shadow_comparison_enabled(mode)


def native_mode_is_fail_safe_disabled() -> bool:
    """Return whether explicit ``off`` requires fail-safe hook responses."""

    from .native_runtime import native_mode

    return native_mode() == "off"


def native_mode_requires_rust() -> bool:
    """Return whether the configured mode requires native semantic authority."""
    from .native_runtime import native_mode

    return native_mode() in {"auto", "force"}
