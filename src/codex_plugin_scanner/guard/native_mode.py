"""Shared native-authority mode predicates."""

from __future__ import annotations


def native_mode_requires_rust() -> bool:
    """Return whether the configured mode requires native semantic authority."""
    from .native_runtime import native_mode

    return native_mode() in {"auto", "force"}
