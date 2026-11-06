"""Fail-closed execution policy for package operations."""

from __future__ import annotations

_EXECUTION_PERMITTED_ACTIONS = frozenset({"allow", "warn"})


def is_execution_permitted(action: object) -> bool:
    """Return whether an explicit package policy action permits execution.

    ``monitor`` is a telemetry disposition, not an enforcement action. Unknown,
    malformed, and future action values therefore fail closed.
    """

    return isinstance(action, str) and action in _EXECUTION_PERMITTED_ACTIONS


__all__ = ["is_execution_permitted"]
