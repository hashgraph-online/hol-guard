"""Health-only Cursor hook intercept proof."""

from __future__ import annotations

from .adapters.base import HarnessContext
from .adapters.cursor_hook_config import _json_object, live_guard_cursor_hooks_intercept
from .adapters.cursor_hooks import cursor_hooks_path


def cursor_runtime_hooks_verified(context: HarnessContext) -> bool:
    """Return whether live Cursor hooks still intercept Guard's blocking events."""

    try:
        payload = _json_object(cursor_hooks_path(context), recover_missing=True)
    except RuntimeError:
        return False
    return live_guard_cursor_hooks_intercept(payload.get("hooks"))


__all__ = ["cursor_runtime_hooks_verified"]
