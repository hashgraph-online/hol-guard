"""Health-only Cursor hook intercept proof."""

from __future__ import annotations

from .adapters.base import HarnessContext
from .adapters.cursor_hook_config import _json_object, live_guard_cursor_hooks_intercept
from .adapters.cursor_hooks import cursor_hooks_path


def cursor_runtime_hooks_verified(context: HarnessContext) -> bool | None:
    """Return whether live Cursor hooks still intercept Guard's blocking events."""

    hooks_path = cursor_hooks_path(context)
    if not hooks_path.is_file():
        return None
    try:
        payload = _json_object(hooks_path, recover_missing=False)
    except RuntimeError:
        return None
    return live_guard_cursor_hooks_intercept(payload.get("hooks"))


__all__ = ["cursor_runtime_hooks_verified"]
