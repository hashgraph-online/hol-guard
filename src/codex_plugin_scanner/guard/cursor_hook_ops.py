"""Cursor's hook ops the Guard process runs outside an install.

The native ``harness_adapter`` kind owns Cursor's hooks, their health and the
rebind decision. This module asks it, publishes the hooks-only plan under the
install transaction, and runs the installed hook script from a frozen Guard
binary once the runtime accepts its path.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .harness_context import HarnessContext
from .native_harness_client import ask

_HARNESS = "cursor"


def _cursor_ask(
    op: str, context: HarnessContext, *, timeout_seconds: float | None = None, **fields: Any
) -> dict[str, Any]:
    """Run one op; the native runtime probes the Cursor CLI itself."""
    return ask(op, context, harness=_HARNESS, timeout_seconds=timeout_seconds, **fields)


def _manifest(answer: dict[str, Any]) -> dict[str, object]:
    return json.loads(str(answer["manifest"]))


def install_cursor_hooks(context: HarnessContext, *, actor: str = "cursor-hooks") -> dict[str, object]:
    """Install only Cursor's native hooks and the script they run.

    The native runtime holds the installation transaction, publishes the plan, then requires the hooks Cursor
    now reads to be Guard's.
    """
    from .cli.native_managed_install import ask_managed

    return _manifest(ask_managed("cursor_hooks_install", context, [], actor=actor))


def rebind_stale_cursor_hooks(guard_home: Path, *, home_dir: Path) -> dict[str, object]:
    """Rewrite managed Cursor hooks that still bake a pruneable Core path or an outdated script."""
    from .runtime_transition import TransitionError

    context = HarnessContext(home_dir=home_dir, guard_home=guard_home, workspace_dir=None)
    answer = _cursor_ask("rebind", context)
    if answer.get("install") is not True:
        return answer
    try:
        install_cursor_hooks(context, actor="cursor-hook-rebind")
    except (OSError, RuntimeError, ValueError, TransitionError) as error:
        return {"rebound": False, "reason": "cursor_hook_script_rebind_failed", "error": str(error)}
    return {"rebound": True, "reason": "cursor_hook_script_rebound"}


def cursor_native_hook_state(context: HarnessContext) -> dict[str, object]:
    """Cursor's registration, scripts and the attested CLI identity they name."""
    return json.loads(str(_cursor_ask("hook_state", context)["state"]))


def cursor_runtime_hooks_verified(context: HarnessContext) -> bool | None:
    """Whether live Cursor hooks still intercept Guard's blocking events."""
    verified = _cursor_ask("health", context)["verified"]
    return verified if isinstance(verified, bool) else None


def run_frozen_cursor_hook(argv: Sequence[str]) -> int:
    """Execute the installed Cursor hook script from a frozen Guard binary."""
    import runpy

    if not argv:
        return 2
    home = Path.home()
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    # A runtime that cannot answer refuses the script the way a bad path does.
    # Gated events are ``failClosed``, so Cursor still blocks them.
    try:
        accepted = ask("frozen_hook_script", context, harness=_HARNESS, script=str(argv[0])).get("accepted")
    except (OSError, RuntimeError, ValueError):
        return 3
    if accepted is not True:
        return 3
    try:
        runpy.run_path(str(argv[0]), run_name="__main__")
    except SystemExit as error:
        code = error.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 1
    return 0


__all__ = [
    "cursor_native_hook_state",
    "cursor_runtime_hooks_verified",
    "install_cursor_hooks",
    "rebind_stale_cursor_hooks",
    "run_frozen_cursor_hook",
]
