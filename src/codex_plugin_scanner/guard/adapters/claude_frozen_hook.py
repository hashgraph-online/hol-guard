"""Frozen-binary entry point for Claude hooks (a frozen Guard cannot run ``python -c``)."""

from __future__ import annotations

from collections.abc import Sequence

from .claude_hook_config import CLAUDE_GUARD_DAEMON_HOOK_MARKER, CLAUDE_GUARD_SESSION_START_HOOK_MARKER

FROZEN_CLAUDE_HOOK_COMMAND = "__guard-claude-hook"


def run_frozen_claude_hook(argv: Sequence[str]) -> int:
    """Dispatch ``<marker> <args...>`` to the daemon bridge or the SessionStart refresher."""

    if not argv:
        raise SystemExit("claude_frozen_hook expects a hook marker")
    marker, rest = argv[0], list(argv[1:])
    if marker == CLAUDE_GUARD_DAEMON_HOOK_MARKER:
        from .claude_daemon_hook_bridge import _bridge_config_from_argv, main

        config = _bridge_config_from_argv(["claude_daemon_hook_bridge", *rest])
        return main(
            state_path=config["state_path"],
            fallback_daemon_url=config["fallback_daemon_url"],
            fallback_command=config["fallback_command"],
            query=config["query"],
        )
    if marker == CLAUDE_GUARD_SESSION_START_HOOK_MARKER:
        from .claude_code import _run_session_start_from_argv

        return _run_session_start_from_argv(rest)
    raise SystemExit("claude_frozen_hook received an unknown hook marker")
