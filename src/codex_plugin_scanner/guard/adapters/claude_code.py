"""Claude Code through the native ``harness_adapter`` kind.

The kind owns Claude's paths, detection, the hook entries in
``~/.claude/settings.json`` (the SessionStart refresh, every runtime group the
contract names and the prune that removes them), the hook argv in its native,
frozen and source-checkout forms, the settings rewrite after an upgrade, the
diagnostics that notice the entries gone and the SessionStart path vector.
The ``facts`` reply and the SessionStart entry point live in
``guard/claude_hook_entry.py``.
"""

from __future__ import annotations

from ..claude_hook_entry import CLAUDE_GUARD_DAEMON_HOOK_MARKER, CLAUDE_GUARD_SESSION_START_HOOK_MARKER
from .base import HarnessContext, _owned_adapter_mutation, _shell_command
from .native_harness import NativeHarnessAdapter

_HARNESS = "claude-code"


def _argv(which: str, context: HarnessContext) -> tuple[str, ...]:
    return tuple(str(part) for part in ClaudeCodeHarnessAdapter()._ask("argv", context, which=which)["argv"])


class ClaudeCodeHarnessAdapter(NativeHarnessAdapter):
    """Claude Code's settings, hooks and workspace agents."""

    harness = _HARNESS
    executable = "claude"
    legacy_launcher_names = ("claude-code",)

    def __init__(self) -> None:
        super().__init__(_HARNESS, ("claude",), "claude")
        self.executable = "claude"

    @staticmethod
    def _hook_command(context: HarnessContext) -> str:
        return _shell_command(ClaudeCodeHarnessAdapter._hook_command_parts(context))

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _argv("hook", context)

    @staticmethod
    def _daemon_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _argv("daemon", context)

    @staticmethod
    def _session_start_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _argv("session_start", context)

    @_owned_adapter_mutation
    def refresh_runtime_hook_urls(self, context: HarnessContext) -> None:
        # The native SessionStart lane hands off to this refresh whenever its
        # recorded runtime build differs from the installed one, which is true
        # after every package upgrade. The runtime rewrites the entries, which
        # moves the next session back onto the native lane.
        self._ask("refresh", context)


__all__ = [
    "CLAUDE_GUARD_DAEMON_HOOK_MARKER",
    "CLAUDE_GUARD_SESSION_START_HOOK_MARKER",
    "ClaudeCodeHarnessAdapter",
]
