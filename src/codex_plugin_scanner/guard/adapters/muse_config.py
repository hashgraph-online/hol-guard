"""Muse config and hook JSON helpers for HOL Guard.

Muse's user config lives under ``$XDG_CONFIG_HOME/muse`` (or
``~/.config/muse``) in ``settings.json``. Its ``hooks`` key is
Claude-Code-shaped: ``{"<Event>": [{"matcher": <regex>, "hooks":
[{"type": "command", "command": ..., "timeout": 30}]}]}``, and its
``mcpServers`` key holds stdio (``command`` argv) and streamable-HTTP
(``url``) MCP entries. Muse also loads hooks from installed plugins
(``.muse-plugin/plugin.json`` capabilities); Guard manages the user
settings hooks directly, like Devin and ZCode, so no plugin trust step is
required. Settings are strict JSON: Guard refuses to rewrite a file that
does not parse as a JSON object rather than rewriting it lossily.
"""

from __future__ import annotations

MUSE_CONFIG_DIR_NAME = "muse"
MUSE_SETTINGS_FILE = "settings.json"
MUSE_PLUGIN_DIR = ".muse-plugin"
MUSE_PLUGIN_FILE = "plugin.json"

GUARD_MANAGED_MARKER = "HOL_GUARD_MANAGED_MUSE"

# Muse surfaces every tool through hooks, including shell, file, search,
# web, MCP (``mcp__*``) and Guard's own ``muse.*`` work tools. Guard omits
# a matcher on its groups, which Muse reads as "every tool"; naming a
# subset would silently exempt the unlisted tools from review.
MUSE_GUARD_EVENTS: tuple[str, ...] = (
    "PreToolUse",
    "PermissionRequest",
    "UserPromptSubmit",
    "PostToolUse",
    "SessionStart",
    "Stop",
)


def is_guard_managed_hook_command(command: object) -> bool:
    """Return True when a hook command string is owned by HOL Guard for Muse."""

    if not isinstance(command, str):
        return False
    # Windows cmdline quoting escapes inner quotes as \"; normalize so the
    # harness marker in the bounded-bridge config matches on every platform.
    normalized = command.replace('\\"', '"')
    return (
        GUARD_MANAGED_MARKER in command
        or ("codex_plugin_scanner.cli" in command and "'guard', 'hook'" in command and "--harness', 'muse'" in command)
        or ("bounded_cli_hook_bridge" in command and '"harness":"muse"' in normalized)
        or ("__guard-bounded-hook" in command and '"harness":"muse"' in normalized)
        or ("managed/bounded-hooks/muse.py" in normalized.replace("\\", "/"))
    )


__all__ = [
    "GUARD_MANAGED_MARKER",
    "MUSE_CONFIG_DIR_NAME",
    "MUSE_GUARD_EVENTS",
    "MUSE_PLUGIN_DIR",
    "MUSE_PLUGIN_FILE",
    "MUSE_SETTINGS_FILE",
    "is_guard_managed_hook_command",
]
