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

__all__ = [
    "MUSE_CONFIG_DIR_NAME",
    "MUSE_PLUGIN_DIR",
    "MUSE_PLUGIN_FILE",
    "MUSE_SETTINGS_FILE",
]
