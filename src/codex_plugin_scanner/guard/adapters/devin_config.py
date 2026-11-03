"""Devin CLI config and hook JSON helpers for HOL Guard.

Devin's user config lives under ``~/.config/devin/config.json`` (or
``%APPDATA%\\devin\\config.json`` on Windows) and holds a ``hooks`` key whose
event groups are Claude-Code-shaped: ``{"<Event>": [{"matcher": <regex>,
"hooks": [{"type": "command", "command": ..., "timeout": 30}]}]}``.
Config files are JSONC (comments and trailing commas are allowed); Guard only
ever writes strict JSON and refuses to rewrite a JSONC file it cannot
preserve byte-for-byte. The native ``devin_detect`` kind inventories hooks,
MCP servers and skills with the JSONC rules, and ``harness_settings_file``
applies them to install and uninstall.
"""

from __future__ import annotations

DEVIN_DIR = ".devin"
DEVIN_CONFIG_FILE = "config.json"


__all__ = [
    "DEVIN_CONFIG_FILE",
    "DEVIN_DIR",
]
