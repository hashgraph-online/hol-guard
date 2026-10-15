"""z.ai ZCode config, hook JSON, and detection helpers for HOL Guard.

ZCode stores its CLI app config under ``~/.zcode/``. ``~/.zcode/cli/config.json``
is Claude-Code-shaped: an ``mcp`` section (``mcp.servers.<name>``), a ``plugins``
section (``plugins.enabledPlugins.<name@marketplace>``), and an optional
``hooks`` section. Current ZCode nests hook event groups under
``hooks.events.<Event>`` (with optional ``enabled``/``timeoutMs``/
``maxOutputBytes`` settings keys) and rejects the legacy flat
``hooks.<Event>`` layout with a config load failure; both layouts are read for
inventory while only the nested one is written. Plugins are cached
under ``~/.zcode/cli/plugins/cache/<marketplace>/<plugin>/<version>/`` with a
``.zcode-plugin/plugin.json`` manifest, a ``.zcode-plugin-seed.json`` provenance
file, ``hooks/hooks.json``, ``.mcp.json``, ``skills/`` and ``commands/`` trees.
"""

from __future__ import annotations

import json

ZCODE_DIR = ".zcode"
ZCODE_CLI_DIR = ".zcode/cli"
ZCODE_CLI_CONFIG_FILE = "config.json"
# Desktop app runtime state (provider config, app settings) written by current ZCode.
ZCODE_V2_DIR = ".zcode/v2"
ZCODE_V2_CONFIG_FILE = "config.json"
ZCODE_PLUGIN_CACHE_DIR = "plugins/cache"
ZCODE_PLUGIN_MARKETPLACES_DIR = "plugins/marketplaces"

GUARD_MANAGED_MARKER = "HOL_GUARD_MANAGED_ZCODE"

# Current ZCode nests hook event groups under ``hooks.events`` with optional
# global settings (``enabled``, ``timeoutMs``, ``maxOutputBytes``) beside it.
# Older ZCode builds placed the event arrays directly under ``hooks``; current
# builds reject those legacy keys and fail to load the whole config file, so
# Guard must only ever write the nested shape while still reading both.
ZCODE_HOOKS_EVENTS_KEY = "events"
ZCODE_HOOK_EVENT_NAMES = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
)


# Claude Code tool matchers ZCode surfaces. MCP tools arrive as mcp__<server>__<tool>;
# the mcp__.* matcher must be present so the PreToolUse hook fires for MCP calls too,
# otherwise an MCP server's tools could be invoked without Guard interception.
ZCODE_PRETOOL_MATCHERS = (
    "Bash",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "Grep",
    "WebFetch",
    "WebSearch",
    "mcp__.*",
    "run_terminal_command",
    "run_command",
    "read_file",
    "write_file",
    "search_replace",
    "multi_edit",
    "grep",
    "web_fetch",
    "web_search",
)

# z.ai/ZCode process identity and runtime env hints (never secret-bearing).
ZCODE_BUNDLE_IDENTIFIER = "dev.zcode.app"
ZCODE_ENV_HINTS = (
    "ZCODE_BASE_URL",
    "ZCODE_APP_VERSION",
    "ZCODE_ENV",
    "ZCODE_RUNTIME_ENV",
    "ZCODE_PROCESS_LABEL",
    "ZCODE_RG_BINARY",
    "ZAI_OAUTH_ORIGIN",
    "ZAI_OAUTH_CLIENT_ID",
)


def is_guard_managed_hook_command(command: object) -> bool:
    """Return True when a hook command string is owned by HOL Guard for ZCode."""

    if not isinstance(command, str):
        return False
    return GUARD_MANAGED_MARKER in command or (
        "codex_plugin_scanner.cli" in command and "'guard', 'hook'" in command and "--harness', 'zcode'" in command
    )


def _entry_key(entry: object) -> str:
    try:
        return json.dumps(entry, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(entry)


def dedupe_hook_entries(entries: list[object]) -> list[object]:
    """Drop equal duplicate group entries so a handler listed in both schema
    layouts is not inventoried or persisted twice (ZCode would run it twice)."""

    seen: set[str] = set()
    unique: list[object] = []
    for entry in entries:
        key = _entry_key(entry)
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def hook_event_groups(hooks_section: object) -> dict[str, list[object]]:
    """Collect ``{event_name: entries}`` from both hooks schema generations.

    Current ZCode stores event groups under ``hooks.events``; older builds put
    them directly under ``hooks``. Both are read so inventories keep working
    for configs written by either generation. Entries that already exist in the
    nested layout are not duplicated from the legacy one.
    """

    if not isinstance(hooks_section, dict):
        return {}
    groups: dict[str, list[object]] = {}
    events = hooks_section.get(ZCODE_HOOKS_EVENTS_KEY)
    if isinstance(events, dict):
        for event_name, entries in events.items():
            if isinstance(event_name, str) and isinstance(entries, list):
                groups.setdefault(event_name, []).extend(entries)
    for event_name, entries in hooks_section.items():
        if event_name == ZCODE_HOOKS_EVENTS_KEY or event_name not in ZCODE_HOOK_EVENT_NAMES:
            continue
        if isinstance(entries, list):
            groups.setdefault(event_name, []).extend(entries)
    return {event_name: dedupe_hook_entries(entries) for event_name, entries in groups.items()}
