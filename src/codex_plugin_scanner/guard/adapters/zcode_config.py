"""z.ai ZCode config, hook JSON, and detection helpers for HOL Guard.

ZCode stores its CLI app config under ``~/.zcode/``. ``~/.zcode/cli/config.json``
is Claude-Code-shaped: an ``mcp`` section (``mcp.servers.<name>``), a ``plugins``
section (``plugins.enabledPlugins.<name@marketplace>``), and an optional
``hooks`` section. Current ZCode nests hook event groups under
``hooks.events.<Event>`` (with optional ``enabled``/``timeoutMs``/
``maxOutputBytes`` settings keys) and rejects the legacy flat
``hooks.<Event>`` layout with a config load failure; both layouts are read for
inventory (by the native runtime) while only the nested one is written. Plugins are cached
under ``~/.zcode/cli/plugins/cache/<marketplace>/<plugin>/<version>/`` with a
``.zcode-plugin/plugin.json`` manifest, a ``.zcode-plugin-seed.json`` provenance
file, ``hooks/hooks.json``, ``.mcp.json``, ``skills/`` and ``commands/`` trees.
"""

from __future__ import annotations

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
