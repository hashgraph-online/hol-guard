"""Harness protection contracts for HOL Guard.

Each contract captures the static protection capabilities, install aliases,
config file paths, event surfaces, known blind spots, and smoke command for
one AI coding harness that HOL Guard supports.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HarnessProtectionContract:
    """Static protection profile for one AI coding harness.

    Attributes:
        harness: Canonical harness identifier (matches adapter `harness` field).
        install_aliases: All strings accepted by `hol-guard install <alias>`.
        config_paths: Glob-style paths where the harness stores config
            (relative to ``$HOME`` unless absolute).
        event_surfaces: Hook event types the harness exposes
            (e.g. "shell", "prompt", "mcp_tool", "file_read").
        native_approval: True if the harness has a first-class native approval
            prompt that Guard can intercept without a browser fallback.
        browser_fallback: True if Guard falls back to a browser approval page
            when native approval is unavailable.
        resume_support: True if the harness can resume the original command
            after an async approval completes.
        known_blind_spots: Human-readable description of event types or
            surfaces that Guard cannot currently observe for this harness.
        smoke_command: Shell command an operator can run to confirm Guard is
            active for this harness.
    """

    harness: str
    install_aliases: tuple[str, ...]
    config_paths: tuple[str, ...]
    event_surfaces: tuple[str, ...]
    native_approval: bool
    browser_fallback: bool
    resume_support: bool
    known_blind_spots: str
    smoke_command: str


HARNESS_CONTRACTS: tuple[HarnessProtectionContract, ...] = (
    HarnessProtectionContract(
        harness="codex",
        install_aliases=("codex", "codex-cli"),
        config_paths=("~/.codex/config.toml",),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read"),
        native_approval=True,
        browser_fallback=True,
        resume_support=True,
        known_blind_spots=(
            "Inline file edits applied directly by the model without a tool call are not visible to Guard."
        ),
        smoke_command="hol-guard install codex --dry-run",
    ),
    HarnessProtectionContract(
        harness="codex-app",
        install_aliases=("codex-app",),
        config_paths=("~/.codex/config.toml",),
        event_surfaces=("shell", "prompt"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Codex App does not expose MCP tool hooks; all tool calls bypass Guard. "
            "File read/write events are not observable."
        ),
        smoke_command="hol-guard install codex-app --dry-run",
    ),
    HarnessProtectionContract(
        harness="claude-code",
        install_aliases=("claude-code", "claude"),
        config_paths=("~/.claude/settings.json", "~/.claude/settings.local.json"),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read"),
        native_approval=True,
        browser_fallback=True,
        resume_support=True,
        known_blind_spots=(
            "Background agent sessions that run without an active terminal do not surface hook events to Guard."
        ),
        smoke_command="hol-guard install claude --dry-run",
    ),
    HarnessProtectionContract(
        harness="opencode",
        install_aliases=("opencode",),
        config_paths=("~/.config/opencode/config.json",),
        event_surfaces=("shell", "mcp_tool"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Prompt content is not currently surfaced through hooks. File read/write events bypass Guard."
        ),
        smoke_command="hol-guard install opencode --dry-run",
    ),
    HarnessProtectionContract(
        harness="copilot",
        install_aliases=("copilot", "copilot-cli", "gh-copilot"),
        config_paths=("~/.config/gh/hosts.yml",),
        event_surfaces=("shell", "prompt"),
        native_approval=True,
        browser_fallback=True,
        resume_support=True,
        known_blind_spots=(
            "MCP tool calls routed through the VS Code extension are not visible to the CLI-level Guard hook."
        ),
        smoke_command="hol-guard install copilot --dry-run",
    ),
    HarnessProtectionContract(
        harness="copilot-ide",
        install_aliases=("copilot-ide", "vscode-copilot"),
        config_paths=("~/.vscode/extensions/",),
        event_surfaces=("prompt",),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Shell and MCP tool actions executed by the IDE extension are not "
            "observable without a proxy layer. Guard only intercepts prompt-level events."
        ),
        smoke_command="hol-guard install copilot-ide --dry-run",
    ),
    HarnessProtectionContract(
        harness="cursor",
        install_aliases=("cursor",),
        config_paths=("~/.cursor/mcp.json",),
        event_surfaces=("mcp_tool",),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Shell commands issued through Cursor's built-in terminal bypass Guard. Prompt content is not surfaced."
        ),
        smoke_command="hol-guard install cursor --dry-run",
    ),
    HarnessProtectionContract(
        harness="gemini",
        install_aliases=("gemini", "gemini-cli"),
        config_paths=("~/.gemini/settings.json",),
        event_surfaces=("shell", "mcp_tool"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Prompt submission events and file read/write operations are not "
            "currently observable through the Gemini hook surface."
        ),
        smoke_command="hol-guard install gemini --dry-run",
    ),
    HarnessProtectionContract(
        harness="hermes",
        install_aliases=("hermes",),
        config_paths=(),
        event_surfaces=("shell", "mcp_tool", "prompt"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Hermes is an early-access harness; some event surface coverage depends on the Hermes version installed."
        ),
        smoke_command="hol-guard install hermes --dry-run",
    ),
    HarnessProtectionContract(
        harness="openclaw",
        install_aliases=("openclaw",),
        config_paths=("~/.openclaw/config.json",),
        event_surfaces=("mcp_tool",),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Shell commands and prompt events are not currently observable. "
            "Guard only intercepts MCP tool calls via the proxy layer."
        ),
        smoke_command="hol-guard install openclaw --dry-run",
    ),
)

_CONTRACT_BY_ALIAS: dict[str, HarnessProtectionContract] = {}
for _c in HARNESS_CONTRACTS:
    _CONTRACT_BY_ALIAS[_c.harness] = _c
    for _alias in _c.install_aliases:
        _CONTRACT_BY_ALIAS[_alias] = _c


def contract_for(harness: str) -> HarnessProtectionContract | None:
    """Return the contract for a harness name or install alias, or None."""
    return _CONTRACT_BY_ALIAS.get(harness)


def harness_contracts_table() -> str:
    """Return a Markdown table summarising all harness contracts."""
    header = (
        "| Harness | Install Aliases | Native Approval | Browser Fallback "
        "| Resume | Event Surfaces |\n"
        "|---------|-----------------|-----------------|------------------"
        "|--------|----------------|\n"
    )
    rows: list[str] = []
    for c in HARNESS_CONTRACTS:
        aliases = ", ".join(f"`{a}`" for a in c.install_aliases)
        surfaces = ", ".join(c.event_surfaces) if c.event_surfaces else "—"
        rows.append(
            f"| `{c.harness}` | {aliases} | {'✅' if c.native_approval else '❌'} "
            f"| {'✅' if c.browser_fallback else '❌'} "
            f"| {'✅' if c.resume_support else '❌'} | {surfaces} |"
        )
    return header + "\n".join(rows) + "\n"
