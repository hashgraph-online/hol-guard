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
    surface_capabilities: tuple[str, ...] = ()
    supported_actions: tuple[str, ...] = ()
    docs_path: str | None = None
    icon_label: str | None = None


@dataclass(frozen=True, slots=True)
class HarnessSetupStep:
    """Plain-language action for connecting or checking one harness."""

    step_id: str
    title: str
    body: str
    command: tuple[str, ...] = ()
    writes_config: bool = False
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "body": self.body,
            "command": list(self.command),
            "writes_config": self.writes_config,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass(frozen=True, slots=True)
class HarnessCoverageSummary:
    """Summary of what Guard can and cannot observe for one harness."""

    native_hooks: bool
    browser_fallback: bool
    mcp_proxy: bool
    prompt_hooks: bool
    blind_spots: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "native_hooks": self.native_hooks,
            "browser_fallback": self.browser_fallback,
            "mcp_proxy": self.mcp_proxy,
            "prompt_hooks": self.prompt_hooks,
            "blind_spots": list(self.blind_spots),
        }


@dataclass(frozen=True, slots=True)
class HarnessSetupContract:
    """Dashboard and CLI setup contract for one supported harness."""

    harness: str
    display_name: str
    install_aliases: tuple[str, ...]
    setup_steps: tuple[HarnessSetupStep, ...]
    verify_steps: tuple[HarnessSetupStep, ...]
    repair_steps: tuple[HarnessSetupStep, ...]
    coverage: HarnessCoverageSummary
    surface_capabilities: tuple[str, ...] = ()
    supported_actions: tuple[str, ...] = ()
    docs_path: str | None = None
    icon_label: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "harness": self.harness,
            "display_name": self.display_name,
            "install_aliases": list(self.install_aliases),
            "setup_steps": [step.to_dict() for step in self.setup_steps],
            "verify_steps": [step.to_dict() for step in self.verify_steps],
            "repair_steps": [step.to_dict() for step in self.repair_steps],
            "coverage": self.coverage.to_dict(),
        }
        if self.surface_capabilities:
            payload["surface_capabilities"] = list(self.surface_capabilities)
        if self.supported_actions:
            payload["supported_actions"] = list(self.supported_actions)
        if self.docs_path is not None:
            payload["docs_path"] = self.docs_path
        if self.icon_label is not None:
            payload["icon_label"] = self.icon_label
        return payload


_DISPLAY_NAMES = {
    "codex": "Codex",
    "claude-code": "Claude Code",
    "opencode": "OpenCode",
    "copilot": "Copilot",
    "cursor": "Cursor",
    "gemini": "Gemini",
    "hermes": "Hermes",
    "openclaw": "OpenClaw",
    "antigravity": "Antigravity",
    "kimi": "Kimi",
    "grok": "Grok",
    "pi": "Pi",
    "zcode": "ZCode",
}


HARNESS_CONTRACTS: tuple[HarnessProtectionContract, ...] = (
    HarnessProtectionContract(
        harness="codex",
        install_aliases=("codex",),
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
            "Prompt content is not currently surfaced through hooks. File read/write events bypass Guard "
            "unless OpenCode permission rules block them."
        ),
        smoke_command="hol-guard install opencode --dry-run",
    ),
    HarnessProtectionContract(
        harness="copilot",
        install_aliases=("copilot",),
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
        harness="cursor",
        install_aliases=("cursor",),
        config_paths=("~/.cursor/mcp.json", "~/.cursor/hooks.json", ".cursor/hooks.json"),
        event_surfaces=("shell", "mcp_tool", "file_read"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Shell commands issued through Cursor's built-in terminal bypass Guard unless the terminal runs inside "
            "an agent session. Prompt submission is not surfaced through native Cursor hooks."
        ),
        smoke_command="hol-guard install cursor --dry-run",
        surface_capabilities=("editor", "cli"),
        supported_actions=(
            "connect:editor",
            "connect:cli",
            "test:editor",
            "test:cli",
            "repair:editor",
            "repair:cli",
            "disconnect:editor",
            "disconnect:cli",
        ),
        docs_path="docs/guard/cursor-local-cloud-contract.md",
        icon_label="Cursor",
    ),
    HarnessProtectionContract(
        harness="gemini",
        install_aliases=("gemini",),
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
    HarnessProtectionContract(
        harness="antigravity",
        install_aliases=("antigravity",),
        config_paths=(
            "~/.config/antigravity/user/settings.json",
            "~/.gemini/antigravity/mcp_config.json",
            "~/.antigravity/extensions/extensions.json",
        ),
        event_surfaces=("mcp_tool", "prompt"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Shell commands are not currently observable through the Antigravity hook surface. "
            "Guard intercepts extensions and MCP registrations via scan at launch time."
        ),
        smoke_command="hol-guard install antigravity --dry-run",
    ),
    HarnessProtectionContract(
        harness="kimi",
        install_aliases=("kimi", "kimi-code", "kimi-cli"),
        config_paths=("~/.kimi-code/config.toml",),
        event_surfaces=("shell", "prompt"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Tool output post-processing and inline edits applied without a tool call are not visible to Guard. "
            "Hooks run in parallel and fail open on crash or timeout."
        ),
        smoke_command="hol-guard install kimi --dry-run",
    ),
    HarnessProtectionContract(
        harness="grok",
        install_aliases=("grok", "grok-build", "grok-build-cli", "xai-grok"),
        config_paths=(
            "~/.grok/config.toml",
            "~/.grok/managed_config.toml",
            "~/.grok/hooks/",
        ),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Grok hooks fail open on crash or timeout. --always-approve and bypassPermissions weaken "
            "prompt policy but PreToolUse hooks still run when installed."
        ),
        smoke_command="hol-guard install grok --dry-run",
    ),
    HarnessProtectionContract(
        harness="pi",
        install_aliases=("pi", "omp", "pi-agent", "pi-coding-agent"),
        config_paths=(
            "~/.pi/agent/settings.json",
            ".pi/settings.json",
            "~/.pi/agent/extensions/*.ts",
            ".pi/extensions/*.ts",
        ),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read"),
        native_approval=True,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Pi package install and update flows happen outside the runtime extension bridge, so Guard observes the "
            "configured package surfaces plus the prompt and tool events forwarded by the managed extension."
        ),
        smoke_command="hol-guard install pi --dry-run",
    ),
    HarnessProtectionContract(
        harness="zcode",
        install_aliases=("zcode", "zai", "z-code", "zai-zcode"),
        config_paths=(
            "~/.zcode/cli/config.json",
            "~/.zcode/cli/plugins/",
        ),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Inline edits applied directly by the model without a tool call are not visible to Guard, "
            "and background sessions that run without an active terminal do not surface hook events."
        ),
        smoke_command="hol-guard install zcode --dry-run",
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


def setup_contract_for(harness: str) -> HarnessSetupContract | None:
    """Return guided setup metadata for a harness name or install alias."""

    contract = contract_for(harness)
    if contract is None:
        return None
    alias = contract.install_aliases[0] if contract.install_aliases else contract.harness
    display_name = _DISPLAY_NAMES.get(contract.harness, contract.harness)
    coverage = HarnessCoverageSummary(
        native_hooks=contract.native_approval,
        browser_fallback=contract.browser_fallback,
        mcp_proxy="mcp_tool" in contract.event_surfaces,
        prompt_hooks="prompt" in contract.event_surfaces,
        blind_spots=(contract.known_blind_spots,),
    )
    setup_steps = (
        HarnessSetupStep(
            step_id="connect",
            title=f"Connect {display_name}",
            body=f"Add Guard's local protection hooks for {display_name}.",
            command=("hol-guard", "apps", "connect", alias),
            writes_config=True,
        ),
        HarnessSetupStep(
            step_id="review-coverage",
            title="Review what Guard can see",
            body="Check covered events and known blind spots before relying on this app.",
        ),
    )
    verify_steps = (
        HarnessSetupStep(
            step_id="safe-test",
            title="Run a safe protection test",
            body="Confirm Guard can detect the app without reading secrets or changing app config.",
            command=("hol-guard", "apps", "test", alias),
        ),
    )
    repair_steps = (
        HarnessSetupStep(
            step_id="repair",
            title=f"Repair {display_name} protection",
            body="Re-apply Guard managed config if hooks were removed or changed.",
            command=("hol-guard", "apps", "repair", alias),
            writes_config=True,
        ),
    )
    return HarnessSetupContract(
        harness=contract.harness,
        display_name=display_name,
        install_aliases=contract.install_aliases,
        setup_steps=setup_steps,
        verify_steps=verify_steps,
        repair_steps=repair_steps,
        coverage=coverage,
        surface_capabilities=contract.surface_capabilities,
        supported_actions=contract.supported_actions,
        docs_path=contract.docs_path,
        icon_label=contract.icon_label,
    )


def all_setup_contracts() -> tuple[HarnessSetupContract, ...]:
    """Return guided setup metadata for all supported harnesses."""

    return tuple(
        setup_contract
        for contract in HARNESS_CONTRACTS
        if (setup_contract := setup_contract_for(contract.harness)) is not None
    )


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
