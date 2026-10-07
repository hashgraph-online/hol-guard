"""Static harness protection registry."""

from .contract_models import HarnessProtectionContract

_BASE_HARNESS_CONTRACTS: tuple[HarnessProtectionContract, ...] = (
    HarnessProtectionContract(
        harness="codex",
        install_aliases=("codex",),
        config_paths=("~/.codex/config.toml",),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read", "tool_result"),
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
        event_surfaces=("shell", "mcp_tool", "file_read", "tool_result"),
        native_approval=True,
        browser_fallback=True,
        resume_support=True,
        known_blind_spots=(
            "Guard does not install a Claude Code UserPromptSubmit hook, so native prompt submission is not "
            "intercepted. Background agent sessions without an active terminal may not surface hook events."
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
        harness="cline",
        install_aliases=("cline", "cline-cli", "cline-vscode"),
        config_paths=(
            "~/.cline/hooks/",
            "~/.cline/plugins/",
            "~/.cline/data/settings/cline_mcp_settings.json",
            "~/.cline/settings/cline_mcp_settings.json",
            "~/Documents/Cline/Hooks/",
            "~/Documents/Cline/Plugins/",
        ),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read", "file_write", "tool_result", "network_request"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Native Cline PostToolUse hooks are observation-only and cannot replace a result already returned to "
            "the model; full post-tool output mediation requires the Guard-managed Cline plugin transport. "
            "JetBrains protection is reported as unverified until a live pre-tool deny proof is observed."
        ),
        smoke_command="hol-guard apps test cline --json",
        surface_capabilities=("auto", "hooks", "plugin", "cli", "all"),
        supported_actions=(
            "connect:auto",
            "connect:hooks",
            "connect:plugin",
            "connect:cli",
            "connect:all",
            "test:auto",
            "test:hooks",
            "test:plugin",
            "test:cli",
            "test:all",
            "repair:auto",
            "repair:hooks",
            "repair:plugin",
            "repair:cli",
            "repair:all",
            "disconnect:auto",
            "disconnect:hooks",
            "disconnect:plugin",
            "disconnect:cli",
            "disconnect:all",
        ),
        docs_path="docs/guard/cline-local-protection-contract.md",
        icon_label="Cline",
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
            "Hermes desktop and ACP entry paths may not register shell hooks; "
            "CLI and gateway honor hooks.pre_tool_call."
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
            "Hooks run in parallel, so separate requests may be reviewed concurrently."
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
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read", "file_write"),
        native_approval=False,
        browser_fallback=True,
        resume_support=True,
        known_blind_spots=(
            "Grok can reject user-typed prompts through UserPromptSubmit. Auto-wake and subagent prompt callbacks "
            "are passive; tool enforcement uses the catch-all PreToolUse hook, including subagent and MCP tools. "
            "--always-approve and bypassPermissions weaken Grok's own prompt policy, but the Guard hook still "
            "returns a native deny when policy blocks a tool call."
        ),
        smoke_command="hol-guard install grok --dry-run",
    ),
    HarnessProtectionContract(
        harness="pi",
        install_aliases=("pi", "pi-agent", "pi-coding-agent"),
        config_paths=(
            "~/.pi/agent/settings.json",
            ".pi/settings.json",
            "~/.pi/agent/extensions/*.ts",
            ".pi/extensions/*.ts",
        ),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read", "tool_result"),
        native_approval=True,
        browser_fallback=True,
        resume_support=True,
        known_blind_spots=(
            "Pi package install and update flows happen outside the runtime extension bridge, so Guard observes the "
            "configured package surfaces plus the prompt and tool events forwarded by the managed extension."
        ),
        smoke_command="hol-guard install pi --dry-run",
    ),
    HarnessProtectionContract(
        harness="omp",
        install_aliases=("omp", "oh-my-pi"),
        config_paths=(
            "~/.omp/agent/settings.json",
            ".omp/settings.json",
            "~/.omp/agent/extensions/*.ts",
            ".omp/extensions/*.ts",
        ),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read", "tool_result"),
        native_approval=True,
        browser_fallback=True,
        resume_support=True,
        known_blind_spots=(
            "Oh My Pi package install and update flows happen outside the runtime extension bridge, so Guard "
            "observes the "
            "configured package surfaces plus the prompt and tool events forwarded by the managed extension."
        ),
        smoke_command="hol-guard install omp --dry-run",
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
    HarnessProtectionContract(
        harness="devin",
        install_aliases=("devin", "devin-cli", "cognition-devin"),
        config_paths=(
            "~/.config/devin/config.json",
            "~/.config/devin/mcp_config.json",
            ".devin/hooks.v1.json",
            ".devin/mcp_config.json",
        ),
        event_surfaces=("shell", "prompt", "mcp_tool", "file_read", "file_write", "tool_result"),
        native_approval=False,
        browser_fallback=True,
        resume_support=False,
        known_blind_spots=(
            "Devin loads Claude Code hook files by default, so Guard's Claude Code hooks may also run inside "
            "Devin sessions and attribute them to Claude Code. Inline edits applied without a tool call, "
            "write_to_process input, and background shell output are not visible to Guard. Subagent tool "
            "calls are covered only where Devin fires hooks for them."
        ),
        smoke_command="hol-guard install devin --dry-run",
        docs_path="docs/guard/devin.md",
        icon_label="Devin",
    ),
    HarnessProtectionContract(
        harness="paseo",
        install_aliases=("paseo",),
        config_paths=("~/.paseo/config.json",),
        event_surfaces=(),
        native_approval=False,
        browser_fallback=False,
        resume_support=False,
        known_blind_spots=(
            "Protection is delegated to supported native providers on the Paseo daemon host. "
            "Paseo permission notifications are not blocking hooks. Terminals, daemon git/browser actions, "
            "plugin code, custom commands, ACP providers, relocated native homes, and remote hosts are not covered. "
            "Native runtime failure behavior and approval/resume support remain provider-specific."
        ),
        smoke_command="hol-guard install paseo --dry-run",
        docs_path="docs/guard/paseo.md",
        icon_label="Paseo",
    ),
)
