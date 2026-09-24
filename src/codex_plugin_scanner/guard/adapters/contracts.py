"""Harness protection contracts for HOL Guard.

Each contract captures the static protection capabilities, install aliases,
config file paths, event surfaces, known blind spots, and smoke command for
one AI coding harness that HOL Guard supports.
"""

from __future__ import annotations

from dataclasses import replace

from .contract_models import CAPABILITY_DECLARED_ACTIONS as CAPABILITY_DECLARED_ACTIONS
from .contract_models import CapabilityLocalHosted as CapabilityLocalHosted
from .contract_models import HarnessCapabilityReport as HarnessCapabilityReport
from .contract_models import HarnessCoverageSummary as HarnessCoverageSummary
from .contract_models import HarnessEventCapability as HarnessEventCapability
from .contract_models import HarnessProtectionContract as HarnessProtectionContract
from .contract_models import HarnessSetupContract as HarnessSetupContract
from .contract_models import HarnessSetupStep as HarnessSetupStep
from .contract_rendering import DISPLAY_NAMES as _DISPLAY_NAMES
from .contract_rendering import render_harness_contracts

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
            "Grok UserPromptSubmit hooks are observe-only, so prompt screening cannot block the model from "
            "seeing a prompt. Enforcement is the catch-all PreToolUse hook, including subagent and MCP tools. "
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


def _capability(
    harness: str,
    event: str,
    transport: str,
    mode: str,
    declared_actions: tuple[str, ...],
    error_behavior: str,
    mandatory_compatibility: str,
    known_blind_spots: tuple[str, ...],
    source_reference: str,
    *,
    host_version_scope: str = "unknown",
    os_arch: str = "unknown",
    local_hosted: CapabilityLocalHosted = "local",
) -> HarnessEventCapability:
    """Create a source declaration row with conservative proof defaults."""

    return HarnessEventCapability(
        harness=harness,
        adapter=harness,
        host_version_scope=host_version_scope,
        os_arch=os_arch,
        local_hosted=local_hosted,  # type: ignore[arg-type]
        event=event,
        transport=transport,
        mode=mode,
        declared_actions=declared_actions,
        error_behavior=error_behavior,
        mandatory_compatibility=mandatory_compatibility,
        known_blind_spots=known_blind_spots,
        source_reference=source_reference,
    )


_CAPABILITY_EVENTS_BY_HARNESS: dict[str, tuple[HarnessEventCapability, ...]] = {
    "codex": (
        _capability(
            "codex",
            "PreToolUse",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            "Malformed payload, transport failure, or unavailable Guard authority fails closed before tool execution.",
            "Codex must invoke the Guard-managed native hook and honor its response before executing the tool.",
            ("A source declaration does not prove that a live Codex process honored a deny response.",),
            "src/codex_plugin_scanner/guard/adapters/codex.py:_managed_hook_groups",
        ),
        _capability(
            "codex",
            "PermissionRequest",
            "native_hook",
            "approval",
            ("observe", "block", "approval"),
            "Approval transport or decision failures fail closed and leave the request pending or denied.",
            "The Codex permission event must remain attached to the managed Guard hook command.",
            ("Native approval UX and Guard evidence still require a live host/version check.",),
            "src/codex_plugin_scanner/guard/adapters/codex.py:_permission_request_hook_group",
        ),
        _capability(
            "codex",
            "UserPromptSubmit",
            "native_hook",
            "screening",
            ("observe", "block", "approval"),
            "Prompt hook failures return a bounded fail-closed response where Codex honors the hook contract.",
            "Codex must expose UserPromptSubmit and preserve the Guard hook response schema.",
            ("Prompt screening does not prove downstream model or host request rewriting.",),
            "src/codex_plugin_scanner/guard/adapters/codex.py:_prompt_hook_group",
        ),
        _capability(
            "codex",
            "PostToolUse",
            "native_hook",
            "observe",
            ("observe",),
            (
                "Post-tool transport failures are surfaced as unavailable review; a completed host action "
                "cannot be undone."
            ),
            "Codex must invoke the managed PostToolUse hook after the tool event.",
            ("Native post-tool observation does not prove model-visible output replacement.",),
            "src/codex_plugin_scanner/guard/adapters/codex.py:_post_tool_hook_group",
        ),
    ),
    "claude-code": (
        _capability(
            "claude-code",
            "PreToolUse",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            (
                "Malformed input, hook transport failure, or unavailable Guard authority fails closed before "
                "tool execution."
            ),
            "Claude Code must invoke the managed PreToolUse hook and honor its deny/defer response.",
            ("Background sessions without an active terminal may not surface hook events.",),
            "src/codex_plugin_scanner/guard/adapters/claude_hook_config.py:_sync_runtime_hook_groups",
        ),
        _capability(
            "claude-code",
            "PermissionRequest",
            "native_hook",
            "approval",
            ("observe", "block", "approval"),
            "Approval hook failures remain fail closed or pending until Guard can return an authenticated decision.",
            "Claude Code must preserve the managed PermissionRequest hook group in its settings.",
            ("Native approval behavior remains host/version dependent until a live proof is captured.",),
            "src/codex_plugin_scanner/guard/adapters/claude_hook_config.py:_sync_runtime_hook_groups",
        ),
        _capability(
            "claude-code",
            "PostToolUse",
            "native_hook",
            "observe",
            ("observe",),
            (
                "Post-tool failures are recorded as unavailable review and cannot retract a result already "
                "delivered by the host."
            ),
            "Claude Code must invoke the managed PostToolUse hook after the tool event.",
            ("Native PostToolUse is not a general model-visible result replacement boundary.",),
            "src/codex_plugin_scanner/guard/adapters/claude_hook_config.py:_sync_runtime_hook_groups",
        ),
        _capability(
            "claude-code",
            "UserPromptSubmit",
            "none",
            "unsupported",
            ("unavailable",),
            "No Guard UserPromptSubmit hook is installed; prompt submission is outside this declared boundary.",
            "Do not infer prompt interception unless a future Claude Code contract adds and verifies this hook.",
            (
                "Guard does not install a Claude Code UserPromptSubmit hook, so native prompt submission is not "
                + "intercepted.",
            ),
            "src/codex_plugin_scanner/guard/adapters/contracts.py:claude-code.known_blind_spots",
        ),
    ),
    "cursor": (
        _capability(
            "cursor",
            "beforeShellExecution",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            "Blocking hook or Guard transport failure fails closed before Cursor starts the shell command.",
            "Cursor must load the managed beforeShellExecution hook and honor failClosed behavior.",
            ("Cursor terminal actions outside an agent hook path remain outside this boundary.",),
            "src/codex_plugin_scanner/guard/adapters/cursor_hook_config.py:_BLOCKING_MANAGED_HOOK_EVENTS",
        ),
        _capability(
            "cursor",
            "beforeMCPExecution",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            "Blocking hook or Guard transport failure fails closed before Cursor forwards the MCP request.",
            "Cursor must load the managed beforeMCPExecution hook and honor failClosed behavior.",
            ("Only MCP traffic entering Cursor's declared hook surface is covered.",),
            "src/codex_plugin_scanner/guard/adapters/cursor_hook_config.py:_BLOCKING_MANAGED_HOOK_EVENTS",
        ),
        _capability(
            "cursor",
            "beforeReadFile",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            "Blocking hook or Guard transport failure fails closed before Cursor reads the file.",
            "Cursor must load the managed beforeReadFile hook and honor failClosed behavior.",
            ("Reads outside the Cursor hook path are not covered.",),
            "src/codex_plugin_scanner/guard/adapters/cursor_hook_config.py:_BLOCKING_MANAGED_HOOK_EVENTS",
        ),
        _capability(
            "cursor",
            "beforeWriteFile",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            "Blocking hook or Guard transport failure fails closed before Cursor writes the file.",
            "Cursor must load the managed beforeWriteFile hook and honor failClosed behavior.",
            ("Inline edits that bypass the declared Cursor hook are not covered.",),
            "src/codex_plugin_scanner/guard/adapters/cursor_hook_config.py:_BLOCKING_MANAGED_HOOK_EVENTS",
        ),
        _capability(
            "cursor",
            "afterShellExecution",
            "native_hook",
            "observe",
            ("observe",),
            "Observer failure is recorded without claiming that a completed shell action can be reversed.",
            "Cursor must load the managed afterShellExecution observer when post-action evidence is requested.",
            ("Observation does not block or undo the completed shell command.",),
            "src/codex_plugin_scanner/guard/adapters/cursor_hook_config.py:_OBSERVER_MANAGED_HOOK_EVENTS",
        ),
        _capability(
            "cursor",
            "afterMCPExecution",
            "native_hook",
            "observe",
            ("observe",),
            "Observer failure is recorded without claiming that a completed MCP action can be reversed.",
            "Cursor must load the managed afterMCPExecution observer when post-action evidence is requested.",
            ("Observation does not block or replace a result already returned by Cursor.",),
            "src/codex_plugin_scanner/guard/adapters/cursor_hook_config.py:_OBSERVER_MANAGED_HOOK_EVENTS",
        ),
        _capability(
            "cursor",
            "UserPromptSubmit",
            "none",
            "unsupported",
            ("unavailable",),
            "Cursor has no declared native prompt submission hook in this contract.",
            "Do not claim prompt interception unless Cursor exposes a separately verified hook boundary.",
            ("Prompt submission is not surfaced through the declared Cursor hooks.",),
            "src/codex_plugin_scanner/guard/adapters/contracts.py:cursor.known_blind_spots",
        ),
    ),
    "cline": (
        _capability(
            "cline",
            "PreToolUse",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            (
                "Malformed payload, bridge failure, or unavailable Guard authority denies state-changing tools; "
                "designated emergency-safe inspection actions may continue in degraded mode."
            ),
            "Cline must invoke the managed native PreToolUse hook and honor its response.",
            (
                "Emergency-safe inspection actions can continue during Guard authority failure.",
                "JetBrains protection remains unverified until a live pre-tool deny proof is observed.",
            ),
            "src/codex_plugin_scanner/guard/adapters/cline_hooks.py:install_cline_hooks",
        ),
        _capability(
            "cline",
            "PreToolUse",
            "agent_plugin",
            "blocking",
            ("observe", "block", "approval"),
            "Plugin bridge failure returns a bounded blocked result before the tool call continues.",
            "Cline must load the Guard AgentPlugin and call beforeTool for each tool invocation.",
            ("Plugin load and live pre-tool suppression still require an installed-host proof.",),
            "src/codex_plugin_scanner/guard/adapters/cline_plugin.py:plugin.hooks.beforeTool",
        ),
        _capability(
            "cline",
            "PostToolUse",
            "native_hook",
            "observe",
            ("observe",),
            (
                "Native PostToolUse failures are recorded; the native hook cannot replace a result already "
                "returned to Cline."
            ),
            "Cline must invoke the managed native PostToolUse hook after the tool event.",
            ("Native Cline PostToolUse is observation-only and cannot provide model-visible replacement.",),
            "src/codex_plugin_scanner/guard/adapters/cline_hooks.py:_EVENTS",
        ),
        _capability(
            "cline",
            "PostToolUse",
            "agent_plugin",
            "replace_or_withhold",
            ("observe", "block", "rewrite"),
            (
                "Unavailable review withholds the original result; reviewed output may replace it without "
                "forwarding unreviewed metadata."
            ),
            "Cline must load the Guard AgentPlugin and route afterTool results through Guard before model delivery.",
            ("Synthetic plugin canaries do not prove live Cline model-visible replacement.",),
            "src/codex_plugin_scanner/guard/adapters/cline_plugin.py:plugin.hooks.afterTool",
        ),
        _capability(
            "cline",
            "UserPromptSubmit",
            "native_hook",
            "observe",
            ("observe",),
            "The native prompt hook reports a decision but does not cancel prompt submission on denial or failure.",
            "Cline must invoke the managed UserPromptSubmit hook for prompt observation.",
            ("Prompt observation does not block submission or prove final model request redaction.",),
            "src/codex_plugin_scanner/guard/adapters/cline_hooks.py:_EVENTS",
        ),
        *(
            _capability(
                "cline",
                event,
                "native_hook",
                "observe",
                ("observe",),
                "The native lifecycle hook records the event but does not cancel it on denial or failure.",
                f"Cline must invoke the managed {event} hook for lifecycle observation.",
                ("Lifecycle observations do not establish a blocking boundary.",),
                "src/codex_plugin_scanner/guard/adapters/cline_hooks.py:_EVENTS",
            )
            for event in ("TaskStart", "TaskError", "SessionShutdown")
        ),
    ),
    "grok": (
        _capability(
            "grok",
            "PreToolUse",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            "The catch-all pre-tool hook returns a native deny when Guard blocks the tool call.",
            "Grok must invoke the managed PreToolUse hook and honor its decision for tool and subagent calls.",
            ("Prompt submission and post-tool events are observe-only.",),
            "src/codex_plugin_scanner/guard/adapters/grok_hooks.py:grok_hook_response_from_guard",
        ),
        _capability(
            "grok",
            "UserPromptSubmit",
            "native_hook",
            "observe",
            ("observe",),
            "Grok ignores a deny response for this prompt hook, so it cannot block prompt submission.",
            "Grok must invoke the managed UserPromptSubmit hook for observation.",
            ("Prompt observation does not prevent model-visible prompt delivery.",),
            "src/codex_plugin_scanner/guard/adapters/grok_hooks.py:_OBSERVE_ONLY_EVENTS",
        ),
        _capability(
            "grok",
            "PostToolUse",
            "native_hook",
            "observe",
            ("observe",),
            "The native post-tool hook records an event after execution and cannot replace its result.",
            "Grok must invoke the managed PostToolUse hook after the tool event.",
            ("Post-tool observation does not block or replace model-visible output.",),
            "src/codex_plugin_scanner/guard/adapters/grok_hooks.py:_OBSERVE_ONLY_EVENTS",
        ),
    ),
    "pi": (
        _capability(
            "pi",
            "UserPromptSubmit",
            "managed_extension",
            "screening",
            ("observe", "block", "approval"),
            "Extension or Guard runtime failure returns a bounded fail-closed prompt decision.",
            "Pi must load the current managed Guard extension and forward input events to the Guard runtime.",
            ("Package installation and update flows happen outside the runtime extension bridge.",),
            'src/codex_plugin_scanner/guard/adapters/pi_extension_source.py:pi.on("input")',
        ),
        _capability(
            "pi",
            "PreToolUse",
            "managed_extension",
            "blocking",
            ("observe", "block", "approval"),
            "Extension or Guard runtime failure returns a bounded fail-closed tool decision.",
            "Pi must load the current managed Guard extension and forward tool_call events to Guard before execution.",
            ("A present extension file alone does not prove Pi loaded it or suppressed a live tool call.",),
            'src/codex_plugin_scanner/guard/adapters/pi_extension_source.py:pi.on("tool_call")',
        ),
        _capability(
            "pi",
            "PostToolUse",
            "managed_extension",
            "replace_or_withhold",
            ("observe", "block", "rewrite"),
            "Unavailable or failed review withholds the tool result; reviewed content may replace it.",
            "Pi must load the current managed Guard extension and forward tool_result events before model delivery.",
            ("A synthetic extension canary does not prove live Pi model-visible replacement.",),
            'src/codex_plugin_scanner/guard/adapters/pi_extension_source.py:pi.on("tool_result")',
        ),
    ),
    "omp": (
        _capability(
            "omp",
            "UserPromptSubmit",
            "managed_extension",
            "screening",
            ("observe", "block", "approval"),
            "Extension or Guard runtime failure returns a bounded fail-closed prompt decision.",
            "Oh My Pi must load the managed Guard extension and forward input events to Guard.",
            ("Package installation and update flows happen outside the runtime extension bridge.",),
            'src/codex_plugin_scanner/guard/adapters/pi_extension_source.py:pi.on("input")',
        ),
        _capability(
            "omp",
            "PreToolUse",
            "managed_extension",
            "blocking",
            ("observe", "block", "approval"),
            "Extension or Guard runtime failure returns a bounded fail-closed tool decision.",
            "Oh My Pi must load the managed Guard extension and forward tool_call events before execution.",
            ("A present extension file alone does not prove live tool suppression.",),
            'src/codex_plugin_scanner/guard/adapters/pi_extension_source.py:pi.on("tool_call")',
        ),
        _capability(
            "omp",
            "PostToolUse",
            "managed_extension",
            "replace_or_withhold",
            ("observe", "block", "rewrite"),
            "Unavailable or failed review withholds the tool result; reviewed content may replace it.",
            "Oh My Pi must load the managed Guard extension and forward tool_result events before model delivery.",
            ("A synthetic extension canary does not prove live model-visible replacement.",),
            'src/codex_plugin_scanner/guard/adapters/pi_extension_source.py:pi.on("tool_result")',
        ),
    ),
}


def _default_capability_events(contract: HarnessProtectionContract) -> tuple[HarnessEventCapability, ...]:
    """Give legacy contracts a conservative row without inventing hooks."""

    if not contract.event_surfaces:
        return (
            _capability(
                contract.harness,
                "*",
                "none",
                "unsupported",
                ("unavailable",),
                "No event surface is declared for this adapter.",
                "A concrete host event and transport must be added before protection is claimed.",
                (contract.known_blind_spots,),
                f"src/codex_plugin_scanner/guard/adapters/contracts.py:{contract.harness}.event_surfaces",
            ),
        )
    rows: list[HarnessEventCapability] = []
    for surface in contract.event_surfaces:
        rows.append(
            _capability(
                contract.harness,
                surface,
                "adapter_declared",
                "declared",
                ("observe",),
                "Failure behavior is adapter-specific until a concrete host hook contract is declared.",
                "The host must expose the declared event and preserve the adapter's response boundary.",
                (contract.known_blind_spots,),
                f"src/codex_plugin_scanner/guard/adapters/contracts.py:{contract.harness}.event_surfaces",
            )
        )
    if contract.harness == "opencode":
        rows.append(
            _capability(
                "opencode",
                "UserPromptSubmit",
                "none",
                "unsupported",
                ("unavailable",),
                "OpenCode's declared hooks do not surface prompt submission to Guard.",
                "A host prompt hook must exist before prompt interception can be claimed.",
                ("Prompt content is not available through the declared OpenCode hooks.",),
                "src/codex_plugin_scanner/guard/adapters/contracts.py:opencode.known_blind_spots",
            )
        )
    return tuple(rows)


# Attach the event authority to the existing setup contracts without changing
# their setup and table APIs.
HARNESS_CONTRACTS: tuple[HarnessProtectionContract, ...] = tuple(
    replace(
        contract,
        capability_events=_CAPABILITY_EVENTS_BY_HARNESS.get(contract.harness, _default_capability_events(contract)),
    )
    for contract in _BASE_HARNESS_CONTRACTS
)

_CONTRACT_BY_ALIAS: dict[str, HarnessProtectionContract] = {}
for _c in HARNESS_CONTRACTS:
    _CONTRACT_BY_ALIAS[_c.harness] = _c
    for _alias in _c.install_aliases:
        _CONTRACT_BY_ALIAS[_alias] = _c


def contract_for(harness: str) -> HarnessProtectionContract | None:
    """Return the contract for a harness name or install alias, or None."""
    return _CONTRACT_BY_ALIAS.get(harness)


def display_name_for(harness: str) -> str:
    contract = contract_for(harness)
    key = contract.harness if contract is not None else harness
    return _DISPLAY_NAMES.get(key, key)


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
            body=(
                "Install native provider hooks on the Paseo daemon host."
                if contract.harness == "paseo"
                else f"Add Guard's local protection hooks for {display_name}."
            ),
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
    return render_harness_contracts(HARNESS_CONTRACTS)


def harness_capability_report(
    *,
    build_id: str = "unknown",
    commit: str = "unknown",
    requested_host: str | None = None,
    host_version_scope: str | None = None,
    os_arch: str | None = None,
    local_hosted: str | None = None,
) -> HarnessCapabilityReport:
    """Return the additive versioned event report for all registered harnesses."""

    from .capability_report import build_capability_report

    return build_capability_report(
        build_id=build_id,
        commit=commit,
        requested_host=requested_host,
        host_version_scope=host_version_scope,
        os_arch=os_arch,
        local_hosted=local_hosted,
    )


def capability_report_for(
    harness: str,
    *,
    build_id: str = "unknown",
    commit: str = "unknown",
    host_version_scope: str | None = None,
    os_arch: str | None = None,
    local_hosted: str | None = None,
) -> HarnessCapabilityReport:
    """Return one event report, including an explicit row for unknown hosts."""

    from .capability_report import capability_report_for as build_for_host

    return build_for_host(
        harness,
        build_id=build_id,
        commit=commit,
        host_version_scope=host_version_scope,
        os_arch=os_arch,
        local_hosted=local_hosted,
    )
