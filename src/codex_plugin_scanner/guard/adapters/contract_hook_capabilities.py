"""Declared event capabilities for supported harnesses."""

from .contract_capability_values import _capability
from .contract_models import HarnessEventCapability

HOOK_EVENT_CAPABILITIES: dict[str, tuple[HarnessEventCapability, ...]] = {
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
            (
                "Guard adds pending review context and defers to Claude's own permission dialog; the native "
                "PreToolUse verdict remains the decision boundary.",
            ),
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
            "preToolUse",
            "native_hook",
            "blocking",
            ("observe", "block", "approval"),
            "Blocking hook or Guard transport failure fails closed before Cursor writes, edits or deletes the file.",
            "Cursor must load the managed preToolUse hook for file mutation tools and honor failClosed behavior.",
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
}
