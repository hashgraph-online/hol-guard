"""Claude hook configuration primitives and managed-handler identity."""

from __future__ import annotations

from pathlib import Path

from .base import HarnessContext

CLAUDE_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
CLAUDE_GUARD_POST_TOOL_MATCHER = f"{CLAUDE_GUARD_TOOL_MATCHER}|AskUserQuestion"
CLAUDE_GUARD_NOTIFICATION_MATCHER = "permission_prompt"
CLAUDE_GUARD_SESSION_START_MATCHERS = ("startup", "resume", "clear", "compact")
CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS = 30
CLAUDE_GUARD_NOTIFICATION_TIMEOUT_SECONDS = 10
CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS = 10
CLAUDE_GUARD_STOP_TIMEOUT_SECONDS = 10
CLAUDE_GUARD_DAEMON_HOOK_MARKER = "HOL_GUARD_CLAUDE_DAEMON_HOOK"
CLAUDE_GUARD_SESSION_START_HOOK_MARKER = "HOL_GUARD_CLAUDE_SESSION_START_HOOK"


def manifest_notes(payload: dict[str, object]) -> list[str]:
    notes = payload.get("notes")
    if not isinstance(notes, list):
        return []
    return [str(note) for note in notes]


def claude_managed_settings_path(context: HarnessContext) -> Path:
    return context.home_dir / ".claude" / "settings.json"


def guard_command_handler(
    argv: tuple[str, ...],
    *,
    timeout: int,
    status_message: str | None = None,
) -> dict[str, object]:
    """Build Claude's shell-free exec form from one canonical argv."""

    if not argv:
        raise ValueError("claude_guard_hook_argv_empty: provide the Guard executable and its argument vector")
    handler: dict[str, object] = {
        "type": "command",
        "command": argv[0],
        "args": list(argv[1:]),
        "timeout": timeout,
    }
    if status_message is not None:
        handler["statusMessage"] = status_message
    return handler


def sync_runtime_hook_groups(hooks: dict[str, object], hook_argv: tuple[str, ...]) -> None:
    for key, matcher, timeout, status_message in (
        (
            "PreToolUse",
            CLAUDE_GUARD_TOOL_MATCHER,
            CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS,
            "HOL Guard is checking this tool use",
        ),
        (
            "PermissionRequest",
            CLAUDE_GUARD_TOOL_MATCHER,
            CLAUDE_GUARD_NOTIFICATION_TIMEOUT_SECONDS,
            "HOL Guard is reviewing this approval prompt",
        ),
        ("PostToolUse", CLAUDE_GUARD_POST_TOOL_MATCHER, CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS, None),
        ("Notification", CLAUDE_GUARD_NOTIFICATION_MATCHER, CLAUDE_GUARD_NOTIFICATION_TIMEOUT_SECONDS, None),
        ("Stop", None, CLAUDE_GUARD_STOP_TIMEOUT_SECONDS, None),
    ):
        existing_entries = hooks.get(key)
        hooks[key] = merge_hook_group(
            prune_guard_hook_entries(existing_entries if isinstance(existing_entries, list) else []),
            matcher,
            guard_command_handler(hook_argv, timeout=timeout, status_message=status_message),
        )


def remove_unsupported_guard_hook_groups(hooks: dict[str, object]) -> None:
    for key in ("PermissionDenied", "UserPromptSubmit"):
        entries = hooks.get(key)
        if not isinstance(entries, list):
            continue
        remaining = prune_guard_hook_entries(entries)
        if remaining:
            hooks[key] = remaining
        else:
            hooks.pop(key, None)


def guard_hook_group(matcher: str | None, handler: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {"hooks": [handler]}
    if isinstance(matcher, str) and matcher.strip():
        payload["matcher"] = matcher
    return payload


def is_guard_hook_command(command: object) -> bool:
    if not isinstance(command, str):
        return False
    if CLAUDE_GUARD_DAEMON_HOOK_MARKER in command:
        return True
    if CLAUDE_GUARD_SESSION_START_HOOK_MARKER in command:
        return True
    if "codex_plugin_scanner.cli" in command:
        return "guard hook" in command or "'guard', 'hook'" in command or '"guard", "hook"' in command
    return "ensure_guard_daemon(" in command and "HOL Guard protection is active for this workspace." in command


def command_handler_argv(handler: dict[str, object]) -> tuple[str, ...] | None:
    command = handler.get("command")
    args = handler.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return None
    return (command, *args)


def handler_identity(handler: dict[str, object]) -> tuple[str, ...]:
    handler_type = str(handler.get("type", ""))
    if handler_type == "http":
        return (handler_type, str(handler.get("url", "")))
    argv = command_handler_argv(handler)
    if argv is not None:
        return (handler_type, "exec", *argv)
    shell = handler.get("shell")
    shell_identity = shell if isinstance(shell, str) and shell else "default"
    return (handler_type, f"shell:{shell_identity}", str(handler.get("command", "")))


def is_guard_hook_url(url: object) -> bool:
    if not isinstance(url, str):
        return False
    return url.startswith("http://127.0.0.1:") and "/v1/hooks/claude-code" in url


def is_guard_hook_handler(handler: object) -> bool:
    if not isinstance(handler, dict):
        return False
    handler_type = handler.get("type")
    if handler_type in {None, "command"}:
        argv = command_handler_argv(handler)
        if argv is not None:
            return any(is_guard_hook_command(argument) for argument in argv)
        return is_guard_hook_command(handler.get("command"))
    if handler_type == "http":
        return is_guard_hook_url(handler.get("url"))
    return False


def merge_hook_group(
    entries: list[object],
    matcher: str | None,
    handler: dict[str, object],
) -> list[object]:
    normalized: list[object] = []
    for entry in entries:
        if isinstance(entry, dict):
            normalized.append(entry)
    matcher_key = matcher.strip() if isinstance(matcher, str) and matcher.strip() else None
    expected_identity = handler_identity(handler)
    for index, entry in enumerate(normalized):
        if not isinstance(entry, dict):
            continue
        entry_matcher = entry.get("matcher")
        entry_matcher_key = entry_matcher.strip() if isinstance(entry_matcher, str) and entry_matcher.strip() else None
        if entry_matcher_key != matcher_key:
            continue
        hooks = entry.get("hooks")
        if not isinstance(hooks, list):
            hooks = []
        if any(isinstance(item, dict) and handler_identity(item) == expected_identity for item in hooks):
            updated_entry = dict(entry)
            updated_entry["hooks"] = [
                handler if isinstance(item, dict) and handler_identity(item) == expected_identity else item
                for item in hooks
            ]
            normalized[index] = updated_entry
            return normalized
        hooks.append(handler)
        updated_entry = dict(entry)
        updated_entry["hooks"] = hooks
        normalized[index] = updated_entry
        return normalized
    normalized.append(guard_hook_group(matcher_key, handler))
    return normalized


def group_has_handler(entry: object, handler: dict[str, object]) -> bool:
    if not isinstance(entry, dict):
        return False
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    expected_identity = handler_identity(handler)
    return any(isinstance(hook, dict) and handler_identity(hook) == expected_identity for hook in hooks)


def prune_guard_hook_entries(entries: list[object]) -> list[object]:
    remaining: list[object] = []
    for entry in entries:
        if not isinstance(entry, dict):
            remaining.append(entry)
            continue
        if is_guard_hook_handler(entry):
            continue
        hooks = entry.get("hooks")
        if not isinstance(hooks, list):
            remaining.append(entry)
            continue
        filtered_hooks = [item for item in hooks if not is_guard_hook_handler(item)]
        if filtered_hooks:
            updated_entry = dict(entry)
            updated_entry["hooks"] = filtered_hooks
            remaining.append(updated_entry)
    return remaining


def remove_hook_entry(entries: list[object], handler: dict[str, object]) -> list[object]:
    remaining: list[object] = []
    expected_identity = handler_identity(handler)
    for entry in entries:
        if not isinstance(entry, dict):
            remaining.append(entry)
            continue
        if is_guard_hook_handler(entry):
            continue
        if group_has_handler(entry, handler):
            hooks = entry.get("hooks")
            if not isinstance(hooks, list):
                continue
            filtered_hooks = [
                item for item in hooks if not (isinstance(item, dict) and handler_identity(item) == expected_identity)
            ]
            if filtered_hooks:
                updated_entry = dict(entry)
                updated_entry["hooks"] = filtered_hooks
                remaining.append(updated_entry)
            continue
        remaining.append(entry)
    return remaining
