"""Claude hook configuration primitives and managed-handler identity.

The managed hook groups (events, matchers, timeouts, status messages, pruned
events, and bridge config keys) come from one declarative contract,
``guard/contracts/claude-hook-groups.v1.json``. The native SessionStart lane
compares installed settings against the same file, so the two cannot drift.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Final, NamedTuple

from .base import HarnessContext

CLAUDE_HOOK_GROUPS_CONTRACT_PATH: Final = (
    Path(__file__).resolve().parent.parent / "contracts" / "claude-hook-groups.v1.json"
)
_CONTRACT_SCHEMA: Final = "hol-guard.claude-hook-groups.v1"


class ClaudeRuntimeHookGroup(NamedTuple):
    event: str
    matcher: str | None
    timeout_seconds: int
    status_message: str | None


def _contract_error(field: str) -> ValueError:
    return ValueError(f"claude_hook_groups_contract_invalid: {field}")


def _field(mapping: Mapping[str, object], name: str) -> object:
    if name not in mapping:
        raise _contract_error(name)
    return mapping[name]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise _contract_error(label)
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise _contract_error(label)
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _texts(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _contract_error(label)
    return tuple(_text(item, label) for item in value)


def _seconds(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise _contract_error(label)
    return value


def _runtime_group(value: object) -> ClaudeRuntimeHookGroup:
    group = _mapping(value, "runtime_groups")
    return ClaudeRuntimeHookGroup(
        _text(_field(group, "event"), "runtime_groups.event"),
        _optional_text(_field(group, "matcher"), "runtime_groups.matcher"),
        _seconds(_field(group, "timeout_seconds"), "runtime_groups.timeout_seconds"),
        _optional_text(_field(group, "status_message"), "runtime_groups.status_message"),
    )


class ClaudeHookGroupsContract(NamedTuple):
    runtime_groups: tuple[ClaudeRuntimeHookGroup, ...]
    pruned_events: tuple[str, ...]
    session_start_matchers: tuple[str, ...]
    session_start_timeout_seconds: int
    session_start_context: str
    daemon_hook_marker: str
    session_start_hook_marker: str
    bridge_required_keys: tuple[str, ...]
    bridge_optional_keys: tuple[str, ...]


def parse_claude_hook_groups_contract(document: object) -> ClaudeHookGroupsContract:
    """Shape-check the whole contract; any defect fails installation closed."""

    contract = _mapping(document, "document")
    if contract.get("schema") != _CONTRACT_SCHEMA:
        raise _contract_error("schema")
    markers = _mapping(_field(contract, "markers"), "markers")
    session_start = _mapping(_field(contract, "session_start"), "session_start")
    bridge_config = _mapping(_field(contract, "bridge_config"), "bridge_config")
    group_values = _field(contract, "runtime_groups")
    if not isinstance(group_values, list) or not group_values:
        raise _contract_error("runtime_groups")
    groups = tuple(_runtime_group(group) for group in group_values)
    events = {group.event for group in groups}
    if len(events) != len(groups) or not {"PreToolUse", "PostToolUse", "Notification", "Stop"} <= events:
        raise _contract_error("runtime_groups.event")
    return ClaudeHookGroupsContract(
        runtime_groups=groups,
        pruned_events=_texts(_field(contract, "pruned_events"), "pruned_events"),
        session_start_matchers=_texts(_field(session_start, "matchers"), "session_start.matchers"),
        session_start_timeout_seconds=_seconds(
            _field(session_start, "timeout_seconds"), "session_start.timeout_seconds"
        ),
        session_start_context=_text(_field(session_start, "additional_context"), "session_start.additional_context"),
        daemon_hook_marker=_text(_field(markers, "daemon_hook"), "markers.daemon_hook"),
        session_start_hook_marker=_text(_field(markers, "session_start_hook"), "markers.session_start_hook"),
        bridge_required_keys=_texts(_field(bridge_config, "required_keys"), "bridge_config.required_keys"),
        bridge_optional_keys=_texts(_field(bridge_config, "optional_keys"), "bridge_config.optional_keys"),
    )


def load_claude_hook_groups_contract(path: Path = CLAUDE_HOOK_GROUPS_CONTRACT_PATH) -> ClaudeHookGroupsContract:
    return parse_claude_hook_groups_contract(json.loads(path.read_text(encoding="utf-8")))


_CONTRACT: Final = load_claude_hook_groups_contract()
_GROUPS_BY_EVENT: Final = {group.event: group for group in _CONTRACT.runtime_groups}
CLAUDE_RUNTIME_HOOK_GROUPS: Final = _CONTRACT.runtime_groups
CLAUDE_GUARD_PRUNED_HOOK_EVENTS: Final = _CONTRACT.pruned_events
CLAUDE_BRIDGE_CONFIG_REQUIRED_KEYS: Final = _CONTRACT.bridge_required_keys
CLAUDE_BRIDGE_CONFIG_OPTIONAL_KEYS: Final = _CONTRACT.bridge_optional_keys

# Grep reads file contents, including hidden files such as `.env`; the
# native authority proves directory scopes before allowing them.
CLAUDE_GUARD_TOOL_MATCHER: Final = _text(_GROUPS_BY_EVENT["PreToolUse"].matcher, "PreToolUse.matcher")
CLAUDE_GUARD_POST_TOOL_MATCHER: Final = _text(_GROUPS_BY_EVENT["PostToolUse"].matcher, "PostToolUse.matcher")
CLAUDE_GUARD_NOTIFICATION_MATCHER: Final = _text(_GROUPS_BY_EVENT["Notification"].matcher, "Notification.matcher")
CLAUDE_GUARD_SESSION_START_MATCHERS: Final = _CONTRACT.session_start_matchers
CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS: Final = _GROUPS_BY_EVENT["PreToolUse"].timeout_seconds
CLAUDE_GUARD_NOTIFICATION_TIMEOUT_SECONDS: Final = _GROUPS_BY_EVENT["Notification"].timeout_seconds
CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS: Final = _CONTRACT.session_start_timeout_seconds
CLAUDE_GUARD_STOP_TIMEOUT_SECONDS: Final = _GROUPS_BY_EVENT["Stop"].timeout_seconds
CLAUDE_GUARD_SESSION_START_CONTEXT: Final = _CONTRACT.session_start_context
CLAUDE_GUARD_DAEMON_HOOK_MARKER: Final = _CONTRACT.daemon_hook_marker
CLAUDE_GUARD_SESSION_START_HOOK_MARKER: Final = _CONTRACT.session_start_hook_marker
# Authenticated daemon marker: defer a PermissionRequest to Claude's own
# dialog without supplying a decision.
CLAUDE_GUARD_PERMISSION_PASSTHROUGH_KEY = "guard_permission_passthrough"


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
    for group in CLAUDE_RUNTIME_HOOK_GROUPS:
        existing_entries = hooks.get(group.event)
        hooks[group.event] = merge_hook_group(
            prune_guard_hook_entries(existing_entries if isinstance(existing_entries, list) else []),
            group.matcher,
            guard_command_handler(hook_argv, timeout=group.timeout_seconds, status_message=group.status_message),
        )


def remove_unsupported_guard_hook_groups(hooks: dict[str, object]) -> None:
    for key in CLAUDE_GUARD_PRUNED_HOOK_EVENTS:
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
    return "ensure_guard_daemon(" in command and CLAUDE_GUARD_SESSION_START_CONTEXT in command


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


CLAUDE_GUARD_REQUIRED_HOOK_EVENTS = ("PreToolUse", "PermissionRequest")


def missing_guard_hook_events(payload: dict[str, object]) -> list[str]:
    """Required hook events whose Guard handler does not cover the protected tools."""

    hooks = payload.get("hooks")
    missing: list[str] = []
    for event in CLAUDE_GUARD_REQUIRED_HOOK_EVENTS:
        entries = hooks.get(event) if isinstance(hooks, dict) else None
        if not isinstance(entries, list) or not any(_entry_covers_guard_tools(entry) for entry in entries):
            missing.append(event)
    return missing


def mark_missing_guard_hooks(
    diagnostics: dict[str, object], settings_path: object, settings: dict[str, object]
) -> None:
    """Downgrade an "active" setup whose settings file lost the Guard hook entries.

    The launcher shim alone makes Guard look managed, so confirm the entries.
    """

    missing = missing_guard_hook_events(settings)
    if not missing:
        return
    warnings = diagnostics.get("warnings")
    diagnostics["warnings"] = [
        *(warnings if isinstance(warnings, list) else []),
        f"Managed Claude Code hooks are missing from {settings_path} ({', '.join(missing)}). "
        "Run `hol-guard repair` or `hol-guard install claude-code` to restore protection.",
    ]
    diagnostics["setup_status"] = "broken"


def _matcher_covers_guard_tools(matcher: object) -> bool:
    """An omitted matcher matches every tool. A set matcher must still name each protected tool."""

    if matcher is None:
        return True
    if not isinstance(matcher, str):
        return False
    installed = {part.strip() for part in matcher.split("|") if part.strip()}
    required = {part.strip() for part in CLAUDE_GUARD_TOOL_MATCHER.split("|") if part.strip()}
    return required <= installed


def _entry_covers_guard_tools(entry: object) -> bool:
    if not _entry_has_guard_handler(entry) or not isinstance(entry, dict):
        return False
    return _matcher_covers_guard_tools(entry.get("matcher"))


def _entry_has_guard_handler(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    if is_guard_hook_handler(entry):
        return True
    handlers = entry.get("hooks")
    return isinstance(handlers, list) and any(is_guard_hook_handler(handler) for handler in handlers)


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
