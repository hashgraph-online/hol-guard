"""Claude hook configuration primitives and managed-handler identity.

The managed hook groups (events, matchers, timeouts, status messages, pruned
events, and bridge config keys) come from one declarative contract,
``guard/contracts/claude-hook-groups.v1.json``. The native SessionStart lane
compares installed settings against the same file, so the two cannot drift.
Handler identity, Guard-handler checks and the entry prune and merge run in the
native ``claude_hook_config`` kind; lists are rebuilt here from the caller's objects.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from .base import HarnessContext

if TYPE_CHECKING:
    from ..native_runner_authority import NativeRunnerAuthorityError

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


# Merge ``handler`` into ``entries`` once per matcher, after pruning Guard's entries when the flag is set.
ClaudeHookMergeJob = tuple[list[object], tuple[str | None, ...], dict[str, object], bool]
_Source = tuple[list[object], dict[str, object] | None]


def _malformed() -> NativeRunnerAuthorityError:
    from ..native_runner_authority import NativeRunnerAuthorityError

    return NativeRunnerAuthorityError("Claude hook config answer is malformed")


def _ask(op: str, **fields: object) -> dict[str, object]:
    # Imported here so the Claude hook bridge stays off the native runtime at import time.
    from ..native_runner_authority import native_runner_authority

    answer: dict[str, object] = native_runner_authority("claude_hook_config", {"op": op, **fields})
    error = answer.get("error")
    if error == "claude_hook_handler_type_unhashable":
        raise TypeError("Claude hook handler type is unhashable")
    if error is not None:
        raise _malformed()
    return answer


def _flag(value: object) -> bool:
    if not isinstance(value, bool):
        raise _malformed()
    return value


def _answer_texts(value: object, *, optional: bool = False) -> list[str] | None:
    if (value is not None or not optional) and (
        not isinstance(value, list) or not all(isinstance(item, str) for item in value)
    ):
        raise _malformed()
    return value


def _index(value: object, size: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < size:
        raise _malformed()
    return value


def _rebuilt(answer: dict[str, object], key: str, sources: list[_Source]) -> list[list[object]]:
    plans = answer.get(key)
    if not isinstance(plans, list) or len(plans) != len(sources):
        raise _malformed()
    return [_rebuild(entries, plan, handler) for (entries, handler), plan in zip(sources, plans, strict=True)]


def _copied_entry(entries: list[object], step: dict[str, object], handler: dict[str, object] | None) -> object:
    entry, items = entries[_index(step.get("entry"), len(entries))], step.get("hooks")
    if set(step) != {"entry", "hooks"} or not isinstance(entry, dict) or not isinstance(items, list):
        raise _malformed()
    own = entry.get("hooks")
    own_hooks = own if isinstance(own, list) else []
    updated_entry = dict(entry)
    updated_entry["hooks"] = [
        handler if item is None and handler is not None else own_hooks[_index(item, len(own_hooks))] for item in items
    ]
    return updated_entry


def _rebuild(entries: list[object], plan: object, handler: dict[str, object] | None) -> list[object]:
    """Apply a native plan to the caller's own entries, keeping their objects and key order."""

    if not isinstance(plan, list):
        raise _malformed()
    rebuilt: list[object] = []
    for step in plan:
        if not isinstance(step, dict):
            rebuilt.append(entries[_index(step, len(entries))])
        elif "entry" in step:
            rebuilt.append(_copied_entry(entries, step, handler))
        elif handler is not None and set(step) == {"matcher"} and isinstance(step["matcher"], str | None):
            rebuilt.append(guard_hook_group(step["matcher"], handler))
        else:
            raise _malformed()
    return rebuilt


def entry_list(entries: object) -> list[object]:
    """The entries of a hook event, or an empty list for a missing or non-list value."""

    return entries if isinstance(entries, list) else []


def prune_guard_hook_lists(lists: list[list[object]]) -> list[list[object]]:
    """Drop Guard's entries and handlers from each list, in one native call."""

    return _rebuilt(_ask("prune", lists=lists), "lists", [(entries, None) for entries in lists])


def prune_guard_hook_entries(entries: list[object]) -> list[object]:
    return prune_guard_hook_lists([entries])[0]


def prune_guard_hook_events(hooks: dict[str, object], events: tuple[str, ...]) -> None:
    lists = [entry_list(hooks.get(event)) for event in events]
    for event, entries in zip(events, prune_guard_hook_lists(lists), strict=True):
        hooks[event] = entries


def merge_hook_groups(jobs: list[ClaudeHookMergeJob]) -> list[list[object]]:
    """Run each merge job in one native call; results reuse the caller's entry and handler objects."""

    request = [{"entries": e, "prune": prune, "matchers": list(m), "handler": h} for e, m, h, prune in jobs]
    return _rebuilt(_ask("merge", jobs=request), "jobs", [(entries, handler) for entries, _, handler, _ in jobs])


def merge_hook_group(
    entries: list[object],
    matcher: str | None,
    handler: dict[str, object],
) -> list[object]:
    return merge_hook_groups([(entries, (matcher,), handler, False)])[0]


def sync_runtime_hook_groups(hooks: dict[str, object], hook_argv: tuple[str, ...]) -> None:
    jobs: list[ClaudeHookMergeJob] = [
        (
            entry_list(hooks.get(group.event)),
            (group.matcher,),
            guard_command_handler(hook_argv, timeout=group.timeout_seconds, status_message=group.status_message),
            True,
        )
        for group in CLAUDE_RUNTIME_HOOK_GROUPS
    ]
    for group, entries in zip(CLAUDE_RUNTIME_HOOK_GROUPS, merge_hook_groups(jobs), strict=True):
        hooks[group.event] = entries


def remove_unsupported_guard_hook_groups(hooks: dict[str, object]) -> None:
    events = [event for event in dict.fromkeys(CLAUDE_GUARD_PRUNED_HOOK_EVENTS) if isinstance(hooks.get(event), list)]
    pruned = prune_guard_hook_lists([entry_list(hooks[event]) for event in events]) if events else []
    for event, remaining in zip(events, pruned, strict=True):
        if remaining:
            hooks[event] = remaining
        else:
            hooks.pop(event, None)


def guard_hook_group(matcher: str | None, handler: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {"hooks": [handler]}
    if isinstance(matcher, str) and matcher.strip():
        payload["matcher"] = matcher
    return payload


def is_guard_hook_command(command: object) -> bool:
    return isinstance(command, str) and _flag(_ask("text", value=command).get("command"))


def is_guard_hook_url(url: object) -> bool:
    return isinstance(url, str) and _flag(_ask("text", value=url).get("url"))


def command_handler_argv(handler: dict[str, object]) -> tuple[str, ...] | None:
    answer = _ask("handler", handler=handler)
    if "argv" not in answer:
        raise _malformed()
    argv = _answer_texts(answer["argv"], optional=True)
    return None if argv is None else tuple(argv)


def handler_identity(handler: dict[str, object]) -> tuple[str, ...]:
    return tuple(_answer_texts(_ask("handler", handler=handler).get("identity")) or ())


def is_guard_hook_handler(handler: object) -> bool:
    if not isinstance(handler, dict):
        return False
    guard = _ask("handler", handler=handler).get("guard")
    if guard is None:
        raise TypeError("Claude hook handler type is unhashable")
    return _flag(guard)


CLAUDE_GUARD_REQUIRED_HOOK_EVENTS = ("PreToolUse", "PermissionRequest")


def missing_guard_hook_events(payload: dict[str, object]) -> list[str]:
    """Required hook events whose Guard handler does not cover the protected tools."""

    answer = _ask(
        "missing",
        payload={"hooks": payload["hooks"]} if "hooks" in payload else {},
        events=list(CLAUDE_GUARD_REQUIRED_HOOK_EVENTS),
        matcher=CLAUDE_GUARD_TOOL_MATCHER,
    )
    return _answer_texts(answer.get("missing")) or []


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
