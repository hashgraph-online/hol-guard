"""Exact ownership and legacy-adoption operations for Codex hook groups."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy

from .codex_hook_file_integrity import split_hook_command
from .codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS


def remove_manifest_bound_hook_events(
    hooks: dict[str, object],
    bindings: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], bool]:
    """Remove only handlers whose exact identity is authenticated by a manifest."""

    updated_hooks = deepcopy(hooks)
    changed = False
    for binding in bindings:
        event_name = binding.get("event")
        expected_group = binding.get("group")
        expected_handler = binding.get("handler")
        if (
            not isinstance(event_name, str)
            or event_name not in MANAGED_CODEX_HOOK_EVENTS
            or not isinstance(expected_group, dict)
            or not isinstance(expected_handler, dict)
        ):
            continue
        groups = updated_hooks.get(event_name)
        if not isinstance(groups, list):
            continue
        remaining_groups: list[object] = []
        removed_for_binding = False
        for group in groups:
            if removed_for_binding or not isinstance(group, dict):
                remaining_groups.append(group)
                continue
            if group == expected_group:
                removed_for_binding = True
                changed = True
                continue
            if group.get("matcher") != expected_group.get("matcher"):
                remaining_groups.append(group)
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list) or expected_handler not in handlers:
                remaining_groups.append(group)
                continue
            remaining_handlers = list(handlers)
            remaining_handlers.remove(expected_handler)
            removed_for_binding = True
            changed = True
            if remaining_handlers:
                updated_group = dict(group)
                updated_group["hooks"] = remaining_handlers
                remaining_groups.append(updated_group)
        if remaining_groups:
            updated_hooks[event_name] = remaining_groups
        else:
            updated_hooks.pop(event_name, None)
    return updated_hooks, changed


def exact_legacy_hook_bindings(
    hooks: Mapping[str, object],
    *,
    expected_bindings: Sequence[Mapping[str, object]],
    current_argv: Sequence[str],
    legacy_argv: Sequence[str],
    legacy_status_messages: set[str],
) -> list[dict[str, object]]:
    """Select exact current-package entries for explicit pre-manifest adoption."""

    expected_by_event = {
        event: binding for binding in expected_bindings if isinstance((event := binding.get("event")), str)
    }
    bindings: list[dict[str, object]] = []
    for event_name in MANAGED_CODEX_HOOK_EVENTS:
        groups = hooks.get(event_name)
        expected = expected_by_event.get(event_name)
        expected_group = expected.get("group") if isinstance(expected, Mapping) else None
        if not isinstance(groups, list) or not isinstance(expected_group, dict):
            continue
        for group in groups:
            if not isinstance(group, dict) or group.get("matcher") != expected_group.get("matcher"):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            handler = next(
                (
                    item
                    for item in handlers
                    if isinstance(item, dict)
                    and split_hook_command(item.get("command")) in (list(current_argv), list(legacy_argv))
                    and item.get("statusMessage") in legacy_status_messages
                ),
                None,
            )
            if handler is not None:
                bindings.append({"event": event_name, "group": group, "handler": handler})
                break
    return bindings


__all__ = ["exact_legacy_hook_bindings", "remove_manifest_bound_hook_events"]
