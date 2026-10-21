"""Shared merge/prune helpers for Guard-managed hook event groups.

Adapters that write Claude-Code-shaped ``hooks`` event groups share the same
mechanical reconciliation: a Guard-managed handler (identified per harness by
an ``is_managed`` predicate over the handler ``command`` string) is added or
refreshed under a matcher group without disturbing user-owned entries.
"""

from __future__ import annotations

from collections.abc import Callable

IsManagedHookCommand = Callable[[object], bool]


def is_managed_handler(handler: object, is_managed: IsManagedHookCommand) -> bool:
    """Return True when a nested hook handler is Guard-managed."""

    return isinstance(handler, dict) and is_managed(handler.get("command"))


def prune_managed_hook_entries(
    entries: list[object],
    *,
    is_managed: IsManagedHookCommand,
) -> list[object]:
    """Drop Guard-managed handlers while preserving user hook groups.

    Groups left without any handlers are removed entirely; non-dict entries
    are kept defensively so user data is never silently dropped.
    """

    remaining: list[object] = []
    for entry in entries:
        if not isinstance(entry, dict):
            remaining.append(entry)
            continue
        if is_managed(entry.get("command")):
            continue
        nested_hooks = entry.get("hooks")
        if isinstance(nested_hooks, list):
            filtered = [item for item in nested_hooks if not is_managed_handler(item, is_managed)]
            if filtered:
                updated = dict(entry)
                updated["hooks"] = filtered
                remaining.append(updated)
            continue
        remaining.append(entry)
    return remaining


def merge_hook_entry(
    entries: list[object],
    matcher: str | None,
    handler: dict[str, object],
    *,
    is_managed: IsManagedHookCommand,
) -> list[object]:
    """Add or refresh the Guard handler for a given matcher, preserving user hooks.

    Non-dict entries (kept defensively by ``prune_managed_hook_entries``) are
    passed through unchanged so the merge never drops user data.
    """

    normalized: list[object] = list(entries)
    matcher_key = matcher.strip() if isinstance(matcher, str) and matcher.strip() else None
    for index, entry in enumerate(normalized):
        if not isinstance(entry, dict):
            continue
        entry_matcher = entry.get("matcher")
        entry_matcher_key = entry_matcher.strip() if isinstance(entry_matcher, str) and entry_matcher.strip() else None
        if entry_matcher_key != matcher_key:
            continue
        nested_hooks = entry.get("hooks")
        if not isinstance(nested_hooks, list):
            nested_hooks = []
        if any(is_managed_handler(item, is_managed) for item in nested_hooks):
            updated = dict(entry)
            updated["hooks"] = [handler if is_managed_handler(item, is_managed) else item for item in nested_hooks]
            normalized[index] = updated
            return normalized
        merged_hooks = [*nested_hooks, handler]
        updated = dict(entry)
        updated["hooks"] = merged_hooks
        normalized[index] = updated
        return normalized
    group: dict[str, object] = {"hooks": [handler]}
    if matcher_key is not None:
        group["matcher"] = matcher_key
    normalized.append(group)
    return normalized


__all__ = ["IsManagedHookCommand", "is_managed_handler", "merge_hook_entry", "prune_managed_hook_entries"]
