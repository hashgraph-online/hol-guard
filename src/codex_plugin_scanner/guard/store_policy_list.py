"""Collapse duplicate remembered artifact rules for dashboard listing."""

from __future__ import annotations


def list_remembered_policy_decisions(
    store: object,
    harness: str | None = None,
) -> list[dict[str, object]]:
    list_fn = getattr(store, "list_policy_decisions")
    items = list_fn(harness)
    return collapse_duplicate_artifact_policy_rows(items)


def collapse_duplicate_artifact_policy_rows(
    items: list[dict[str, object]],
) -> list[dict[str, object]]:
    seen: set[tuple[object, ...]] = set()
    collapsed: list[dict[str, object]] = []
    for item in items:
        if str(item.get("scope") or "") != "artifact":
            collapsed.append(item)
            continue
        command = str(item.get("remembered_command") or item.get("artifact_id") or "")
        key = (
            str(item.get("harness") or ""),
            str(item.get("action") or ""),
            str(item.get("source") or ""),
            command,
        )
        if key in seen:
            continue
        seen.add(key)
        collapsed.append(item)
    return collapsed
