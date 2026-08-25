"""Collapse duplicate remembered artifact rules for dashboard listing."""

from __future__ import annotations

from typing import Protocol


class PolicyDecisionStore(Protocol):
    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]: ...


def list_remembered_policy_decisions(
    store: PolicyDecisionStore,
    harness: str | None = None,
) -> list[dict[str, object]]:
    return collapse_duplicate_artifact_policy_rows(store.list_policy_decisions(harness))


def _artifact_row_rank(item: dict[str, object]) -> tuple[str, int]:
    updated_at = str(item.get("updated_at") or "")
    decision_id = item.get("decision_id")
    ident = decision_id if type(decision_id) is int else 0
    return (updated_at, ident)


def collapse_duplicate_artifact_policy_rows(
    items: list[dict[str, object]],
) -> list[dict[str, object]]:
    best: dict[tuple[object, ...], dict[str, object]] = {}
    order: list[tuple[object, ...]] = []
    for item in items:
        if str(item.get("scope") or "") != "artifact":
            key = ("row", item.get("decision_id"))
        else:
            command = str(item.get("remembered_command") or item.get("artifact_id") or "")
            key = (
                "artifact",
                str(item.get("harness") or ""),
                str(item.get("action") or ""),
                str(item.get("source") or ""),
                command,
            )
        current = best.get(key)
        if current is None:
            best[key] = item
            order.append(key)
            continue
        if _artifact_row_rank(item) > _artifact_row_rank(current):
            best[key] = item
    return [best[key] for key in order]
