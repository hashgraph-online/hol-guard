"""Mechanical admission fences for a publisher's already observed authority."""

from __future__ import annotations

from collections.abc import Mapping


def policy_authority_required(publisher: object) -> bool:
    return (
        getattr(publisher, "requires_policy_authority", False) is True
        or getattr(publisher, "requires_scoped_authority", False) is True
    )


def legacy_source_binding_is_current(publisher: object, snapshot: Mapping[str, object] | None) -> bool:
    getter = getattr(publisher, "current_snapshot_binding", None)
    if snapshot is None or not callable(getter):
        return False
    try:
        current = getter()
    except Exception:
        return False
    return isinstance(current, dict) and current == snapshot
