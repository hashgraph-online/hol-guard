"""Thin transport to the native runtime's hook decision receipt check."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .native_context import _resolve_existing_digest_home, native_context_digest


def _native_receipt_valid(
    receipt: Mapping[str, object],
    edge: Mapping[str, object] | None,
    *,
    guard_home: Path | None,
    deadline_monotonic: float | None,
) -> bool:
    # A caller under a deadline bounds every resident attempt by what it has left.
    budget = (
        {}
        if deadline_monotonic is None
        else {
            "timeout_seconds": deadline_monotonic - time.monotonic(),
            "hard_deadline_monotonic": deadline_monotonic,
        }
    )
    result = native_context_digest(
        "native_decision_receipt_validation",
        {"receipt": dict(receipt), "edge": dict(edge) if edge is not None else None},
        guard_home=_resolve_existing_digest_home(guard_home),
        **budget,
    )
    return isinstance(result, dict) and result.get("native_decision_receipt_valid") is True


def validate_native_decision_receipt(
    value: object, *, guard_home: Path | None = None, deadline_monotonic: float | None = None
) -> dict[str, object] | None:
    """Copy one Rust receipt the native runtime accepts; anything else is ``None``."""

    if not isinstance(value, Mapping):
        return None
    receipt = dict(cast(Mapping[str, object], value))
    valid = _native_receipt_valid(receipt, None, guard_home=guard_home, deadline_monotonic=deadline_monotonic)
    return receipt if valid else None


def edge_receipt(
    harness: str, result: Mapping[str, object], receipt: object, *, guard_home: Path | None = None
) -> dict[str, object] | None:
    """Copy one receipt the native runtime accepts as this ``PreToolUse`` result's record."""

    if not isinstance(receipt, Mapping):
        return None
    copied = dict(cast(Mapping[str, object], receipt))
    edge = {
        "harness": harness,
        "event_name": "PreToolUse",
        "payload_kind": copied.get("payload_kind"),
        "result": dict(result),
    }
    return copied if receipt_matches_edge(edge, copied, guard_home=guard_home) else None


def receipt_matches_edge(payload: Mapping[str, object], receipt: object, *, guard_home: Path | None = None) -> bool:
    """Whether the native runtime accepts the receipt as a record of this edge result."""

    edge = {
        key: payload[key]
        for key in ("harness", "event_name", "payload_kind", "request_id", "result")
        if payload.get(key) is not None
    }
    return isinstance(receipt, Mapping) and _native_receipt_valid(
        cast(Mapping[str, object], receipt), edge, guard_home=guard_home, deadline_monotonic=None
    )


__all__ = [
    "edge_receipt",
    "receipt_matches_edge",
    "validate_native_decision_receipt",
]
