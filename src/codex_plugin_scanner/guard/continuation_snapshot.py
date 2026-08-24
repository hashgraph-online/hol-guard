"""Immutable Cloud Review continuation capability snapshots."""

from __future__ import annotations

import re
from collections.abc import Mapping
from hashlib import sha256
from typing import Final, cast

CONTINUATION_CAPABILITIES: Final = frozenset({"retry-only", "session-resume", "suspended-response", "unsupported"})
_CORRELATION_PATTERN: Final = re.compile(r"^gcr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CORRELATION_KEYS: Final = ("correlationId", "correlation_id")


def canonical_continuation_correlation_id(
    *,
    request_id: str,
    request_row: Mapping[str, object],
    operation_metadata: Mapping[str, object],
) -> str:
    """Preserve a canonical upstream correlation or derive one from the request identity."""

    candidates: list[object] = []
    for source in (
        operation_metadata,
        _mapping(request_row.get("decision_v2_json")),
        _mapping(request_row.get("action_envelope_json")),
        request_row,
    ):
        candidates.extend(source.get(key) for key in _CORRELATION_KEYS)
    for candidate in candidates:
        value = _text(candidate)
        if value is not None and _CORRELATION_PATTERN.fullmatch(value) is not None:
            return value
    digest = sha256(f"guard-cloud-review\0{request_id}".encode()).hexdigest()[:32]
    return f"gcr_{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:]}"


def non_resumable_continuation_snapshot(request_row: Mapping[str, object]) -> dict[str, object]:
    """Freeze an explicit no-transport capability without consulting runtime state."""

    request_id = _text(request_row.get("request_id"))
    if request_id is None:
        raise ValueError("continuation_request_id_missing")
    harness = (_text(request_row.get("harness")) or "unknown").lower()
    capability = (
        "retry-only" if harness in {"codex", "grok", "hermes", "oh-my-pi", "omp", "openclaw", "pi"} else "unsupported"
    )
    return {
        "correlationId": canonical_continuation_correlation_id(
            request_id=request_id,
            request_row=request_row,
            operation_metadata={},
        ),
        "capability": capability,
        "hookAttached": False,
        "opaqueTargetId": None,
        "waitDeadline": None,
    }


def validated_continuation_snapshot(value: object) -> dict[str, object] | None:
    """Return a canonical frozen snapshot, rejecting ambiguous or unsafe shapes."""

    if not isinstance(value, Mapping):
        return None
    raw_snapshot = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw_snapshot):
        return None
    snapshot = {cast(str, key): nested for key, nested in raw_snapshot.items()}
    if set(snapshot) != {
        "capability",
        "correlationId",
        "hookAttached",
        "opaqueTargetId",
        "waitDeadline",
    }:
        return None
    correlation = _text(snapshot.get("correlationId"))
    capability = _text(snapshot.get("capability"))
    hook_attached = snapshot.get("hookAttached")
    target = snapshot.get("opaqueTargetId")
    deadline = snapshot.get("waitDeadline")
    if correlation is None or _CORRELATION_PATTERN.fullmatch(correlation) is None:
        return None
    if capability not in CONTINUATION_CAPABILITIES or not isinstance(hook_attached, bool):
        return None
    if target is not None and (not isinstance(target, str) or not target.strip()):
        return None
    if deadline is not None and (not isinstance(deadline, str) or not deadline.strip()):
        return None
    if capability == "suspended-response":
        if hook_attached is not True or deadline is None or target is not None:
            return None
    elif hook_attached or deadline is not None:
        return None
    if capability == "session-resume":
        if target is None:
            return None
    elif target is not None:
        return None
    return {
        "correlationId": correlation,
        "capability": capability,
        "hookAttached": hook_attached,
        "opaqueTargetId": target,
        "waitDeadline": deadline,
    }


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        return {}
    raw = cast(Mapping[object, object], value)
    return {key: nested for key, nested in raw.items() if isinstance(key, str)}


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = [
    "canonical_continuation_correlation_id",
    "non_resumable_continuation_snapshot",
    "validated_continuation_snapshot",
]
