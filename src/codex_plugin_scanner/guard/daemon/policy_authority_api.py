"""Authenticated daemon authority for OS-bound remembered policy decisions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class PolicyAuthorityApiError(ValueError):
    """Stable validation error for the local policy authority API."""


def resolve_policy_decision(
    store: Any,
    payload: Mapping[str, object],
    *,
    now: str,
) -> dict[str, object]:
    harness = _required_string(payload, "harness")
    artifact_id = _optional_string(payload.get("artifact_id"))
    artifact_hash = _optional_string(payload.get("artifact_hash"))
    workspace = _optional_string(payload.get("workspace"))
    publisher = _optional_string(payload.get("publisher"))
    lookup = store.resolve_policy_decision_lookup(
        harness,
        artifact_id,
        artifact_hash,
        workspace,
        publisher,
        now,
        consume_one_shot=False,
    )
    decision = lookup.get("decision")
    ignored_integrity = lookup.get("ignored_local_integrity")
    return {
        "decision": dict(decision) if isinstance(decision, Mapping) else None,
        "ignored_local_integrity": (
            dict(ignored_integrity) if isinstance(ignored_integrity, Mapping) else None
        ),
        "authority_revision": lookup.get("authority_revision"),
    }


def claim_policy_decision(
    store: Any,
    payload: Mapping[str, object],
    *,
    now: str,
) -> dict[str, object]:
    decision = payload.get("decision")
    if not isinstance(decision, Mapping):
        raise PolicyAuthorityApiError("invalid_decision")
    return {
        "claimed": bool(store.claim_approval_reuse_decision(dict(decision), now=now)),
    }


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = _optional_string(payload.get(key))
    if value is None:
        raise PolicyAuthorityApiError(f"invalid_{key}")
    return value


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
