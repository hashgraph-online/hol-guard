"""Non-Codex harness resume helpers for approval resolution."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress

from .adapters.contracts import contract_for
from .store import GuardStore


def resume_harness_operation(
    store: GuardStore,
    *,
    request_id: str,
    action: str,
    now: str,
) -> dict[str, object] | None:
    """Mark a waiting non-Codex operation as resumed or blocked."""

    operation = store.get_guard_operation_for_approval_request(request_id)
    if operation is None:
        return None
    canonical_harness = _canonical_harness(operation.get("harness"))
    if canonical_harness != "pi":
        return None
    normalized_action = _normalize_action(action)
    if normalized_action is None:
        return None
    status = "resumed" if normalized_action == "allow" else "blocked"
    metadata = operation.get("metadata")
    safe_metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
    safe_metadata["resume_action"] = normalized_action
    safe_metadata["resume_completed_at"] = now
    approval_request_ids = operation.get("approval_request_ids")
    safe_approval_request_ids = (
        [str(item) for item in approval_request_ids if isinstance(item, str)]
        if isinstance(approval_request_ids, list)
        else [request_id]
    )
    updated = store.upsert_guard_operation(
        operation_id=str(operation["operation_id"]),
        session_id=str(operation["session_id"]),
        harness=canonical_harness,
        operation_type=str(operation["operation_type"]),
        status=status,
        approval_request_ids=safe_approval_request_ids,
        resume_token=str(operation["resume_token"]) if isinstance(operation.get("resume_token"), str) else None,
        metadata=safe_metadata,
        now=now,
    )
    payload = {
        "operationId": str(updated["operation_id"]),
        "harness": canonical_harness,
        "status": status,
        "action": normalized_action,
        "completedAt": now,
    }
    with suppress(Exception):
        store.add_event(
            "harness/operation_resume",
            {
                "action": normalized_action,
                "harness": canonical_harness,
                "operation_id": str(updated["operation_id"]),
                "request_id": request_id,
                "status": status,
            },
            now,
        )
    return payload


def _canonical_harness(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    contract = contract_for(value.strip())
    return contract.harness if contract is not None else value.strip()


def _normalize_action(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().replace("_", "-")
    if normalized in {"allow", "allow-once"} or value.strip() == "allowOnce":
        return "allow"
    if normalized in {"block", "deny", "denied", "blocked"}:
        return "block"
    return None
