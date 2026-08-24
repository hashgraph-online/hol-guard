"""Non-Codex harness resume helpers for approval resolution."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress

from .adapters.contracts import contract_for
from .continuation_runtime import continue_request_after_application
from .store import GuardStore


def safe_resume_metadata(resume: Mapping[str, object]) -> dict[str, object]:
    """Return the public, normalized subset of harness resume metadata."""

    safe: dict[str, object] = {}
    for source_key, target_key in (
        ("operationId", "operationId"),
        ("operation_id", "operationId"),
        ("harness", "harness"),
        ("requestId", "requestId"),
        ("request_id", "requestId"),
        ("status", "status"),
        ("reason", "reason"),
        ("message", "message"),
        ("attempt_count", "attemptCount"),
        ("attemptCount", "attemptCount"),
        ("last_attempt_at", "lastAttemptAt"),
        ("lastAttemptAt", "lastAttemptAt"),
        ("sent_at", "sentAt"),
        ("sentAt", "sentAt"),
        ("completedAt", "completedAt"),
        ("completed_at", "completedAt"),
        ("resolution_action", "resolutionAction"),
        ("resolutionAction", "resolutionAction"),
        ("strategy", "strategy"),
        ("supported", "supported"),
    ):
        value = resume.get(source_key)
        if isinstance(value, str) and value.strip():
            safe[target_key] = value.strip()
        elif isinstance(value, (int, float, bool)):
            safe[target_key] = value
    return safe


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
    if canonical_harness not in {"pi", "omp", "grok", "openclaw", "hermes"}:
        return None
    normalized_action = _normalize_action(action)
    if normalized_action is None:
        return None
    request = store.get_approval_request(request_id)
    if isinstance(request, dict) and _supports_durable_continuation(store):
        continuation = continue_request_after_application(
            store,
            request_row=request,
            action=normalized_action,
            now=now,
        )
        detail = continuation.get("harnessResume")
        if isinstance(detail, dict):
            return {
                "action": normalized_action,
                "completedAt": detail.get("completedAt"),
                "harness": canonical_harness,
                "operationId": str(operation["operation_id"]),
                "reason": detail.get("reason"),
                "status": detail.get("status"),
            }
    # Pi/OMP/Grok have no proven original-session continuation transport.  A
    # locally applied allow therefore requires an explicit retry, not a resume.
    status = "manual_retry_required" if normalized_action == "allow" else "blocked"
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
    payload: dict[str, object] = {
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


def _supports_durable_continuation(store: GuardStore) -> bool:
    return all(
        callable(getattr(store, name, None))
        for name in ("get_request_resume", "seed_request_resume", "update_request_resume")
    )
