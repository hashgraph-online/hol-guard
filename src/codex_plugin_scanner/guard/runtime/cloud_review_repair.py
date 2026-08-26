"""Bounded recovery for quarantined Cloud Review event synchronization."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import GuardStore

REPAIRABLE_REVIEW_EVENT_BINDING_STATES = frozenset(
    {
        "identity_mismatch",
        "unbound",
    }
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _count(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    return value if isinstance(value, int) and value > 0 else 0


def cloud_review_sync_repair_status(
    store: GuardStore,
    *,
    now: str | None = None,
) -> dict[str, object] | None:
    binding = store.get_review_event_oauth_binding()
    if not isinstance(binding, dict):
        return None
    required = (
        "oauth_subject_hash",
        "workspace_id",
        "machine_id",
        "machine_installation_id",
    )
    if not all(isinstance(binding.get(key), str) and binding[key] for key in required):
        return None
    status = store.review_event_outbox_status(
        now=now or _now(),
        oauth_subject_hash=str(binding["oauth_subject_hash"]),
        workspace_id=str(binding["workspace_id"]),
        machine_id=str(binding["machine_id"]),
        machine_installation_id=str(binding["machine_installation_id"]),
    )
    identity_mismatch_count = _count(status, "identity_mismatch_depth")
    unbound_count = _count(status, "unbound_depth")
    other_workspace_count = _count(status, "other_workspace_depth")
    if unbound_count:
        binding_state = "unbound"
    elif identity_mismatch_count:
        binding_state = "identity_mismatch"
    elif other_workspace_count:
        binding_state = "workspace_mismatch"
    else:
        binding_state = str(status.get("binding_state") or "healthy")
    quarantined_count = identity_mismatch_count + unbound_count
    return {
        "bindingState": binding_state,
        "quarantinedCount": quarantined_count,
        "repairable": (quarantined_count > 0 and binding_state in REPAIRABLE_REVIEW_EVENT_BINDING_STATES),
        "source": store.guard_source,
        "workspaceId": str(binding["workspace_id"]),
    }


def execute_cloud_review_sync_repair(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    source = payload.get("source")
    workspace_id = payload.get("workspaceId")
    if not isinstance(source, str) or source != store.guard_source:
        raise ValueError("approved_source_mismatch")
    binding = store.get_review_event_oauth_binding()
    if not isinstance(binding, dict) or workspace_id != binding.get("workspace_id"):
        raise ValueError("approved_workspace_mismatch")
    reassigned = store.reassign_quarantined_review_events(
        approved_source=source,
        approved_workspace_id=str(workspace_id),
    )
    return {
        "summary": "Cloud Review event sync history repaired.",
        "data": {
            "reassignedCount": reassigned,
            "status": cloud_review_sync_repair_status(store, now=generated_at),
        },
        "generatedAt": generated_at,
    }
