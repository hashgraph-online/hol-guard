"""Bounded recovery for quarantined live-request synchronization."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import GuardStore

REPAIRABLE_LIVE_REQUEST_BINDING_STATES = frozenset(
    {
        "identity_mismatch",
        "legacy_ambiguous",
    }
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _count(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    return value if isinstance(value, int) and value > 0 else 0


def live_request_sync_repair_status(
    store: GuardStore,
    *,
    now: str | None = None,
) -> dict[str, object] | None:
    binding = store.get_live_request_oauth_binding()
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
    status = store.live_request_outbox_status(
        now=now or _now(),
        oauth_subject_hash=str(binding["oauth_subject_hash"]),
        workspace_id=str(binding["workspace_id"]),
        machine_id=str(binding["machine_id"]),
        machine_installation_id=str(binding["machine_installation_id"]),
    )
    identity_mismatch_count = _count(status, "identity_mismatch_depth")
    repairable_legacy_count = _count(status, "repairable_legacy_unbound_depth")
    legacy_count = _count(status, "legacy_unbound_depth")
    if repairable_legacy_count:
        binding_state = "legacy_ambiguous"
    elif identity_mismatch_count:
        binding_state = "identity_mismatch"
    elif legacy_count:
        binding_state = "workspace_mismatch"
    else:
        binding_state = str(status.get("binding_state") or "healthy")
    quarantined_count = identity_mismatch_count + repairable_legacy_count
    return {
        "bindingState": binding_state,
        "quarantinedCount": quarantined_count,
        "repairable": (quarantined_count > 0 and binding_state in REPAIRABLE_LIVE_REQUEST_BINDING_STATES),
        "source": store.guard_source,
        "workspaceId": str(binding["workspace_id"]),
    }


def execute_live_request_sync_repair(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    source = payload.get("source")
    workspace_id = payload.get("workspaceId")
    if not isinstance(source, str) or source != store.guard_source:
        raise ValueError("approved_source_mismatch")
    binding = store.get_live_request_oauth_binding()
    if not isinstance(binding, dict) or workspace_id != binding.get("workspace_id"):
        raise ValueError("approved_workspace_mismatch")
    reassigned = store.reassign_quarantined_live_request_outbox(
        approved_source=source,
        approved_workspace_id=str(workspace_id),
    )
    return {
        "summary": "Live request sync history repaired.",
        "data": {
            "reassignedCount": reassigned,
            "status": live_request_sync_repair_status(store, now=generated_at),
        },
        "generatedAt": generated_at,
    }
