"""OAuth identity resolution for the Cloud Review event worker."""

from __future__ import annotations

from typing import Any

from ..review_oauth_binding import GuardReviewContractError, guard_review_oauth_metadata
from ..store import GuardStore
from ..store_review_event_outbox_binding import review_event_oauth_subject_hash


def _with_cloud_review_sync_identity(
    store: GuardStore,
    auth_context: dict[str, object],
) -> dict[str, object]:
    oauth = guard_review_oauth_metadata(store)
    subject_hash = review_event_oauth_subject_hash(oauth.grant_id)
    if subject_hash is None:
        raise GuardReviewContractError("missing_oauth_subject")
    expected_binding = {
        "oauth_source": store.guard_source,
        "oauth_subject_hash": subject_hash,
        "workspace_id": oauth.workspace_id,
        "machine_id": oauth.machine_id,
        "machine_installation_id": oauth.installation_id,
    }
    if store.get_review_event_oauth_binding() != expected_binding:
        raise GuardReviewContractError("oauth_binding_mismatch")
    return {**auth_context, **expected_binding}


def resolve_cloud_review_sync_auth_context(
    store: GuardStore,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Resolve event-sync auth and repair paired storage when possible."""

    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _resolve_guard_sync_auth_context,
        repair_guard_cloud_connect_storage,
    )

    try:
        resolved = _resolve_guard_sync_auth_context(store, force_refresh=force_refresh)
        return _with_cloud_review_sync_identity(store, resolved)
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
        repair = repair_guard_cloud_connect_storage(store)
        if repair["existing_sign_in_valid"] or repair["repaired_storage"]:
            resolved = _resolve_guard_sync_auth_context(store, force_refresh=force_refresh)
            return _with_cloud_review_sync_identity(store, resolved)
        raise


__all__ = ["resolve_cloud_review_sync_auth_context"]
