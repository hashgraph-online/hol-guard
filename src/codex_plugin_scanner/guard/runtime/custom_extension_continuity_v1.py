"""Legacy exact-identity custom Extension continuity planning."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from ..store_custom_extension_continuity import CustomExtensionContinuityMutation
from .custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY,
    CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY,
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
    CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
    _AuthorityUpdate,
    _local_override_matches,
    _observation_precondition,
    _plan_exact_settings,
    _preflight,
)

if TYPE_CHECKING:
    from ..store import GuardStore


def prepare_v1_continuity(
    store: GuardStore,
    *,
    payload: Mapping[str, object],
    now: str,
) -> tuple[CustomExtensionContinuityMutation, dict[str, object]]:
    """Plan v1 continuity without mutating persistent authority."""

    preflight = _preflight(store, payload=payload, now=now)
    statuses: dict[str, dict[str, object]] = {}
    authority_updates: list[_AuthorityUpdate] = []
    events: list[tuple[str, Mapping[str, object]]] = []
    observation_preconditions: dict[str, object] = {}
    remaining_overrides = dict(preflight.removals)
    overrides_changed = False
    for item in cast(list[dict[str, object]], preflight.observation["items"]):
        cli_id = cast(str, item["cliId"])
        identity_hash = cast(str, item["identityHash"])
        settings = cast(dict[str, object], item["settings"])
        local = preflight.local_items.get(cli_id)
        observation_preconditions[cli_id] = _observation_precondition(local)
        surface = local.get("surface") if local is not None else None
        observed_count = local.get("observed_count") if local is not None else None
        status, reason = "pending_observation", "local_identity_not_observed"
        local_override = preflight.removals.get(cli_id)
        if preflight.stale:
            status, reason = "stale", "cloud_observation_expired"
        elif _local_override_matches(local_override, identity_hash=identity_hash, cloud_revision=preflight.revision):
            status, reason = _local_override_status(local_override)
        elif local is None or type(observed_count) is not int or observed_count < 1:
            pass
        elif local.get("identity_hash") != identity_hash:
            status, reason = "changed_identity", "identity_mismatch"
        else:
            overrides_changed = _plan_matched_item(
                store,
                cli_id=cli_id,
                local=local,
                settings=settings,
                remaining_overrides=remaining_overrides,
                authority_updates=authority_updates,
            ) or overrides_changed
            status, reason = "applied", "same_identity"
        evidence: dict[str, object] = {
            "cli_id": cli_id,
            "identity_hash": identity_hash,
            "cloud_revision": preflight.revision,
            "status": status,
            "reason": reason,
        }
        if surface in {"cli", "mcp", "package-scripts"}:
            evidence["surface"] = surface
        statuses[cli_id] = evidence
        events.append((f"custom_extension_continuity/{status}", evidence))
    state: dict[str, object] = {
        "schema_version": CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
        "cloud_revision": preflight.revision,
        "observed_at": preflight.observation["observedAt"],
        "expires_at": preflight.observation["expiresAt"],
        "stale": preflight.stale,
        "observation_digest": preflight.observation_digest,
        "items": statuses,
    }
    sync_payloads: dict[str, Mapping[str, object]] = {CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: state}
    if not preflight.stale:
        sync_payloads[CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY] = state
    if overrides_changed:
        sync_payloads[CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY] = remaining_overrides
    return (
        CustomExtensionContinuityMutation(
            expected_revision=preflight.authority_revision,
            authority_updates=tuple((item.identity, item.state, item.commands) for item in authority_updates),
            sync_payloads=sync_payloads,
            events=tuple(events),
            updated_at=now,
            sync_preconditions={
                CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: preflight.previous,
                CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY: preflight.removals_raw,
            },
            observation_preconditions=observation_preconditions,
        ),
        state,
    )


def _local_override_status(value: object) -> tuple[str, str]:
    if isinstance(value, dict) and value.get("state") in {"allowed", "blocked"}:
        return "locally_overridden", "local_authority_preserved"
    return "removed", "removed_locally"


def _plan_matched_item(
    store: GuardStore,
    *,
    cli_id: str,
    local: dict[str, object],
    settings: dict[str, object],
    remaining_overrides: dict[str, object],
    authority_updates: list[_AuthorityUpdate],
) -> bool:
    override_removed = cli_id in remaining_overrides
    remaining_overrides.pop(cli_id, None)
    update = _plan_exact_settings(store, local=local, settings=settings)
    if update is not None:
        authority_updates.append(update)
    return override_removed
