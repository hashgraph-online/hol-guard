"""Device-bound v2 custom Extension continuity planning."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from ..store_custom_extension_continuity import CustomExtensionContinuityMutation
from .custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY,
    CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY,
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2,
    CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
    CustomExtensionContinuityError,
    _AuthorityUpdate,
    _identity_from_local,
    _local_override_matches,
    _observation_precondition,
    _plan_exact_settings,
    _require_monotonic_observation,
    _timestamp,
)

if TYPE_CHECKING:
    from ..store import GuardStore

_MAX_ITEMS = 100
_MAX_DEVICE_BINDINGS_PER_ITEM = 1
_TOP_LEVEL_FIELDS = frozenset({"schemaVersion", "revision", "observedAt", "expiresAt", "items"})
_ITEM_FIELDS = frozenset({"identityHash", "deviceIdentityHashes", "state"})
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class _V2Preflight:
    authority_revision: int
    observation: dict[str, object]
    digest: str
    previous: object
    revision: int
    device_hash: str
    binding: Mapping[str, str]
    same_context: bool
    stale: bool
    local_items: Mapping[str, dict[str, object]]
    local_by_scoped_identity: Mapping[str, list[dict[str, object]]]
    removals_raw: object
    removals: Mapping[str, object]


@dataclass(slots=True)
class _V2Plan:
    authority_updates: list[_AuthorityUpdate]
    statuses: dict[str, dict[str, object]]
    events: list[tuple[str, Mapping[str, object]]]
    observation_preconditions: dict[str, object]


def prepare_v2_continuity(
    store: GuardStore,
    value: object,
    *,
    device_id: str,
    workspace_id: str,
    now: str,
) -> tuple[CustomExtensionContinuityMutation, dict[str, object]]:
    """Plan exact v2 writes while capturing every optimistic precondition."""

    preflight = _preflight_v2(store, value, workspace_id=workspace_id, device_id=device_id, now=now)
    plan = _plan_projection_items(store, preflight, workspace_id=workspace_id)
    if not preflight.same_context and isinstance(preflight.previous, dict):
        _plan_context_cleanup(
            store,
            previous=preflight.previous,
            local_items=preflight.local_items,
            removals=preflight.removals,
            protected_cli_ids=set(plan.statuses),
            authority_updates=plan.authority_updates,
            observation_preconditions=plan.observation_preconditions,
            events=plan.events,
        )
    state = _state_payload(preflight, statuses=plan.statuses)
    return _mutation(preflight, plan, state=state, now=now), state


def _preflight_v2(
    store: GuardStore,
    value: object,
    *,
    workspace_id: str,
    device_id: str,
    now: str,
) -> _V2Preflight:
    authority_revision = store.read_local_cli_revision()
    observation = _parse_observation(value)
    digest = hashlib.sha256(
        json.dumps(observation, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    previous = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    revision = cast(int, observation["revision"])
    device_hash = _device_binding_hash(workspace_id, device_id)
    workspace_hash = _workspace_binding_hash(workspace_id)
    binding = {"workspaceHash": workspace_hash, "deviceHash": device_hash}
    same_context = _same_context(previous, binding)
    if same_context:
        _require_monotonic_observation(previous, revision=revision, digest=digest)
    elif (
        isinstance(previous, dict)
        and previous.get("schema_version") == CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2
        and not isinstance(previous.get("binding"), dict)
    ):
        raise CustomExtensionContinuityError("prior v2 continuity binding is unavailable")
    stale = _timestamp(cast(str, observation["expiresAt"]), "expiry") <= _timestamp(now, "current time")
    local_items = {
        str(item["cli_id"]): item for item in store.list_local_cli_items() if isinstance(item.get("cli_id"), str)
    }
    local_by_scoped_identity: dict[str, list[dict[str, object]]] = defaultdict(list)
    for local in local_items.values():
        identity_hash = local.get("identity_hash")
        if isinstance(identity_hash, str):
            local_by_scoped_identity[_workspace_identity_hash(workspace_id, identity_hash)].append(local)
    removals_raw = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY)
    removals = dict(removals_raw) if isinstance(removals_raw, dict) else {}
    return _V2Preflight(
        authority_revision,
        observation,
        digest,
        previous,
        revision,
        device_hash,
        binding,
        same_context,
        stale,
        local_items,
        local_by_scoped_identity,
        removals_raw,
        removals,
    )


def _plan_projection_items(store: GuardStore, preflight: _V2Preflight, *, workspace_id: str) -> _V2Plan:
    plan = _V2Plan([], {}, [], {})
    for item in cast(list[dict[str, object]], preflight.observation["items"]):
        if preflight.device_hash not in cast(list[str], item["deviceIdentityHashes"]):
            continue
        scoped_identity = cast(str, item["identityHash"])
        matches = list(preflight.local_by_scoped_identity.get(scoped_identity, ()))
        if not matches:
            matches = [
                preflight.local_items[cli_id]
                for cli_id in _prior_local_items(preflight.previous, scoped_identity=scoped_identity)
                if cli_id in preflight.local_items
            ]
        if not matches:
            evidence = _evidence(
                scoped_identity,
                preflight.revision,
                "pending_observation",
                "local_identity_not_observed",
            )
            plan.statuses[scoped_identity] = evidence
            plan.events.append(("custom_extension_continuity/pending_observation", evidence))
            continue
        for local in matches:
            cli_id = cast(str, local["cli_id"])
            raw_identity_hash = local.get("identity_hash")
            observed_count = local.get("observed_count")
            status, reason = "pending_observation", "local_identity_not_observed"
            if isinstance(raw_identity_hash, str):
                plan.observation_preconditions[cli_id] = _observation_precondition(local)
            if type(observed_count) is not int or observed_count < 1:
                pass
            elif preflight.stale:
                status, reason = "stale", "cloud_observation_expired"
            elif not isinstance(raw_identity_hash, str):
                pass
            elif _workspace_identity_hash(workspace_id, raw_identity_hash) != scoped_identity:
                status, reason = "changed_identity", "identity_mismatch"
            elif _local_override_matches(
                preflight.removals.get(cli_id),
                identity_hash=raw_identity_hash,
                cloud_revision=preflight.revision,
            ):
                status, reason = "locally_overridden", "local_authority_preserved"
            elif item["state"] == "removed":
                plan.authority_updates.append(_AuthorityUpdate(_identity_from_local(local), "unset", {}))
                status, reason = "removed", "signed_cloud_tombstone"
            else:
                update = _plan_exact_settings(
                    store,
                    local=local,
                    settings={"state": item["state"], "commands": {}},
                )
                if update is not None:
                    plan.authority_updates.append(update)
                status, reason = "applied", "same_scoped_identity"
            evidence = _evidence(scoped_identity, preflight.revision, status, reason)
            if isinstance(raw_identity_hash, str):
                evidence["local_identity_hash"] = raw_identity_hash
            plan.statuses[cli_id] = evidence
            plan.events.append((f"custom_extension_continuity/{status}", evidence))
    return plan


def _state_payload(preflight: _V2Preflight, *, statuses: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2,
        "cloud_revision": preflight.revision,
        "observed_at": preflight.observation["observedAt"],
        "expires_at": preflight.observation["expiresAt"],
        "stale": preflight.stale,
        "observation_digest": preflight.digest,
        "binding": preflight.binding,
        "items": statuses,
    }


def _mutation(
    preflight: _V2Preflight,
    plan: _V2Plan,
    *,
    state: dict[str, object],
    now: str,
) -> CustomExtensionContinuityMutation:
    sync_payloads: dict[str, Mapping[str, object]] = {CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: state}
    if not preflight.stale:
        sync_payloads[CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY] = state
    return CustomExtensionContinuityMutation(
        expected_revision=preflight.authority_revision,
        authority_updates=tuple((item.identity, item.state, item.commands) for item in plan.authority_updates),
        sync_payloads=sync_payloads,
        events=tuple(plan.events),
        updated_at=now,
        sync_preconditions={
            CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: preflight.previous,
            CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY: preflight.removals_raw,
        },
        observation_preconditions=plan.observation_preconditions,
        requires_protected_extension_authority=True,
        required_negotiated_capability="custom-extension-continuity.v2",
    )


def _plan_context_cleanup(
    store: GuardStore,
    *,
    previous: dict[str, object],
    local_items: Mapping[str, dict[str, object]],
    removals: Mapping[str, object],
    protected_cli_ids: set[str],
    authority_updates: list[_AuthorityUpdate],
    observation_preconditions: dict[str, object],
    events: list[tuple[str, Mapping[str, object]]],
) -> None:
    raw_items = previous.get("items")
    if not isinstance(raw_items, dict):
        return
    previous_revision = previous.get("cloud_revision")
    cloud_revision = previous_revision if type(previous_revision) is int else 0
    for cli_id, raw in raw_items.items():
        if cli_id in protected_cli_ids or not isinstance(cli_id, str) or not isinstance(raw, dict):
            continue
        if raw.get("status") != "applied":
            continue
        local = local_items.get(cli_id)
        prior_identity = raw.get("local_identity_hash", raw.get("identity_hash"))
        if local is None or local.get("identity_hash") != prior_identity or not isinstance(prior_identity, str):
            continue
        if _local_override_matches(removals.get(cli_id), identity_hash=prior_identity, cloud_revision=cloud_revision):
            continue
        current = store.read_local_cli_grant(cli_id)
        if current is None or current.get("identity_hash") != prior_identity:
            continue
        observation_preconditions[cli_id] = _observation_precondition(local)
        authority_updates.append(_AuthorityUpdate(_identity_from_local(local), "unset", {}))
        evidence = {
            "cloud_revision": cloud_revision,
            "status": "removed",
            "reason": "continuity_context_changed",
        }
        events.append(("custom_extension_continuity/removed", evidence))


def _evidence(scoped_identity: str, revision: int, status: str, reason: str) -> dict[str, object]:
    return {
        "workspace_identity_hash": scoped_identity,
        "cloud_revision": revision,
        "status": status,
        "reason": reason,
    }


def _same_context(previous: object, binding: Mapping[str, str]) -> bool:
    return isinstance(previous, dict) and previous.get("binding") == dict(binding)


def _prior_local_items(previous: object, *, scoped_identity: str) -> tuple[str, ...]:
    if not isinstance(previous, dict) or not isinstance(previous.get("items"), dict):
        return ()
    return tuple(
        cli_id
        for cli_id, item in cast(dict[str, object], previous["items"]).items()
        if isinstance(item, dict) and item.get("workspace_identity_hash") == scoped_identity
    )


def _parse_observation(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _TOP_LEVEL_FIELDS:
        raise CustomExtensionContinuityError("continuity observation contains unsupported fields")
    if value.get("schemaVersion") != CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2:
        raise CustomExtensionContinuityError("unsupported continuity observation schema")
    revision = value.get("revision")
    if type(revision) is not int or cast(int, revision) < 1:
        raise CustomExtensionContinuityError("continuity revision must be positive")
    observed_at = value.get("observedAt")
    expires_at = value.get("expiresAt")
    if not isinstance(observed_at, str) or not isinstance(expires_at, str):
        raise CustomExtensionContinuityError("continuity timestamps are required")
    if _timestamp(expires_at, "expiry") <= _timestamp(observed_at, "observation"):
        raise CustomExtensionContinuityError("continuity expiry must follow observation")
    raw_items = value.get("items")
    if not isinstance(raw_items, list) or len(raw_items) > _MAX_ITEMS:
        raise CustomExtensionContinuityError("continuity item limit exceeded")
    items: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _ITEM_FIELDS:
            raise CustomExtensionContinuityError("continuity item contains unsupported fields")
        identity_hash = raw_item.get("identityHash")
        if not _sha256(identity_hash) or cast(str, identity_hash) in seen:
            raise CustomExtensionContinuityError("invalid or duplicate continuity identity")
        device_hashes = raw_item.get("deviceIdentityHashes")
        if (
            not isinstance(device_hashes, list)
            or not device_hashes
            or len(device_hashes) > _MAX_DEVICE_BINDINGS_PER_ITEM
            or any(not _sha256(item) for item in device_hashes)
            or len(set(cast(list[str], device_hashes))) != len(device_hashes)
        ):
            raise CustomExtensionContinuityError("invalid continuity device binding")
        state = raw_item.get("state")
        if state not in {"allowed", "blocked", "removed"}:
            raise CustomExtensionContinuityError("invalid continuity setting")
        seen.add(cast(str, identity_hash))
        items.append(
            {
                "identityHash": identity_hash,
                "deviceIdentityHashes": sorted(cast(list[str], device_hashes)),
                "state": state,
            }
        )
    return {**value, "items": sorted(items, key=lambda item: cast(str, item["identityHash"]))}


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in _HEX for character in value)


def _workspace_identity_hash(workspace_id: str, local_identity_hash: str) -> str:
    material = f"{CUSTOM_EXTENSION_CONTINUITY_SCHEMA}:{workspace_id}:{local_identity_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _workspace_binding_hash(workspace_id: str) -> str:
    material = f"{CUSTOM_EXTENSION_CONTINUITY_SCHEMA}:workspace:{workspace_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _device_binding_hash(workspace_id: str, device_id: str) -> str:
    material = f"{CUSTOM_EXTENSION_CONTINUITY_SCHEMA}:device:{workspace_id}:{device_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
