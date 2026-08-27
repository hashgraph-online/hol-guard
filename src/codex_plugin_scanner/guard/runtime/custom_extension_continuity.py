"""Apply signed Cloud custom-Extension settings to exact local identities only."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from .local_cli_commands import MAX_LOCAL_CLI_COMMANDS, LocalCliCommandState, is_local_cli_command_id
from .local_cli_identity import LocalCliKind, UnlistedCliIdentity, is_local_cli_id

if TYPE_CHECKING:
    from ..store import GuardStore

CUSTOM_EXTENSION_CONTINUITY_FIELD = "x-hol-custom-extension-continuity"
CUSTOM_EXTENSION_CONTINUITY_SCHEMA = "guard.custom-extension-continuity.v1"
CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2 = "guard.custom-extension-continuity.v2"
CUSTOM_EXTENSION_CONTINUITY_STATE_KEY = "custom_extension_continuity"
CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY = "custom_extension_continuity_last_good"
CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY = "custom_extension_continuity_local_removals"

_MAX_ITEMS = 100
_MAX_DEVICE_BINDINGS_PER_ITEM = 1
_ITEM_FIELDS = frozenset({"cliId", "identityHash", "settings"})
_SETTINGS_FIELDS = frozenset({"state", "commands"})
_TOP_LEVEL_FIELDS = frozenset({"schemaVersion", "revision", "observedAt", "expiresAt", "items"})
_V2_ITEM_FIELDS = frozenset({"identityHash", "deviceIdentityHashes", "state"})
_HEX = frozenset("0123456789abcdef")


class CustomExtensionContinuityError(ValueError):
    """The signed continuity observation cannot be applied safely."""


@dataclass(frozen=True, slots=True)
class _AuthorityUpdate:
    identity: UnlistedCliIdentity
    state: str
    commands: Mapping[str, LocalCliCommandState]


@dataclass(frozen=True, slots=True)
class _ContinuityPreflight:
    authority_revision: int
    observation: dict[str, object]
    observation_digest: str
    previous: object
    stale: bool
    local_items: Mapping[str, dict[str, object]]
    removals_raw: object
    removals: Mapping[str, object]
    revision: int


def apply_verified_custom_extension_continuity(
    store: GuardStore,
    validated_policy_bundle: Mapping[str, object],
    *,
    device_id: str | None = None,
    now: str,
) -> dict[str, object]:
    """Consume continuity only after the production caller verified the bundle signature."""

    payload = validated_policy_bundle.get("payload")
    if not isinstance(payload, Mapping):
        raise CustomExtensionContinuityError("verified policy bundle payload is missing")
    if payload.get(CUSTOM_EXTENSION_CONTINUITY_FIELD) is None:
        previous = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
        return dict(previous) if isinstance(previous, dict) else {}
    continuity = payload[CUSTOM_EXTENSION_CONTINUITY_FIELD]
    if isinstance(continuity, dict) and continuity.get("schemaVersion") == CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2:
        workspace_id = validated_policy_bundle.get("workspaceId")
        if not isinstance(workspace_id, str) or not workspace_id or device_id is None:
            raise CustomExtensionContinuityError("v2 continuity requires workspace and device binding")
        return _apply_v2(
            store,
            continuity,
            device_id=device_id,
            workspace_id=workspace_id,
            now=now,
        )
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
        status = "pending_observation"
        reason = "local_identity_not_observed"
        local_override = preflight.removals.get(cli_id)
        if preflight.stale:
            status, reason = "stale", "cloud_observation_expired"
        elif _local_override_matches(
            local_override,
            identity_hash=identity_hash,
            cloud_revision=preflight.revision,
        ):
            if isinstance(local_override, dict) and local_override.get("state") in {"allowed", "blocked"}:
                status, reason = "locally_overridden", "local_authority_preserved"
            else:
                status, reason = "removed", "removed_locally"
        elif local is None or type(observed_count) is not int or cast(int, observed_count) < 1:
            status, reason = "pending_observation", "local_identity_not_observed"
        elif local.get("identity_hash") != identity_hash:
            status, reason = "changed_identity", "identity_mismatch"
        else:
            if cli_id in remaining_overrides:
                remaining_overrides.pop(cli_id)
                overrides_changed = True
            update = _plan_exact_settings(store, local=local, settings=settings)
            if update is not None:
                authority_updates.append(update)
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
    sync_payloads = {CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: state}
    if not preflight.stale:
        sync_payloads[CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY] = state
    if overrides_changed:
        sync_payloads[CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY] = remaining_overrides
    try:
        _ = store.apply_custom_extension_continuity_transaction(
            expected_revision=preflight.authority_revision,
            authority_updates=[(item.identity, item.state, item.commands) for item in authority_updates],
            sync_payloads=sync_payloads,
            events=events,
            updated_at=now,
            sync_preconditions={
                CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: preflight.previous,
                CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY: preflight.removals_raw,
            },
            observation_preconditions=observation_preconditions,
        )
    except ValueError as error:
        raise CustomExtensionContinuityError("local continuity authority changed during apply") from error
    return state


def _apply_v2(
    store: GuardStore,
    value: object,
    *,
    device_id: str,
    workspace_id: str,
    now: str,
) -> dict[str, object]:
    observation = _parse_v2_observation(value)
    digest = hashlib.sha256(
        json.dumps(observation, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    previous = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    revision = cast(int, observation["revision"])
    _require_monotonic_observation(previous, revision=revision, digest=digest)
    stale = _timestamp(cast(str, observation["expiresAt"]), "expiry") <= _timestamp(now, "current time")
    device_hash = _scoped_device_identity_hash(workspace_id, device_id)
    local_items = {
        str(item["cli_id"]): item
        for item in store.list_local_cli_items()
        if isinstance(item.get("cli_id"), str)
    }
    local_by_scoped_identity = {
        _scoped_workspace_identity_hash(workspace_id, cast(str, item["identity_hash"])): item
        for item in local_items.values()
        if isinstance(item.get("identity_hash"), str)
    }
    removals_raw = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY)
    removals = dict(removals_raw) if isinstance(removals_raw, dict) else {}
    authority_updates: list[_AuthorityUpdate] = []
    statuses: dict[str, dict[str, object]] = {}
    events: list[tuple[str, Mapping[str, object]]] = []
    observation_preconditions: dict[str, object] = {}
    for item in cast(list[dict[str, object]], observation["items"]):
        if device_hash not in cast(list[str], item["deviceIdentityHashes"]):
            continue
        scoped_identity = cast(str, item["identityHash"])
        local = local_by_scoped_identity.get(scoped_identity)
        prior_local = _prior_local_item(previous, scoped_identity=scoped_identity)
        if local is None and prior_local is not None:
            local = local_items.get(prior_local)
        cli_id = cast(str, local["cli_id"]) if local is not None else scoped_identity
        raw_identity_hash = local.get("identity_hash") if local is not None else None
        state = cast(str, item["state"])
        status = "pending_observation"
        reason = "local_identity_not_observed"
        if stale:
            status, reason = "stale", "cloud_observation_expired"
        elif local is not None and isinstance(raw_identity_hash, str):
            observation_preconditions[cli_id] = _observation_precondition(local)
            local_override = removals.get(cli_id)
            if _local_override_matches(
                local_override,
                identity_hash=raw_identity_hash,
                cloud_revision=revision,
            ):
                status, reason = "locally_overridden", "local_authority_preserved"
            elif state == "removed":
                authority_updates.append(_AuthorityUpdate(_identity_from_local(local), "unset", {}))
                status, reason = "removed", "signed_cloud_tombstone"
            elif _scoped_workspace_identity_hash(workspace_id, raw_identity_hash) != scoped_identity:
                status, reason = "changed_identity", "identity_mismatch"
            else:
                update = _plan_exact_settings(
                    store,
                    local=local,
                    settings={"state": state, "commands": {}},
                )
                if update is not None:
                    authority_updates.append(update)
                status, reason = "applied", "same_scoped_identity"
        evidence: dict[str, object] = {
            "workspace_identity_hash": scoped_identity,
            "cloud_revision": revision,
            "status": status,
            "reason": reason,
        }
        statuses[cli_id] = evidence
        events.append((f"custom_extension_continuity/{status}", evidence))
    state_payload: dict[str, object] = {
        "schema_version": CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2,
        "cloud_revision": revision,
        "observed_at": observation["observedAt"],
        "expires_at": observation["expiresAt"],
        "stale": stale,
        "observation_digest": digest,
        "items": statuses,
    }
    sync_payloads = {CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: state_payload}
    if not stale:
        sync_payloads[CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY] = state_payload
    try:
        _ = store.apply_custom_extension_continuity_transaction(
            expected_revision=store.read_local_cli_revision(),
            authority_updates=[(item.identity, item.state, item.commands) for item in authority_updates],
            sync_payloads=sync_payloads,
            events=events,
            updated_at=now,
            sync_preconditions={
                CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: previous,
                CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY: removals_raw,
            },
            observation_preconditions=observation_preconditions,
        )
    except ValueError as error:
        raise CustomExtensionContinuityError("local continuity authority changed during apply") from error
    return state_payload


def _preflight(
    store: GuardStore,
    *,
    payload: Mapping[str, object],
    now: str,
) -> _ContinuityPreflight:
    authority_revision = store.read_local_cli_revision()
    observation = _parse_observation(payload[CUSTOM_EXTENSION_CONTINUITY_FIELD])
    digest = hashlib.sha256(
        json.dumps(observation, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    previous = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    revision = cast(int, observation["revision"])
    _require_monotonic_observation(previous, revision=revision, digest=digest)
    local_items = {
        str(item["cli_id"]): item for item in store.list_local_cli_items() if isinstance(item.get("cli_id"), str)
    }
    removals_raw = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY)
    return _ContinuityPreflight(
        authority_revision=authority_revision,
        observation=observation,
        observation_digest=digest,
        previous=previous,
        stale=_timestamp(cast(str, observation["expiresAt"]), "expiry") <= _timestamp(now, "current time"),
        local_items=local_items,
        removals_raw=removals_raw,
        removals=dict(removals_raw) if isinstance(removals_raw, dict) else {},
        revision=revision,
    )


def _require_monotonic_observation(previous: object, *, revision: int, digest: str) -> None:
    if not isinstance(previous, dict) or type(previous.get("cloud_revision")) is not int:
        return
    previous_revision = cast(int, previous["cloud_revision"])
    if revision < previous_revision:
        raise CustomExtensionContinuityError("continuity revision cannot move backwards")
    previous_digest = previous.get("observation_digest")
    if revision == previous_revision and isinstance(previous_digest, str) and previous_digest != digest:
        raise CustomExtensionContinuityError("continuity revision payload changed")


def continuity_state_for_local_items(store: GuardStore, *, now: str) -> dict[str, dict[str, object]]:
    """Return path-free continuity state, becoming stale without a network request."""

    stored = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    if not isinstance(stored, dict):
        return {}
    raw_items = stored.get("items")
    expires_at = stored.get("expires_at")
    if not isinstance(raw_items, dict) or not isinstance(expires_at, str):
        return {}
    try:
        stale = _timestamp(expires_at, "expiry") <= _timestamp(now, "current time")
    except CustomExtensionContinuityError:
        return {}
    states: dict[str, dict[str, object]] = {}
    for cli_id, raw in raw_items.items():
        if not isinstance(cli_id, str) or not isinstance(raw, dict):
            continue
        public = {key: value for key, value in raw.items() if key in {"status", "reason", "cloud_revision", "surface"}}
        if stale and public.get("status") not in {"removed", "changed_identity"}:
            public["status"] = "stale"
            public["reason"] = "cloud_observation_expired"
        states[cli_id] = public
    return states


def record_local_custom_extension_mutation(
    store: GuardStore,
    *,
    identity: UnlistedCliIdentity,
    state: str,
    expected_revision: int,
    command_states: Mapping[str, LocalCliCommandState],
    now: str,
) -> int:
    """Commit a local grant and its continuity tombstone/state/receipt atomically."""

    raw = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY)
    active = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    removals = dict(raw) if isinstance(raw, dict) else {}
    local = next(
        (item for item in store.list_local_cli_items() if item.get("cli_id") == identity.cli_id),
        None,
    )
    sync_payloads: dict[str, Mapping[str, object]] = {}
    events: list[tuple[str, Mapping[str, object]]] = []
    revision = active.get("cloud_revision") if isinstance(active, dict) else 0
    removals[identity.cli_id] = {
        "identity_hash": identity.identity_hash,
        "cloud_revision": revision if type(revision) is int else 0,
        "state": state,
        "updated_at": now,
    }
    if state == "unset":
        updated_active = _updated_item_status(
            active,
            cli_id=identity.cli_id,
            status="removed",
            reason="removed_locally",
        )
        if updated_active is not None:
            sync_payloads[CUSTOM_EXTENSION_CONTINUITY_STATE_KEY] = updated_active
        events.append(
            (
                "custom_extension_continuity/removed",
                {
                    "cli_id": identity.cli_id,
                    "identity_hash": identity.identity_hash,
                    "status": "removed",
                    "reason": "removed_locally",
                },
            )
        )
    else:
        updated_active = _updated_item_status(
            active,
            cli_id=identity.cli_id,
            status="locally_overridden",
            reason="local_authority_preserved",
        )
        if updated_active is not None:
            sync_payloads[CUSTOM_EXTENSION_CONTINUITY_STATE_KEY] = updated_active
        events.append(
            (
                "custom_extension_continuity/locally_overridden",
                {
                    "cli_id": identity.cli_id,
                    "identity_hash": identity.identity_hash,
                    "status": "locally_overridden",
                    "reason": "local_authority_preserved",
                },
            )
        )
    sync_payloads[CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY] = removals
    try:
        return store.apply_custom_extension_continuity_transaction(
            expected_revision=expected_revision,
            authority_updates=[(identity, state, command_states)],
            sync_payloads=sync_payloads,
            events=events,
            updated_at=now,
            sync_preconditions={
                CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: active,
                CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY: raw,
            },
            observation_preconditions={identity.cli_id: _observation_precondition(local)},
        )
    except ValueError as error:
        if str(error) == "local_cli_revision_conflict":
            raise
        raise CustomExtensionContinuityError("local continuity state changed during local mutation") from error


def _parse_observation(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _TOP_LEVEL_FIELDS:
        raise CustomExtensionContinuityError("continuity observation contains unsupported fields")
    if value.get("schemaVersion") != CUSTOM_EXTENSION_CONTINUITY_SCHEMA:
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
        cli_id = raw_item.get("cliId")
        identity_hash = raw_item.get("identityHash")
        if not isinstance(cli_id, str) or not is_local_cli_id(cli_id) or cli_id in seen:
            raise CustomExtensionContinuityError("invalid or duplicate continuity identity")
        if not isinstance(identity_hash, str) or len(identity_hash) != 64 or any(c not in _HEX for c in identity_hash):
            raise CustomExtensionContinuityError("invalid continuity identity hash")
        seen.add(cli_id)
        items.append({"cliId": cli_id, "identityHash": identity_hash, "settings": _settings(raw_item.get("settings"))})
    return {**value, "items": items}


def _parse_v2_observation(value: object) -> dict[str, object]:
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
        if not isinstance(raw_item, dict) or set(raw_item) != _V2_ITEM_FIELDS:
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


def _scoped_workspace_identity_hash(workspace_id: str, local_identity_hash: str) -> str:
    material = f"{CUSTOM_EXTENSION_CONTINUITY_SCHEMA}:{workspace_id}:{local_identity_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _scoped_device_identity_hash(workspace_id: str, device_id: str) -> str:
    material = f"{CUSTOM_EXTENSION_CONTINUITY_SCHEMA}:device:{workspace_id}:{device_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _prior_local_item(previous: object, *, scoped_identity: str) -> str | None:
    if not isinstance(previous, dict) or not isinstance(previous.get("items"), dict):
        return None
    for cli_id, item in cast(dict[str, object], previous["items"]).items():
        if isinstance(item, dict) and item.get("workspace_identity_hash") == scoped_identity:
            return cli_id
    return None


def _identity_from_local(local: dict[str, object]) -> UnlistedCliIdentity:
    kind = local.get("kind")
    if kind not in {"executable", "script"}:
        raise CustomExtensionContinuityError("local continuity identity kind is invalid")
    return UnlistedCliIdentity(
        cli_id=cast(str, local["cli_id"]),
        name=cast(str, local["name"]),
        kind=cast(LocalCliKind, kind),
        identity_hash=cast(str, local["identity_hash"]),
        example_label=cast(str, local["example_label"]),
        interpreter_name=cast(str | None, local.get("interpreter_name")),
    )


def _settings(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _SETTINGS_FIELDS:
        raise CustomExtensionContinuityError("continuity settings contain unsupported fields")
    state = value.get("state")
    if state not in {"allowed", "blocked"}:
        raise CustomExtensionContinuityError("invalid continuity setting")
    commands = value.get("commands")
    if not isinstance(commands, dict) or len(commands) > MAX_LOCAL_CLI_COMMANDS:
        raise CustomExtensionContinuityError("invalid continuity command settings")
    parsed: dict[str, LocalCliCommandState] = {}
    for command_id, command_state in commands.items():
        if not isinstance(command_id, str) or not is_local_cli_command_id(command_id):
            raise CustomExtensionContinuityError("invalid continuity command identity")
        if command_state not in {"inherit", "allow", "block"}:
            raise CustomExtensionContinuityError("invalid continuity command setting")
        parsed[command_id] = cast(LocalCliCommandState, command_state)
    return {"state": state, "commands": parsed}


def _plan_exact_settings(
    store: GuardStore,
    *,
    local: dict[str, object],
    settings: dict[str, object],
) -> _AuthorityUpdate | None:
    cli_id = cast(str, local["cli_id"])
    catalog_ids = {command.command_id for command in store.read_local_cli_command_catalog(cli_id)}
    commands = cast(dict[str, LocalCliCommandState], settings["commands"])
    if not set(commands) <= catalog_ids:
        raise CustomExtensionContinuityError("continuity settings reference an unobserved command")
    kind = local.get("kind")
    if kind not in {"executable", "script"}:
        raise CustomExtensionContinuityError("local continuity identity kind is invalid")
    identity = UnlistedCliIdentity(
        cli_id=cli_id,
        name=cast(str, local["name"]),
        kind=cast(LocalCliKind, kind),
        identity_hash=cast(str, local["identity_hash"]),
        example_label=cast(str, local["example_label"]),
        interpreter_name=cast(str | None, local.get("interpreter_name")),
    )
    current = store.read_local_cli_grant(cli_id)
    current_commands = store.read_local_cli_command_states(cli_id)
    if (
        current is not None
        and current.get("identity_hash") == identity.identity_hash
        and current.get("state") == settings["state"]
        and current_commands == commands
    ):
        return None
    return _AuthorityUpdate(identity, cast(str, settings["state"]), commands)


def _mark_cloud_removed(store: GuardStore, *, now: str) -> dict[str, object]:
    previous = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    if not isinstance(previous, dict):
        return {}
    raw_items = previous.get("items")
    items: dict[str, object] = {}
    if isinstance(raw_items, dict):
        for cli_id, raw in raw_items.items():
            if isinstance(cli_id, str) and isinstance(raw, dict):
                item = dict(raw)
                item.update({"status": "removed", "reason": "removed_from_cloud_observation"})
                items[cli_id] = item
    events = [
        (
            "custom_extension_continuity/removed",
            {"cli_id": cli_id, "status": "removed", "reason": "removed_from_cloud_observation"},
        )
        for cli_id in items
    ]
    state = {**previous, "items": items, "stale": False}
    try:
        _ = store.apply_custom_extension_continuity_transaction(
            expected_revision=store.read_local_cli_revision(),
            authority_updates=[],
            sync_payloads={CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: state},
            events=events,
            updated_at=now,
            sync_preconditions={CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: previous},
        )
    except ValueError as error:
        raise CustomExtensionContinuityError("local continuity state changed during Cloud removal") from error
    return state


def _updated_item_status(
    active: object,
    *,
    cli_id: str,
    status: str,
    reason: str,
) -> dict[str, object] | None:
    if not isinstance(active, dict) or not isinstance(active.get("items"), dict):
        return None
    items = dict(cast(dict[str, object], active["items"]))
    current = items.get(cli_id)
    if isinstance(current, dict):
        items[cli_id] = {**current, "status": status, "reason": reason}
        return {**active, "items": items}
    return None


def _local_override_matches(value: object, *, identity_hash: str, cloud_revision: int) -> bool:
    return (
        isinstance(value, dict)
        and value.get("identity_hash") == identity_hash
        and type(value.get("cloud_revision")) is int
        and cast(int, value["cloud_revision"]) >= cloud_revision
    )


def _observation_precondition(local: dict[str, object] | None) -> dict[str, object] | None:
    if local is None or type(local.get("observed_count")) is not int or cast(int, local["observed_count"]) < 1:
        return None
    raw_commands = local.get("commands")
    command_ids: list[str] = []
    if isinstance(raw_commands, list):
        for command in raw_commands:
            if isinstance(command, dict) and isinstance(command.get("command_id"), str):
                command_ids.append(cast(str, command["command_id"]))
    return {
        "identity_hash": local.get("identity_hash"),
        "kind": local.get("kind"),
        "name": local.get("name"),
        "interpreter_name": local.get("interpreter_name"),
        "example_label": local.get("example_label"),
        "observed_count": local.get("observed_count"),
        "surface": local.get("surface"),
        "command_ids": command_ids,
    }


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CustomExtensionContinuityError(f"invalid continuity {label}") from error
    if parsed.tzinfo is None:
        raise CustomExtensionContinuityError(f"continuity {label} must include a timezone")
    return parsed.astimezone(timezone.utc)
