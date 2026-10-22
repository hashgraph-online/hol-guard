"""Apply signed Cloud custom-Extension settings to exact local identities only.

The native runtime validates the signed observation (v1 or the device-bound
v2), checks it is monotonic, and answers the whole commit: every authority
update, receipt and continuity state, which sync-state records are written, the
protected-authority and capability requirements, and the observation guard each
update carries. Python only reads the store snapshot the plan needs, checks the
shape of the answer, and runs the commit in one store transaction. When the
resident cannot answer, nothing is applied: preparing and local mutations raise
``CustomExtensionContinuityError`` and the public state reads as empty.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, cast

from ..native_context import _resolve_digest_home, native_context_digest
from ..store_custom_extension_continuity import CustomExtensionContinuityMutation
from ..store_local_cli_capabilities import LocalCliCapabilityError
from .local_cli_commands import LocalCliCommand, LocalCliCommandState
from .local_cli_identity import LocalCliKind, UnlistedCliIdentity

if TYPE_CHECKING:
    from ..store import GuardStore

CUSTOM_EXTENSION_CONTINUITY_FIELD = "x-hol-custom-extension-continuity"
CUSTOM_EXTENSION_CONTINUITY_SCHEMA = "guard.custom-extension-continuity.v1"
CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2 = "guard.custom-extension-continuity.v2"
CUSTOM_EXTENSION_CONTINUITY_STATE_KEY = "custom_extension_continuity"
CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY = "custom_extension_continuity_last_good"
CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY = "custom_extension_continuity_local_removals"

_LOCAL_KEYS = ("identity_hash", "kind", "name", "example_label", "interpreter_name", "observed_count", "surface")
_PREPARE_KEYS = frozenset(
    {"error", "authority_updates", "events", "observation_preconditions", "writes", "requirements"}
)
_LOCAL_COMMIT_KEYS = frozenset({"writes", "event", "observation_precondition"})
_WRITE_KEYS = frozenset({"stores", "payload", "item_order"})
_REQUIREMENT_KEYS = frozenset({"protected_authority", "capability"})
# The resident names a record by role; each role is the sync-state key that holds it.
_STATE_KEYS = {
    "state": CUSTOM_EXTENSION_CONTINUITY_STATE_KEY,
    "last_good": CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY,
    "removals": CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY,
}
_PREPARE_ROLES = frozenset({"state", "last_good", "removals"})
_LOCAL_ROLES = frozenset({"state", "removals"})
_IDENTITY_KEYS = ("cli_id", "name", "kind", "identity_hash", "example_label", "interpreter_name")


class CustomExtensionContinuityError(ValueError):
    """The signed continuity observation cannot be applied safely."""


def apply_verified_custom_extension_continuity(
    store: GuardStore,
    validated_policy_bundle: Mapping[str, object],
    *,
    device_id: str | None = None,
    now: str,
) -> dict[str, object]:
    """Consume continuity only after the production caller verified the bundle signature."""

    mutation, state = prepare_verified_custom_extension_continuity(
        store,
        validated_policy_bundle,
        device_id=device_id,
        now=now,
    )
    if mutation is None:
        return state
    try:
        _ = store.apply_custom_extension_continuity_transaction(
            expected_revision=mutation.expected_revision,
            authority_updates=mutation.authority_updates,
            sync_payloads=mutation.sync_payloads,
            events=mutation.events,
            updated_at=mutation.updated_at,
            sync_preconditions=mutation.sync_preconditions,
            observation_preconditions=mutation.observation_preconditions,
        )
    except ValueError as error:
        raise CustomExtensionContinuityError("local continuity authority changed during apply") from error
    return state


def prepare_verified_custom_extension_continuity(
    store: GuardStore,
    validated_policy_bundle: Mapping[str, object],
    *,
    device_id: str | None = None,
    now: str,
) -> tuple[CustomExtensionContinuityMutation | None, dict[str, object]]:
    """Plan continuity natively without mutating persistent authority."""

    payload = validated_policy_bundle.get("payload")
    if not isinstance(payload, Mapping):
        raise CustomExtensionContinuityError("verified policy bundle payload is missing")
    if payload.get(CUSTOM_EXTENSION_CONTINUITY_FIELD) is None:
        previous = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
        return None, dict(previous) if isinstance(previous, dict) else {}
    authority_revision = store.read_local_cli_revision()
    previous = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    locals_ = [item for item in store.list_local_cli_items() if isinstance(item.get("cli_id"), str)]
    removals = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY)
    request: dict[str, object] = {
        "operation": "plan",
        "continuity": payload[CUSTOM_EXTENSION_CONTINUITY_FIELD],
        "workspace_id": validated_policy_bundle.get("workspaceId"),
        "device_id": device_id,
        "now": now,
        "previous": previous,
        "previous_item_order": _item_order(previous),
        "removals": removals,
        "locals": [_local_request(item) for item in locals_],
    }
    answer = _plan_with_details(store, request, {str(item["cli_id"]) for item in locals_})
    updates = answer["authority_updates"]
    events = answer["events"]
    observation_preconditions = answer["observation_preconditions"]
    if not isinstance(updates, list) or not isinstance(events, list) or not isinstance(observation_preconditions, dict):
        raise _malformed()
    for update in updates:
        cli_id = update.get("cli_id") if isinstance(update, dict) else None
        if not isinstance(cli_id, str) or observation_preconditions.get(cli_id) is None:
            raise _malformed()
    sync_payloads = _sync_payloads(answer["writes"], allowed=_PREPARE_ROLES, required="state")
    protected_authority, capability = _requirements(answer["requirements"])
    mutation = CustomExtensionContinuityMutation(
        expected_revision=authority_revision,
        authority_updates=tuple(_authority_update(update) for update in updates),
        sync_payloads=sync_payloads,
        events=tuple(_event(event) for event in events),
        updated_at=now,
        sync_preconditions={
            CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: previous,
            CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY: removals,
        },
        observation_preconditions=observation_preconditions,
        requires_protected_extension_authority=protected_authority,
        required_negotiated_capability=capability,
    )
    return mutation, sync_payloads[CUSTOM_EXTENSION_CONTINUITY_STATE_KEY]


def continuity_state_for_local_items(store: GuardStore, *, now: str) -> dict[str, dict[str, object]]:
    """Return path-free continuity state, becoming stale without a network request."""

    stored = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    if not isinstance(stored, dict):
        return {}
    try:
        answer = _native_continuity(
            store, {"operation": "public_state", "stored": stored, "now": now}, frozenset({"states"})
        )
    except CustomExtensionContinuityError:
        return {}
    states = answer["states"]
    if not isinstance(states, dict) or not all(isinstance(value, dict) for value in states.values()):
        return {}
    return cast(dict[str, dict[str, object]], states)


def record_local_custom_extension_mutation(
    store: GuardStore,
    *,
    identity: UnlistedCliIdentity,
    state: str,
    expected_revision: int,
    command_states: Mapping[str, LocalCliCommandState],
    now: str,
    provider_updates: Sequence[tuple[str, str, int]] = (),
    catalog_seed: Sequence[LocalCliCommand] = (),
    capabilities: Mapping[str, str] | None = None,
) -> int:
    """Commit a local grant and its continuity tombstone/state/receipt atomically.

    ``capabilities`` are the operator's ``{name: on|off}`` choices from the
    authority apply; signed continuity never carries them.
    """

    raw = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY)
    active = store.get_sync_payload(CUSTOM_EXTENSION_CONTINUITY_STATE_KEY)
    local = next(
        (item for item in store.list_local_cli_items() if item.get("cli_id") == identity.cli_id),
        None,
    )
    answer = _native_continuity(
        store,
        {
            "operation": "local_mutation",
            "cli_id": identity.cli_id,
            "identity_hash": identity.identity_hash,
            "state": state,
            "now": now,
            "active": active,
            "active_item_order": _item_order(active),
            "removals": raw,
            "local": None if local is None else _local_request(local),
        },
        _LOCAL_COMMIT_KEYS,
    )
    sync_payloads = _sync_payloads(answer["writes"], allowed=_LOCAL_ROLES, required="removals")
    try:
        return store.apply_custom_extension_continuity_transaction(
            expected_revision=expected_revision,
            authority_updates=[(identity, state, command_states)],
            sync_payloads=sync_payloads,
            events=[_event(answer["event"])],
            updated_at=now,
            sync_preconditions={
                CUSTOM_EXTENSION_CONTINUITY_STATE_KEY: active,
                CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY: raw,
            },
            observation_preconditions={identity.cli_id: answer["observation_precondition"]},
            provider_updates={identity.cli_id: provider_updates} if provider_updates else None,
            catalog_seeds={identity.cli_id: catalog_seed} if catalog_seed else None,
            capability_updates={identity.cli_id: capabilities} if capabilities else None,
        )
    except ValueError as error:
        if str(error) in {"local_cli_revision_conflict", "provider_action_revision_conflict"}:
            raise
        if isinstance(error, LocalCliCapabilityError):
            raise
        raise CustomExtensionContinuityError("local continuity state changed during local mutation") from error


def _native_continuity(
    store: GuardStore,
    request: dict[str, object],
    keys: frozenset[str],
    *,
    allow_need_details: bool = False,
) -> dict[str, object]:
    result = native_context_digest(
        "custom_extension_continuity",
        {"request": request},
        guard_home=_resolve_digest_home(store.guard_home),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise CustomExtensionContinuityError("native custom extension continuity unavailable")
    answer = result.get("custom_extension_continuity")
    if not isinstance(answer, dict):
        raise _malformed()
    refusal = answer.get("error")
    if refusal is not None:
        raise CustomExtensionContinuityError(refusal if isinstance(refusal, str) else "continuity refused")
    if allow_need_details and set(answer) == {"need_details"}:
        return answer
    if set(answer) != keys:
        raise _malformed()
    return answer


def _malformed() -> CustomExtensionContinuityError:
    return CustomExtensionContinuityError("native custom extension continuity answer is malformed")


def _local_request(item: Mapping[str, object]) -> dict[str, object]:
    commands = item.get("commands")
    return {
        "cli_id": item["cli_id"],
        **{key: item.get(key) for key in _LOCAL_KEYS},
        "command_ids": [command.get("command_id") for command in commands if isinstance(command, dict)]
        if isinstance(commands, list)
        else [],
    }


def _plan_with_details(store: GuardStore, request: dict[str, object], local_ids: set[str]) -> dict[str, object]:
    """Ask for a plan, loading grant and command details only for the locals it reads."""

    details: dict[str, object] = {}
    for _ in range(len(local_ids) + 1):
        answer = _native_continuity(store, {**request, "details": details}, _PREPARE_KEYS, allow_need_details=True)
        wanted = answer.get("need_details")
        if wanted is None:
            return answer
        if (
            not isinstance(wanted, list)
            or not wanted
            or not all(isinstance(cli_id, str) and cli_id in local_ids and cli_id not in details for cli_id in wanted)
        ):
            raise _malformed()
        details.update({cli_id: _detail_request(store, cli_id) for cli_id in wanted})
    raise _malformed()


def _detail_request(store: GuardStore, cli_id: str) -> dict[str, object]:
    grant = store.read_local_cli_grant(cli_id)
    return {
        "grant": None if grant is None else {"identity_hash": grant["identity_hash"], "state": grant["state"]},
        "command_states": store.read_local_cli_command_states(cli_id),
        "catalog_ids": [command.command_id for command in store.read_local_cli_command_catalog(cli_id)],
    }


def _item_order(payload: object) -> list[str]:
    if isinstance(payload, dict) and isinstance(payload.get("items"), dict):
        return [key for key in payload["items"] if isinstance(key, str)]
    return []


def _ordered_items(state: dict[str, object], order: object) -> dict[str, object]:
    """Restore the item order the native answer reports; its maps arrive sorted."""

    items = state.get("items")
    if (
        not isinstance(items, dict)
        or not isinstance(order, list)
        or not all(isinstance(key, str) for key in order)
        or len(order) != len(items)
        or set(order) != set(items)
    ):
        raise _malformed()
    return {**state, "items": {key: items[key] for key in order}}


def _sync_payloads(writes: object, *, allowed: frozenset[str], required: str) -> dict[str, dict[str, object]]:
    """Map the writes the native answer names onto the sync-state keys they are stored under."""

    if not isinstance(writes, list):
        raise _malformed()
    payloads: dict[str, dict[str, object]] = {}
    for write in writes:
        if not isinstance(write, dict) or set(write) != _WRITE_KEYS:
            raise _malformed()
        stores, payload, order = write["stores"], write["payload"], write["item_order"]
        if (
            not isinstance(stores, list)
            or not stores
            or not isinstance(payload, dict)
            or not all(isinstance(role, str) and role in allowed for role in stores)
            or len(set(stores)) != len(stores)
        ):
            raise _malformed()
        # The removals record is written alone and has no item order; every state record keeps one.
        removals_only = stores == ["removals"]
        if ("removals" in stores and not removals_only) or removals_only == (order is not None):
            raise _malformed()
        stored = payload if removals_only else _ordered_items(payload, order)
        for role in stores:
            if _STATE_KEYS[role] in payloads:
                raise _malformed()
            payloads[_STATE_KEYS[role]] = stored
    if _STATE_KEYS[required] not in payloads:
        raise _malformed()
    return payloads


def _requirements(requirements: object) -> tuple[bool, str | None]:
    if not isinstance(requirements, dict) or set(requirements) != _REQUIREMENT_KEYS:
        raise _malformed()
    protected_authority, capability = requirements["protected_authority"], requirements["capability"]
    if not isinstance(protected_authority, bool) or not (capability is None or isinstance(capability, str)):
        raise _malformed()
    return protected_authority, capability


def _authority_update(update: object) -> tuple[UnlistedCliIdentity, str, Mapping[str, LocalCliCommandState]]:
    if not isinstance(update, dict) or set(update) != {*_IDENTITY_KEYS, "state", "commands"}:
        raise _malformed()
    strings = ("cli_id", "name", "kind", "identity_hash", "example_label", "state")
    interpreter = update["interpreter_name"]
    if any(not isinstance(update[key], str) for key in strings) or not isinstance(update["commands"], dict):
        raise _malformed()
    if interpreter is not None and not isinstance(interpreter, str):
        raise _malformed()
    identity = UnlistedCliIdentity(
        cli_id=update["cli_id"],
        name=update["name"],
        kind=cast(LocalCliKind, update["kind"]),
        identity_hash=update["identity_hash"],
        example_label=update["example_label"],
        interpreter_name=interpreter,
    )
    return identity, update["state"], cast(Mapping[str, LocalCliCommandState], update["commands"])


def _event(event: object) -> tuple[str, Mapping[str, object]]:
    if (
        not isinstance(event, list)
        or len(event) != 2
        or not isinstance(event[0], str)
        or not isinstance(event[1], dict)
    ):
        raise _malformed()
    return event[0], event[1]
