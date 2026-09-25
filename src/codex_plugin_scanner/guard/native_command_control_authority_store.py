"""Durable control revocation and explicit recovery, outside native hook work."""

from __future__ import annotations

import hmac
import os
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_command_control_authority import (
    AUTHORITY_FILE_NAME,
    AUTHORITY_MAX_BYTES,
    AUTHORITY_SCHEMA,
    MAX_REVISION,
    RECOVERY_SCHEMA,
    ZERO_DIGEST,
    authority_binding,
    authority_key_id,
    decode_authority,
    encode_authority,
    floor_link_digest,
    validate_control_floor,
)
from .native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
    read_private_state,
    require_command_control_mutation_lease,
    write_private_state,
)
from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _generation_floor_mac_v3,
    _strict_json_loads_v3,
    _valid_digest_v3,
    derive_native_policy_verifier_key,
)
from .native_policy_snapshot_constants import (
    _RUST_GENERATION_FLOOR_NAME,
    _RUST_SNAPSHOT_STATE_NAME,
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
    POLICY_SNAPSHOT_AUTHORITY_SCHEMA,
    NativePolicySnapshotError,
)

if TYPE_CHECKING:
    from .store import GuardStore


def _key(store: GuardStore) -> bytes:
    material = store._policy_integrity_secret_material(create=True)
    if material is None or not isinstance(material[0], bytes):
        raise NativePolicySnapshotError("native_command_control_authority_key_unavailable")
    return derive_native_policy_verifier_key(material[0])


def read_command_control_authority(store: GuardStore, verifier_key: bytes) -> dict[str, object] | None:
    content = read_private_state(store.guard_home, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)
    return None if content is None else decode_authority(content, verifier_key)


def _write(store: GuardStore, record: Mapping[str, object], verifier_key: bytes) -> dict[str, object]:
    content = encode_authority(record, verifier_key)
    write_private_state(store.guard_home, AUTHORITY_FILE_NAME, content, AUTHORITY_MAX_BYTES)
    observed = read_private_state(store.guard_home, AUTHORITY_FILE_NAME, AUTHORITY_MAX_BYTES)
    if content != observed:
        raise NativePolicySnapshotError("native_command_control_authority_write_mismatch")
    return decode_authority(content, verifier_key)


def read_native_control_floor(store: GuardStore, verifier_key: bytes) -> Mapping[str, object] | None:
    """Authenticate the persisted floor even when its expired snapshot is absent."""

    return read_native_control_floor_for_home(store.guard_home, verifier_key)


def _verify_legacy_generation_floor(guard_home: Path, verifier_key: bytes) -> None:
    """Match the resident's canonical GenerationFloorV1 validation contract."""

    content = read_private_state(guard_home, _RUST_GENERATION_FLOOR_NAME, 8 * 1024)
    if content is None:
        return
    record = _strict_json_loads_v3(content)
    if not isinstance(record, Mapping):
        raise NativePolicySnapshotError("native_command_control_recovery_floor_invalid")
    generation = record.get("generation")
    digest, mac = record.get("policy_digest"), record.get("mac")
    if (
        set(record) != {"schema", "generation", "policy_digest", "mac"}
        or record.get("schema") != "guard-policy-snapshot-generation-floor.v1"
        or type(generation) is not int
        or not 1 <= generation <= MAX_REVISION
        or not _valid_digest_v3(digest)
        or not _valid_digest_v3(mac)
        or _canonical_json_bytes_v3(record) != content
        or not hmac.compare_digest(
            cast(str, mac), _generation_floor_mac_v3(generation, cast(str, digest), verifier_key)
        )
    ):
        raise NativePolicySnapshotError("native_command_control_recovery_floor_invalid")


def read_native_control_floor_for_home(guard_home: Path, verifier_key: bytes) -> Mapping[str, object] | None:
    """Verify every retained floor without constructing a credential-bearing store."""

    from .native_command_control_binding import native_command_control_floor_mac

    _verify_legacy_generation_floor(guard_home, verifier_key)
    content = read_private_state(guard_home, _RUST_SNAPSHOT_STATE_NAME, POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES)
    if content is None:
        return None
    record = _strict_json_loads_v3(content)
    if not isinstance(record, Mapping) or record.get("schema") != POLICY_SNAPSHOT_AUTHORITY_SCHEMA:
        raise NativePolicySnapshotError("native_command_control_recovery_floor_invalid")
    fields = {"schema", "generation_floor", "policy_digest", "snapshot", "floor_mac"}
    if "command_control_floor" in record:
        fields.add("command_control_floor")
    generation = record.get("generation_floor")
    digest, mac = record.get("policy_digest"), record.get("floor_mac")
    floor = record.get("command_control_floor")
    if (
        set(record) != fields
        or type(generation) is not int
        or not 1 <= generation <= MAX_REVISION
        or not _valid_digest_v3(digest)
        or not _valid_digest_v3(mac)
        or _canonical_json_bytes_v3(record) != content
        or ("command_control_floor" in record and floor is None)
    ):
        raise NativePolicySnapshotError("native_command_control_recovery_floor_invalid")
    if not hmac.compare_digest(
        cast(str, mac), native_command_control_floor_mac(generation, cast(str, digest), floor, verifier_key)
    ):
        raise NativePolicySnapshotError("native_command_control_recovery_floor_invalid")
    return None if floor is None else validate_control_floor(floor)


def _floor_authority(floor: Mapping[str, object] | None) -> Mapping[str, object]:
    authority = floor.get("authority") if floor else None
    return authority if isinstance(authority, Mapping) else {}


def _next(value: object) -> int:
    if type(value) is not int or not 0 <= value < MAX_REVISION:
        raise NativePolicySnapshotError("native_command_control_authority_revision_exhausted")
    return value + 1


def _initial(store: GuardStore, verifier_key: bytes) -> dict[str, object]:
    floor = read_native_control_floor(store, verifier_key)
    prior = _floor_authority(floor)
    # Recreating a missing marker never lowers an authenticated native floor.
    return {
        "schema": AUTHORITY_SCHEMA,
        "epoch": prior.get("epoch", 1),
        "mutation_revision": _next(prior.get("mutation_revision", 0)),
        "authority_key_id": prior.get("authority_key_id", authority_key_id(store._authority_key(required=False))),
        "phase": "closed",
        "effective_digest": None,
        "recovery": prior.get("recovery"),
    }


def begin_native_command_control_mutation(store: GuardStore, *, explicit_recovery: bool = False) -> None:
    """Close every resident before effects; caller holds the exclusive OS lock."""

    require_command_control_mutation_lease(store.guard_home)
    state = store.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    if not any(os.path.lexists(state / name) for name in (AUTHORITY_FILE_NAME, NATIVE_POLICY_VERIFIER_KEY_NAME)):
        # No native authority has been armed. A future publisher must create
        # its first authenticated marker before a bound snapshot can be admitted.
        return
    verifier_key = _key(store)
    try:
        current = read_command_control_authority(store, verifier_key)
    except NativePolicySnapshotError:
        if not explicit_recovery:
            raise
        current = None
    if current is None:
        candidate = _initial(store, verifier_key)
    else:
        candidate = {
            **current,
            "mutation_revision": _next(current["mutation_revision"]),
            "phase": "closed",
            "effective_digest": None,
        }
    _write(store, candidate, verifier_key)


def begin_native_command_control_recovery(store: GuardStore, *, new_authority_key: bytes) -> None:
    """Link an authorized reset to the exact retained floor before resetting SQL."""

    require_command_control_mutation_lease(store.guard_home)
    state = store.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    if not any(os.path.lexists(state / name) for name in (AUTHORITY_FILE_NAME, NATIVE_POLICY_VERIFIER_KEY_NAME)):
        return
    verifier_key = _key(store)
    current = read_command_control_authority(store, verifier_key) or _initial(store, verifier_key)
    floor = read_native_control_floor(store, verifier_key)
    previous = _floor_authority(floor)
    recovery = {
        "schema": RECOVERY_SCHEMA,
        "previous_epoch": previous.get("epoch", 0),
        "previous_mutation_revision": previous.get("mutation_revision", 0),
        "previous_authority_key_id": previous.get("authority_key_id", ZERO_DIGEST),
        "previous_floor_digest": floor_link_digest(floor),
        "nonce": secrets.token_hex(32),
    }
    candidate = {
        **current,
        "epoch": _next(max(cast(int, current["epoch"]), cast(int, previous.get("epoch", 0)))),
        "mutation_revision": _next(
            max(cast(int, current["mutation_revision"]), cast(int, previous.get("mutation_revision", 0)))
        ),
        "phase": "closed",
        "effective_digest": None,
        "recovery": recovery,
        "authority_key_id": authority_key_id(new_authority_key),
    }
    _write(store, candidate, verifier_key)


def commit_native_command_control_projection(store: GuardStore, binding: Mapping[str, object]) -> dict[str, object]:
    """Finalize only a verified committed projection under the authority lock."""

    require_command_control_mutation_lease(store.guard_home)
    verifier_key = _key(store)
    current = read_command_control_authority(store, verifier_key)
    if current is None:
        current = _initial(store, verifier_key)
        # Persist closure before first publication; a crash cannot revive a
        # previously acknowledged snapshot whose old marker disappeared.
        current = _write(store, current, verifier_key)
    key_id = authority_key_id(store._authority_key(required=False))
    # Recovery selects and binds its new key before reset effects. Historical
    # recovery evidence never authorizes another key change in that epoch.
    if key_id != current["authority_key_id"] and current["authority_key_id"] != ZERO_DIGEST:
        raise NativePolicySnapshotError("native_command_control_authority_key_changed")
    candidate = {
        **current,
        "authority_key_id": key_id,
        "phase": "committed",
        "effective_digest": binding["effective_digest"],
    }
    if current["phase"] == "committed" and current["effective_digest"] != candidate["effective_digest"]:
        # A health/catalog change discovered by verification is still a new
        # fence; never reuse a committed fence for different effective bytes.
        candidate["mutation_revision"] = _next(current["mutation_revision"])
        _write(store, {**candidate, "phase": "closed", "effective_digest": None}, verifier_key)
    if candidate != current:
        candidate = _write(store, candidate, verifier_key)
    return authority_binding(candidate)


def read_committed_projection_authority(store: GuardStore, binding: Mapping[str, object]) -> dict[str, object]:
    """Read an unchanged committed marker without excluding native readers."""

    current = read_command_control_authority(store, _key(store))
    if (  # NOSONAR(S2583) A present authenticated marker can satisfy all retained checks.
        current is None  # NOSONAR(S2583) Missing markers require mutation; verified present markers return a dict.
        or current["phase"] != "committed"
        or current["effective_digest"] != binding["effective_digest"]
        or current["authority_key_id"] != authority_key_id(store._authority_key(required=False))
    ):
        raise NativeCommandControlMutationRequiredError()
    return authority_binding(current)
