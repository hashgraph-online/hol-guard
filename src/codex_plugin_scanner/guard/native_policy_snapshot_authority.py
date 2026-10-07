"""Read a native combined authority record without relaxing its retained floor."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import cast

from .native_business_policy_floor import (
    business_binding_matches_floor,
    native_policy_authority_fields,
    native_policy_authority_floor_mac,
)
from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _valid_digest_v3
from .native_policy_snapshot_constants import _MAX_GENERATION, NativePolicySnapshotError


def _authority_snapshot_v3(
    value: Mapping[str, object],
    payload: bytes,
    verifier_key: bytes,
) -> dict[str, object]:
    """Return the nested snapshot from a rust-accepted authority record."""

    from .native_policy_snapshot_storage import _snapshot_api

    api = _snapshot_api()
    generation_floor = value.get("generation_floor")
    policy_digest = value.get("policy_digest")
    floor_mac = value.get("floor_mac")
    snapshot = value.get("snapshot")
    fields = native_policy_authority_fields(value, "native_policy_snapshot_cache_invalid")
    if (
        set(value) != fields
        or _canonical_json_bytes_v3(value) != payload
        or isinstance(generation_floor, bool)
        or not isinstance(generation_floor, int)
        or not 1 <= generation_floor <= _MAX_GENERATION
        or not _valid_digest_v3(policy_digest)
        or not _valid_digest_v3(floor_mac)
        or not isinstance(snapshot, dict)
        or snapshot.get("generation") != generation_floor
        or snapshot.get("policy_digest") != policy_digest
        or not hmac.compare_digest(
            cast(str, floor_mac),
            native_policy_authority_floor_mac(
                generation_floor,
                cast(str, policy_digest),
                value.get("command_control_floor"),
                value.get("business_policy_floor"),
                verifier_key,
            ),
        )
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    api._validate_snapshot_v3(snapshot)
    if not business_binding_matches_floor(snapshot, value.get("business_policy_floor")):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    integrity = snapshot.get("integrity")
    if not isinstance(integrity, Mapping) or not hmac.compare_digest(
        cast(str, integrity.get("mac")),
        api._snapshot_integrity_mac_v3(snapshot, verifier_key),
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_integrity_invalid")
    return cast(dict[str, object], snapshot)
