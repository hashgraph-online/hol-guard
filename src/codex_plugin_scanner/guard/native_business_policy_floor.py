"""Verify the native retained floor wire MAC; no business policy evaluation."""

from __future__ import annotations

from collections.abc import Mapping

from .native_command_control_binding import native_command_control_floor_mac
from .native_policy_snapshot_codec import _digest_v3, _generation_floor_mac_v3, _valid_digest_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError


def native_policy_authority_fields(record: Mapping[str, object], error: str) -> set[str]:
    fields = {"schema", "generation_floor", "policy_digest", "snapshot", "floor_mac"}
    if "command_control_floor" in record:
        if record["command_control_floor"] is None:
            raise NativePolicySnapshotError(error)
        fields.add("command_control_floor")
    if "business_policy_floor" in record:
        if not _valid_digest_v3(record["business_policy_floor"]):
            raise NativePolicySnapshotError(error)
        fields.add("business_policy_floor")
    return fields


def business_binding_matches_floor(snapshot: Mapping[str, object], floor: object) -> bool:
    # Wire identity equality only; business semantics remain native-owned.
    if floor is None:
        return True
    binding = snapshot.get("business_policy")
    return isinstance(binding, Mapping) and _valid_digest_v3(floor) and _digest_v3(binding) == floor


def native_policy_authority_floor_mac(
    generation: int,
    policy_digest: str,
    controls: object,
    business: object,
    verifier_key: bytes,
) -> str:
    base = native_command_control_floor_mac(generation, policy_digest, controls, verifier_key)
    if business is None:
        return base
    if not _valid_digest_v3(business):
        raise NativePolicySnapshotError("native_business_policy_floor_invalid")
    bound = f"guard-native-policy-business-floor.v1\0{base}\0{business}"
    return _generation_floor_mac_v3(generation, bound, verifier_key)
