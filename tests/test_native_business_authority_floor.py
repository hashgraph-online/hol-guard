"""A hook binding must agree with the authenticated native retained floor."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as api
from codex_plugin_scanner.guard.native_business_policy_floor import native_policy_authority_floor_mac
from codex_plugin_scanner.guard.native_policy_snapshot_authority import _authority_snapshot_v3
from codex_plugin_scanner.guard.native_policy_snapshot_codec import _canonical_json_bytes_v3, _digest_v3


@pytest.mark.parametrize("case", ["matching", "mismatched", "omitted-binding", "null-floor"])
def test_authenticated_record_requires_matching_business_binding(
    tmp_path: Path,
    native_hook_force: Path,
    case: str,
) -> None:
    binding = {"schema": "guard.native-business-policy.v1", "version": 1, "defaultAction": "block", "rules": []}
    key = b"k" * 32
    snapshot = api.build_policy_snapshot_v3(
        config={},
        guard_home=tmp_path,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=key,
        generation=1,
        issued_at_ms=100,
        expires_at_ms=1000,
        business_policy=None if case == "omitted-binding" else binding,
    )
    floor = "f" * 64 if case == "mismatched" else None if case == "null-floor" else _digest_v3(binding)
    record = {
        "schema": "guard-policy-snapshot-authority.v3",
        "generation_floor": 1,
        "policy_digest": snapshot["policy_digest"],
        "snapshot": snapshot,
        "business_policy_floor": floor,
        "floor_mac": native_policy_authority_floor_mac(1, snapshot["policy_digest"], None, floor, key),
    }
    # Both snapshot and floor MAC are valid. Coherence is a separate requirement.
    if case == "matching":
        assert _authority_snapshot_v3(record, _canonical_json_bytes_v3(record), key) == snapshot
    else:
        with pytest.raises(api.NativePolicySnapshotError, match="cache_invalid"):
            _authority_snapshot_v3(record, _canonical_json_bytes_v3(record), key)
