"""Managed origin bytes participate in V4 negotiation, digest, and authentication."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.native_managed_configuration import (
    MANAGED_CONFIGURATION_FEATURE,
    project_managed_configuration,
)
from codex_plugin_scanner.guard.native_policy_authority_contract import NativePolicyAuthorityCapabilities
from codex_plugin_scanner.guard.native_policy_authority_decode import native_policy_authority_from_mapping
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_v4 import (
    policy_digest_v4,
    snapshot_signing_bytes_v4,
    verify_snapshot_v4,
)
from tests.test_managed_action_origin import loaded

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"
FIXTURE = BASE.with_name("managed-configuration-vector.json")


def generated(tmp_path: Path) -> dict[str, object]:
    vector = json.loads(BASE.read_text())
    old = vector["snapshot"]
    config = loaded(
        tmp_path,
        '[harness_risk_actions.codex]\nlocal_secret_read="allow"\n',
        {"risk_actions": {"local_secret_read": "block"}},
    )
    origin = project_managed_configuration(config)
    assert origin is not None
    authority = replace(native_policy_authority_from_mapping(old["scoped_authority"]), managed_config=origin)
    assert authority.managed is not None
    caps = NativePolicyAuthorityCapabilities(
        4,
        frozenset({"policy-scoped-authority-v1", "policy-managed-authority-v1", MANAGED_CONFIGURATION_FEATURE}),
        authority.managed.catalog_digest,
    )
    # Preserve the existing cross-platform synthetic scope vector; only the
    # genuinely projected managed source is added before normal V4 signing.
    snapshot = deepcopy(old)
    snapshot["scoped_authority"] = authority.for_snapshot(caps)
    snapshot["policy_digest"] = policy_digest_v4(snapshot)
    import hashlib
    import hmac

    from codex_plugin_scanner.guard.native_policy_snapshot_v4 import INTEGRITY_DOMAIN

    snapshot["integrity"]["mac"] = hmac.new(
        bytes.fromhex(vector["verifierKeyHex"]),
        INTEGRITY_DOMAIN + snapshot_signing_bytes_v4(snapshot),
        hashlib.sha256,
    ).hexdigest()
    import hashlib

    return {
        "snapshot": snapshot,
        "verifierKeyHex": vector["verifierKeyHex"],
        "signingBytesSha256": hashlib.sha256(snapshot_signing_bytes_v4(snapshot)).hexdigest(),
    }


def check(snapshot: dict[str, object], key: bytes) -> None:
    verify_snapshot_v4(
        snapshot,
        verifier_key=key,
        expected_runtime_identity="a" * 64,
        expected_rule_digest="b" * 64,
        minimum_generation=7,
        now_ms=1500,
    )


def test_actual_projection_matches_shared_rust_fixture(tmp_path: Path) -> None:
    assert generated(tmp_path) == json.loads(FIXTURE.read_text())


def test_omission_preserves_original_authenticated_bytes() -> None:
    import hashlib

    vector = json.loads(BASE.read_text())
    snapshot = vector["snapshot"]
    assert "managed_config" not in snapshot["scoped_authority"]
    assert hashlib.sha256(snapshot_signing_bytes_v4(snapshot)).hexdigest() == vector["signingBytesSha256"]
    check(snapshot, bytes.fromhex(vector["verifierKeyHex"]))


def test_origin_requires_its_exact_feature() -> None:
    vector = json.loads(FIXTURE.read_text())
    authority = native_policy_authority_from_mapping(vector["snapshot"]["scoped_authority"])
    assert authority.managed is not None
    with pytest.raises(NativePolicySnapshotError, match="capability_unsupported"):
        authority.for_snapshot(
            NativePolicyAuthorityCapabilities(
                4,
                frozenset({"policy-scoped-authority-v1", "policy-managed-authority-v1"}),
                authority.managed.catalog_digest,
            )
        )


@pytest.mark.parametrize("change", ["remove", "source", "policy", "mode", "presence"])
def test_origin_removal_and_substitution_never_reuse_authentication(change: str) -> None:
    vector = json.loads(FIXTURE.read_text())
    snapshot = vector["snapshot"]
    key = bytes.fromhex(vector["verifierKeyHex"])
    check(snapshot, key)
    managed = snapshot["scoped_authority"]["managed_config"]
    if change == "remove":
        del snapshot["scoped_authority"]["managed_config"]
    elif change == "source":
        managed["source_digest"] = "f" * 64
    elif change == "policy":
        managed["effective_policy"]["risk_actions"]["local_secret_read"] = "allow"
    elif change == "presence":
        managed["default_action_present"] = True
    else:
        managed["mode"] = "observe"
    with pytest.raises(NativePolicySnapshotError):
        check(snapshot, key)
    snapshot["policy_digest"] = policy_digest_v4(snapshot)
    with pytest.raises(NativePolicySnapshotError):
        check(snapshot, key)


@pytest.mark.parametrize("value", [None, {}, {"schema": "future"}])
def test_present_extension_cannot_decode_as_absent(value: object) -> None:
    vector = json.loads(BASE.read_text())
    authority = deepcopy(vector["snapshot"]["scoped_authority"])
    authority["managed_config"] = value
    with pytest.raises(NativePolicySnapshotError):
        native_policy_authority_from_mapping(cast(object, authority))
