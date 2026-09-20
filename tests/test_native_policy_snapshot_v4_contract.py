"""Complete scoped snapshots bind exact source and effective policy identities."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_authority_contract import NativePolicyAuthorityCapabilities
from codex_plugin_scanner.guard.native_policy_authority_decode import native_policy_authority_from_mapping
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_v4 import (
    INTEGRITY_DOMAIN,
    build_policy_snapshot_v4,
    snapshot_bytes_v4,
    snapshot_signing_bytes_v4,
    validate_snapshot_v4,
    verify_snapshot_v4,
)
from tests.native_policy_snapshot_test_fixtures import _config

_VECTOR = Path(__file__).parents[1] / "contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"


def _fixture():
    return json.loads(_VECTOR.read_text())


def test_shared_vector_matches_actual_python_builder():
    fixture = _fixture()
    expected = fixture["snapshot"]
    authority = native_policy_authority_from_mapping(expected["scoped_authority"])
    capabilities = NativePolicyAuthorityCapabilities(
        4, frozenset({"policy-scoped-authority-v1", "policy-managed-authority-v1"}), authority.managed.catalog_digest
    )
    snapshot = build_policy_snapshot_v4(
        config=_config(),
        guard_home=Path("/synthetic/guard"),
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=bytes.fromhex(fixture["verifierKeyHex"]),
        generation=7,
        authority=authority,
        capabilities=capabilities,
        source_input_digest="d" * 64,
        issued_at_ms=1000,
        expires_at_ms=2000,
    )
    assert snapshot == expected
    signing = snapshot_signing_bytes_v4(snapshot)
    assert hashlib.sha256(signing).hexdigest() == fixture["signingBytesSha256"]
    assert (
        hmac.new(bytes.fromhex(fixture["verifierKeyHex"]), INTEGRITY_DOMAIN + signing, hashlib.sha256).hexdigest()
        == snapshot["integrity"]["mac"]
    )
    assert json.loads(snapshot_bytes_v4(snapshot)) == expected


@pytest.mark.parametrize(
    "field", ["scoped_authority", "source_input_digest", "policy_digest", "runtime_identity", "integrity"]
)
def test_required_snapshot_fields_cannot_be_omitted(field):
    snapshot = _fixture()["snapshot"]
    del snapshot[field]
    with pytest.raises(NativePolicySnapshotError):
        validate_snapshot_v4(snapshot)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda snapshot: snapshot.update(source_input_digest="e" * 64),
        lambda snapshot: snapshot["scoped_authority"]["rows"][0].update(action="allow"),
        lambda snapshot: snapshot["effective_policy"].update(default_action="allow"),
        lambda snapshot: snapshot.update(version=True),
        lambda snapshot: snapshot.update(version=3),
        lambda snapshot: snapshot.update(extra="ignored"),
    ],
)
def test_snapshot_changes_are_rejected(mutate):
    snapshot = _fixture()["snapshot"]
    mutate(snapshot)
    with pytest.raises(NativePolicySnapshotError):
        validate_snapshot_v4(snapshot)


@pytest.mark.parametrize(
    "field", ["artifact_id", "artifact_hash", "workspace", "publisher", "expires_at_ms", "requires_exact_context"]
)
def test_nullable_authority_fields_are_required(field):
    snapshot = _fixture()["snapshot"]
    del snapshot["scoped_authority"]["rows"][0][field]
    with pytest.raises(NativePolicySnapshotError):
        validate_snapshot_v4(snapshot)


@pytest.mark.parametrize(
    "version,features", [(3, frozenset()), (4, frozenset()), (4, frozenset({"policy-scoped-authority-v1"}))]
)
def test_snapshot_builder_refuses_unadvertised_authority(version, features):
    fixture = _fixture()
    authority = native_policy_authority_from_mapping(fixture["snapshot"]["scoped_authority"])
    with pytest.raises(NativePolicySnapshotError):
        build_policy_snapshot_v4(
            config=_config(),
            guard_home=Path("/synthetic/guard"),
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            verifier_key=bytes.fromhex(fixture["verifierKeyHex"]),
            generation=7,
            authority=authority,
            capabilities=NativePolicyAuthorityCapabilities(version, features),
            source_input_digest="d" * 64,
            issued_at_ms=1000,
            expires_at_ms=2000,
        )


@pytest.mark.parametrize("change", ["mac", "key", "runtime", "rules", "generation", "expired"])
def test_persisted_snapshot_revalidates_every_authority_fence(change):
    fixture = _fixture()
    snapshot = fixture["snapshot"]
    verification = {
        "verifier_key": bytes.fromhex(fixture["verifierKeyHex"]),
        "expected_runtime_identity": "a" * 64,
        "expected_rule_digest": "b" * 64,
        "minimum_generation": 7,
        "now_ms": 1500,
    }
    verify_snapshot_v4(snapshot, **verification)
    if change == "mac":
        snapshot["integrity"]["mac"] = "0" * 64
    else:
        key, value = {
            "key": ("verifier_key", b"x" * 32),
            "runtime": ("expected_runtime_identity", "e" * 64),
            "rules": ("expected_rule_digest", "e" * 64),
            "generation": ("minimum_generation", 8),
            "expired": ("now_ms", 2000),
        }[change]
        verification[key] = value
    with pytest.raises(NativePolicySnapshotError):
        verify_snapshot_v4(snapshot, **verification)
