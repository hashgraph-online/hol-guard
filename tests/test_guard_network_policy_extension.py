from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.policy_document import (
    NETWORK_POLICY_SCHEMA_VERSION,
    GuardPolicyDocument,
    guard_policy_network_extension,
    policy_document_digest,
)


def _mapping(network_policy: object | None = None) -> dict[str, object]:
    spec: dict[str, object] = {
        "defaults": {"mode": "enforce"},
        "rules": [],
    }
    if network_policy is not None:
        spec["networkPolicy"] = network_policy
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "policy.one", "name": "Policy One", "revision": 1},
        "spec": spec,
    }


def test_versioned_network_contract_round_trips_inside_guard_policy() -> None:
    extension = {
        "schemaVersion": NETWORK_POLICY_SCHEMA_VERSION,
        "policyId": "network.one",
        "generation": 1,
        "requiredGrade": "destination-enforced",
        "rules": [],
    }
    document = GuardPolicyDocument.from_mapping(_mapping(extension))
    assert guard_policy_network_extension(document) == extension
    encoded = document.to_mapping()
    encoded_spec = encoded["spec"]
    assert isinstance(encoded_spec, dict)
    assert encoded_spec["networkPolicy"] == extension
    assert policy_document_digest(document) == policy_document_digest(GuardPolicyDocument.from_mapping(encoded))


def test_legacy_guard_policy_remains_explicitly_compatible() -> None:
    document = GuardPolicyDocument.from_mapping(_mapping())
    assert guard_policy_network_extension(document) is None


def test_explicit_null_network_extension_is_rejected() -> None:
    mapping = _mapping()
    spec = mapping["spec"]
    assert isinstance(spec, dict)
    spec["networkPolicy"] = None
    document = GuardPolicyDocument.from_mapping(mapping)
    with pytest.raises(ValueError, match="networkPolicy must be an object"):
        guard_policy_network_extension(document)


@pytest.mark.parametrize(
    "extension",
    (
        "guard.network-policy.v1",
        {"schemaVersion": "guard.network-policy.v2"},
        {},
    ),
)
def test_network_extension_rejects_ambiguous_or_unknown_versions(extension: object) -> None:
    document = GuardPolicyDocument.from_mapping(_mapping(extension))
    with pytest.raises(ValueError, match=r"networkPolicy|schemaVersion"):
        guard_policy_network_extension(document)
