from __future__ import annotations

from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument, policy_document_digest
from codex_plugin_scanner.guard.runtime.network_policy_contract import NETWORK_POLICY_SCHEMA_VERSION


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
    encoded = document.to_mapping()
    encoded_spec = encoded["spec"]
    assert isinstance(encoded_spec, dict)
    assert encoded_spec["networkPolicy"] == extension
    assert policy_document_digest(document) == policy_document_digest(GuardPolicyDocument.from_mapping(encoded))
