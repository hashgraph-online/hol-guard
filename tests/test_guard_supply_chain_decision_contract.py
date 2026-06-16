"""Contract tests for canonical supply-chain decision evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.contracts.supply_chain_decision_evidence_v1 import (
    DECISION_EVIDENCE_CONTRACT_VERSION,
    cloud_evaluate_response_to_decision_evidence_v1,
    package_evaluation_to_decision_evidence_v1,
    validate_decision_evidence_v1,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
    _evidence_id,
)

WORKSPACE_ID = "11111111-1111-4111-8111-111111111111"


def _sample_evaluation() -> PackageRequestEvaluation:
    package = {
        "decision": "block",
        "ecosystem": "npm",
        "name": "minimist",
        "namespace": None,
        "requestedVersion": "1.2.8",
        "resolvedVersion": "1.2.8",
        "reasons": (
            {
                "code": "known_advisory",
                "message": "Prototype pollution in minimist",
                "severity": "critical",
                "source": "ghsa",
            },
        ),
    }
    package_intent_hash = "intent-hash-1"
    return PackageRequestEvaluation(
        decision="block",
        policy_action="block",
        enforcement="premium_cloud",
        entitlement_state="premium",
        cache_status="miss",
        package_intent_hash=package_intent_hash,
        policy_version="policy-hash-1",
        bundle_version="bundle-v1",
        workspace_fingerprint="workspace-fingerprint-1",
        reasons=package["reasons"],
        packages=(package,),
        risk_summary="minimist needs a safer version before you continue.",
        user_copy=SupplyChainUserCopy(
            title="Critical install blocked",
            summary="minimist needs a safer version before you continue.",
            next_step="npm install minimist@1.2.9",
            dashboard_url=None,
            harness_message="HOL Guard blocked minimist@1.2.8.",
        ),
        evidence_ids=(_evidence_id(package_intent_hash, package),),
    )


def test_decision_evidence_validation_reports_missing_fields_once() -> None:
    errors = validate_decision_evidence_v1({})
    assert errors.count("missing field: decision") == 1
    assert "invalid decision: None" not in errors


def test_cloud_evaluate_response_handles_null_reason_and_evidence_lists() -> None:
    payload = cloud_evaluate_response_to_decision_evidence_v1(
        {
            "decision": "monitor",
            "recommendation": "monitor",
            "enforcement": "premium_cloud",
            "entitlementState": "premium",
            "cacheStatus": "miss",
            "policyVersion": "policy-hash-1",
            "reasons": None,
            "evidenceIds": None,
        },
        package_intent_hash="intent-hash-1",
        command_shape={
            "argCount": 1,
            "flags": [],
            "packageManager": "npm",
            "redacted": True,
            "verb": "install",
        },
    )

    assert payload["reasons"] == []
    assert payload["evidenceIds"] == []


def test_decision_evidence_contract_schema_accepts_shared_fields() -> None:
    command_shape = {
        "argCount": 3,
        "flags": [],
        "packageManager": "npm",
        "redacted": True,
        "verb": "install",
    }
    payload = package_evaluation_to_decision_evidence_v1(
        _sample_evaluation(),
        command_shape=command_shape,
        package_intent_hash="intent-hash-1",
    )

    assert payload["contractVersion"] == DECISION_EVIDENCE_CONTRACT_VERSION
    assert validate_decision_evidence_v1(payload) == []


def test_package_evaluation_aligns_with_cloud_evaluate_response_shape() -> None:
    command_shape = {
        "argCount": 3,
        "flags": [],
        "packageManager": "npm",
        "redacted": True,
        "verb": "install",
    }
    cloud_response = {
        "cacheStatus": "miss",
        "decision": "block",
        "enforcement": "premium_cloud",
        "entitlementState": "premium",
        "evidenceIds": ["evidence-abc"],
        "policyVersion": "policy-hash-1",
        "reasons": [
            {
                "code": "known_advisory",
                "message": "Prototype pollution in minimist",
                "severity": "critical",
                "source": "ghsa",
            }
        ],
        "recommendation": "block",
    }
    local_payload = package_evaluation_to_decision_evidence_v1(
        _sample_evaluation(),
        command_shape=command_shape,
        package_intent_hash="intent-hash-1",
    )
    cloud_payload = cloud_evaluate_response_to_decision_evidence_v1(
        cloud_response,
        package_intent_hash="intent-hash-1",
        command_shape=command_shape,
    )

    shared_keys = {
        "contractVersion",
        "decision",
        "recommendation",
        "enforcement",
        "entitlementState",
        "cacheStatus",
        "policyVersion",
        "packageIntentHash",
        "commandShape",
        "reasons",
        "evidenceIds",
    }
    assert shared_keys.issubset(local_payload.keys())
    assert shared_keys.issubset(cloud_payload.keys())
    for key in shared_keys - {"evidenceIds", "reasons"}:
        assert local_payload[key] == cloud_payload[key]


def test_evidence_id_stability_across_local_conversion() -> None:
    evaluation = _sample_evaluation()
    package = evaluation.packages[0]
    converted = package_evaluation_to_decision_evidence_v1(
        evaluation,
        command_shape={"argCount": 1, "flags": [], "packageManager": "npm", "redacted": True, "verb": "install"},
        package_intent_hash=evaluation.package_intent_hash,
    )

    assert converted["evidenceIds"] == [evaluation.evidence_ids[0]]
    assert converted["evidenceIds"][0] == _evidence_id(evaluation.package_intent_hash, package)


def test_redacted_command_shape_parity_matches_portal_contract_fields() -> None:
    portal_contract_path = (
        Path(__file__).resolve().parents[3]
        / "hol-points-portal"
        / "src"
        / "lib"
        / "guard"
        / "contracts"
        / "v1"
        / "supply-chain.ts"
    )
    if not portal_contract_path.exists() and len(Path(__file__).resolve().parents) > 4:
        portal_contract_path = (
            Path(__file__).resolve().parents[4]
            / "hol-points-portal"
            / "src"
            / "lib"
            / "guard"
            / "contracts"
            / "v1"
            / "supply-chain.ts"
        )
    if not portal_contract_path.exists():
        pytest.skip("hol-points-portal contract file not found")
    contract_text = portal_contract_path.read_text(encoding="utf-8")
    for field in ("argCount", "flags", "packageManager", "redacted", "verb"):
        assert field in contract_text

    command_shape = {
        "argCount": 4,
        "flags": ["--save-dev"],
        "packageManager": "npm",
        "redacted": True,
        "verb": "install",
    }
    payload = package_evaluation_to_decision_evidence_v1(
        _sample_evaluation(),
        command_shape=command_shape,
        package_intent_hash="intent-hash-1",
    )
    assert payload["commandShape"] == command_shape
    assert json.dumps(payload["commandShape"], sort_keys=True)
