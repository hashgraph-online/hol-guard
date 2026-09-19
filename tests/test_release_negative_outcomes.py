"""Release-gated fail-closed cases that must stay visible in default pytest collection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.contracts.guard_cloud_review import (
    load_fixtures,
    validate_review_result,
    validate_reviewability_case,
)
from codex_plugin_scanner.guard.policy_bundle_parser import (
    policy_bundle_is_enforceable,
    policy_bundle_is_version_downgrade,
    validated_policy_bundle_payload,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from scripts.ci.verify_installed_release_matrix import InstalledMatrixError, validate_matrix
from tests.policy_bundle_signing_helpers import (
    TEST_POLICY_BUNDLE_WORKSPACE_ID,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)
from tests.test_verify_installed_release_matrix import VERSION, _matrix, _validate

ROOT = Path(__file__).resolve().parents[1]
_VALIDATION_NOW = 1_784_419_200.0


def _unsigned_policy_bundle(*, rollout_state: str = "enforcing") -> dict[str, object]:
    return {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-07-18.1",
        "bundleHash": "",
        "issuedAt": "2026-07-18T00:00:00Z",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "replaced-by-signing-helper",
            "signature": None,
        },
        "rolloutState": rollout_state,
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [],
        "acknowledgements": [],
    }


@pytest.mark.release
def test_draft_rollout_is_not_live_authority() -> None:
    v1_draft = _unsigned_policy_bundle(rollout_state="draft")
    v1_live = _unsigned_policy_bundle(rollout_state="enforcing")
    v2_draft = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "payload": {"spec": {"rolloutState": "draft"}},
    }
    v2_omitted = {"contractVersion": POLICY_BUNDLE_V2_CONTRACT, "payload": {"spec": {}}}
    v2_enforcing = {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "payload": {"spec": {"rolloutState": "enforcing"}},
    }

    assert policy_bundle_is_enforceable(v1_draft) is False
    assert policy_bundle_is_enforceable(v1_live) is True
    assert policy_bundle_is_enforceable(v2_draft) is False
    assert policy_bundle_is_enforceable(v2_omitted) is True
    assert policy_bundle_is_enforceable(v2_enforcing) is True
    assert (
        policy_bundle_is_enforceable(
            {"contractVersion": POLICY_BUNDLE_V2_CONTRACT, "payload": {"spec": {"rolloutState": None}}}
        )
        is False
    )
    assert policy_bundle_is_enforceable({"contractVersion": POLICY_BUNDLE_V2_CONTRACT}) is False
    assert policy_bundle_is_enforceable({"contractVersion": POLICY_BUNDLE_V2_CONTRACT, "payload": []}) is False
    assert (
        policy_bundle_is_enforceable({"contractVersion": POLICY_BUNDLE_V2_CONTRACT, "payload": {"spec": []}}) is False
    )


@pytest.mark.release
def test_wrong_workspace_bundle_is_refused() -> None:
    key = policy_bundle_test_verification_key()
    signed = sign_policy_bundle(_unsigned_policy_bundle(), key=key)

    validated, reason = validated_policy_bundle_payload(
        signed,
        trusted_verification_keys=(key,),
        anchored_verification_keys=(key,),
        expected_workspace_id="other-workspace",
        now=_VALIDATION_NOW,
    )

    assert validated is None
    assert reason == "wrong_workspace"


@pytest.mark.release
def test_stale_bundle_is_rejected_as_downgrade() -> None:
    accepted = {
        "bundleHash": "sha256:" + "a" * 64,
        "bundleVersion": "policy-v2",
        "issuedAt": "2026-07-18T12:00:00Z",
        "workspaceId": TEST_POLICY_BUNDLE_WORKSPACE_ID,
    }
    stale = {
        "bundleHash": "sha256:" + "b" * 64,
        "bundleVersion": "policy-v1",
        "issuedAt": "2026-07-18T11:59:59Z",
        "workspaceId": TEST_POLICY_BUNDLE_WORKSPACE_ID,
    }

    assert policy_bundle_is_version_downgrade(accepted, stale) is True


@pytest.mark.release
def test_unavailable_runtime_is_not_release_evidence() -> None:
    payload = _matrix()
    scenario = payload["platforms"][0]["scenarios"][0]
    scenario["native_selected"] = False
    scenario["python_fallback"] = True

    with pytest.raises(InstalledMatrixError, match="unsafe runtime"):
        _validate(payload, windows_waiver="waived")

    validate_matrix(
        _matrix(),
        expected_version=VERSION,
        expected_source_sha="a" * 40,
        expected_rule_digest="b" * 64,
        windows_waiver="waived",
    )


@pytest.mark.release
def test_immutable_block_is_not_remotely_approvable() -> None:
    fixtures = load_fixtures()
    reviewability = fixtures["reviewabilityCases"]
    assert isinstance(reviewability, list)
    kinds: dict[str, bool] = {}
    for case in reviewability:
        assert isinstance(case, dict)
        validate_reviewability_case(case)
        kind = case["requestKind"]
        accepted = case["remoteDecisionAccepted"]
        assert isinstance(kind, str)
        assert isinstance(accepted, bool)
        kinds[kind] = accepted
    assert kinds["reviewable_pause"] is True
    assert kinds["immutable_policy_block"] is False

    invalid = next(
        item
        for item in fixtures["invalidResults"]
        if isinstance(item, dict) and item.get("name") == "immutable-block-cannot-use-exact-review-result"
    )
    source_name = invalid["source"]
    mutation = invalid["mutations"][0]
    assert isinstance(source_name, str)
    source = next(
        item["result"]
        for item in fixtures["validResults"]
        if isinstance(item, dict) and item.get("name") == source_name
    )
    assert isinstance(source, dict)
    mutated = json.loads(json.dumps(source))
    mutated["request"]["kind"] = mutation["value"]
    with pytest.raises(ValueError, match="reviewable_pause"):
        validate_review_result(mutated)

    contract_doc = (ROOT / "docs/guard/contracts/guard-cloud-review.md").read_text(encoding="utf-8")
    assert "immutable-block-not-remotely-approvable" in contract_doc
