"""Shared helper for signed single-rule policy bundle validation tests."""

from __future__ import annotations

from datetime import datetime, timezone

from codex_plugin_scanner.guard.policy_bundle_parser import validated_policy_bundle_payload
from tests.policy_bundle_signing_helpers import (
    TEST_POLICY_BUNDLE_WORKSPACE_ID,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)

# The bundle below is valid until 2027-01-01. Validate at a fixed instant inside
# its window so the result never depends on the wall clock.
VALIDATION_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp()


def policy_bundle_rule_is_valid(rule: dict[str, object]) -> bool:
    """Whether a signed bundle carrying only this rule passes full native validation."""

    bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "1.0",
        "issuedAt": "2026-01-01T00:00:00Z",
        "expiresAt": "2027-01-01T00:00:00Z",
        "verifier": {"algorithm": "rsa-pss-sha256", "keyId": "key-1", "signature": "sig"},
        "rolloutState": "enforced",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "block",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "block",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": False,
        },
        "rules": [rule],
        "acknowledgements": [],
    }
    signing_key = policy_bundle_test_verification_key()
    payload, _ = validated_policy_bundle_payload(
        sign_policy_bundle(bundle, key=signing_key),
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=VALIDATION_NOW,
    )
    return payload is not None
