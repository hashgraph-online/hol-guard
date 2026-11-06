from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).parents[1]
SCHEMA_DIR = ROOT / "docs" / "guard" / "schemas"
WORKSPACE = "workspace-mdm-cloud-lab"
DEVICE = "device-a"
GENERATION = "a" * 32
NOW = "2026-08-16T12:00:00Z"
LATER = "2026-08-16T12:10:00Z"


def load(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "name",
    [
        "mdm-cloud-config-v1.schema.json",
        "mdm-cloud-ack-v1.schema.json",
        "mdm-cloud-health-v1.schema.json",
        "mdm-cloud-remediation-v1.schema.json",
        "mdm-cloud-enrollment-v1.schema.json",
        "mdm-cloud-lab-report-v1.schema.json",
    ],
)
def test_cloud_mdm_schemas_are_valid_draft_2020_12(name: str) -> None:
    Draft202012Validator.check_schema(load(name))


def examples() -> dict[str, dict[str, object]]:
    policy = {
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "settings": {"mode": "enforce"},
        "lockedSettings": ["mode"],
        "requiredHarnesses": [],
    }
    return {
        "mdm-cloud-config-v1.schema.json": {
            "schemaVersion": "hol-guard-mdm-cloud-config.v1",
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "revision": 1,
            "issuedAt": NOW,
            "notBefore": NOW,
            "expiresAt": LATER,
            "policy": policy,
            "policyHash": "1" * 64,
            "previousPolicyHash": None,
            "rollback": {"authorized": False, "fromRevision": None, "reason": None},
            "signingKeyId": "cloud-key-1",
            "signature": {"algorithm": "rsa-pss-sha256", "value": "YQ=="},
        },
        "mdm-cloud-ack-v1.schema.json": {
            "schemaVersion": "hol-guard-mdm-cloud-ack.v1",
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "revision": 1,
            "policyHash": "1" * 64,
            "status": "applied",
            "reasonCode": None,
            "observedAt": NOW,
            "requestId": "ack-1",
        },
        "mdm-cloud-health-v1.schema.json": {
            "schemaVersion": "hol-guard-mdm-cloud-health.v1",
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "sequence": 1,
            "appliedRevision": 1,
            "appliedPolicyHash": "1" * 64,
            "observedAt": NOW,
            "requestId": "health-1",
            "status": {"healthy": True, "managementAssuranceLevel": "mdm-managed"},
        },
        "mdm-cloud-remediation-v1.schema.json": {
            "schemaVersion": "hol-guard-mdm-cloud-remediation.v1",
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "jobId": "job-1",
            "idempotencyKey": "job-1-once",
            "action": "repair",
            "parameters": {"scope": "machine"},
            "createdAt": NOW,
            "expiresAt": LATER,
            "maxAttempts": 2,
        },
        "mdm-cloud-enrollment-v1.schema.json": {
            "schemaVersion": "hol-guard-mdm-enrollment.v1",
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "keyId": "device-key-1",
            "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----",
            "token": "one-time-token",
        },
        "mdm-cloud-lab-report-v1.schema.json": {
            "schemaVersion": "hol-guard-mdm-cloud-integration-lab.v1",
            "generatedAt": NOW,
            "workspaceId": WORKSPACE,
            "healthy": True,
            "stepCount": 1,
            "steps": [{"name": "fixture", "passed": True, "durationMs": 1, "evidence": {}}],
            "nativeCertification": {
                "outcome": "not-evaluated",
                "requiredGates": ["apple-apns-enrollment"],
                "reason": "native_platform_or_vendor_required",
            },
        },
    }


@pytest.mark.parametrize("name,payload", list(examples().items()))
def test_cloud_mdm_schema_examples_validate(name: str, payload: dict[str, object]) -> None:
    Draft202012Validator(load(name)).validate(payload)


@pytest.mark.parametrize("name,payload", list(examples().items()))
def test_cloud_mdm_schemas_reject_unknown_authority_fields(name: str, payload: dict[str, object]) -> None:
    candidate = copy.deepcopy(payload)
    candidate["command"] = "curl attacker.invalid"
    with pytest.raises(ValidationError):
        Draft202012Validator(load(name)).validate(candidate)
