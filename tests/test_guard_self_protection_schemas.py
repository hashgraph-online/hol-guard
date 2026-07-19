from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from tests.guard_mdm_health_lease_support import snapshot

SCHEMA_ROOT = Path(__file__).parents[1] / "docs" / "guard" / "schemas"
SCHEMA_FILES = {
    "self-protection-common.v1": "self-protection-common.v1.schema.json",
    "local-integrity-snapshot.v1": "local-integrity-snapshot-v1.schema.json",
    "protection-lease.v1": "protection-lease.v1.schema.json",
    "observer-assertion.v1": "observer-assertion.v1.schema.json",
    "protection-state.v1": "protection-state.v1.schema.json",
    "removal-authorization.v1": "removal-authorization.v1.schema.json",
    "remediation-job.v1": "remediation-job.v1.schema.json",
}
SCHEMA_NAMES = tuple(SCHEMA_FILES)

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


def _schemas() -> dict[str, dict[str, JsonValue]]:
    return {
        name: json.loads((SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
        for name, filename in SCHEMA_FILES.items()
    }


def _validator(name: str) -> Draft202012Validator:
    schemas = _schemas()
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema)) for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry)


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_self_protection_schemas_are_valid_draft_2020_12(name: str) -> None:
    Draft202012Validator.check_schema(_schemas()[name])


def test_local_integrity_snapshot_rejects_unknown_fields_and_invalid_time() -> None:
    payload: dict[str, JsonValue] = {
        "schemaVersion": "local-integrity-snapshot.v1",
        "generatedAt": "not-a-dateZ",
        "unexpected": "field",
    }
    errors = list(_validator("local-integrity-snapshot.v1").iter_errors(payload))
    messages = [error.message for error in errors]
    assert any("does not match" in message for message in messages)
    assert any("Additional properties are not allowed" in message for message in messages)

    payload["generatedAt"] = "2026-07-18T22:00:00+05:30"
    assert list(_validator("local-integrity-snapshot.v1").iter_errors(payload))


def test_local_integrity_snapshot_accepts_valid_healthy_components() -> None:
    _validator("local-integrity-snapshot.v1").validate(snapshot())


def test_protection_lease_requires_bounded_attestation_not_commands() -> None:
    payload: dict[str, JsonValue] = {
        "schemaVersion": "protection-lease.v1",
        "claims": {
            "workspaceId": "workspace-a",
            "deviceId": "device-a",
            "machineInstallationId": "1" * 32,
            "installationGeneration": "2" * 32,
            "sequence": 7,
            "issuedAt": "2026-07-18T22:00:00Z",
            "expiresAt": "2026-07-18T22:15:00Z",
            "snapshotSchemaVersion": "local-integrity-snapshot.v1",
            "snapshotDigest": "3" * 64,
            "previousLeaseDigest": "4" * 64,
            "signingKeyId": "device-key-a",
            "challenge": {
                "challengeId": "challenge-a",
                "nonce": "A" * 32,
                "issuedAt": "2026-07-18T22:00:00Z",
                "expiresAt": "2026-07-18T22:02:00Z",
            },
        },
        "signature": {
            "algorithm": "ecdsa-p256-sha256",
            "keyId": "device-key-a",
            "value": "A" * 86 + "==",
        },
    }
    validator = _validator("protection-lease.v1")
    validator.validate(payload)

    claims = payload["claims"]
    assert isinstance(claims, dict)
    claims["issuedAt"] = "not-a-dateZ"
    assert list(validator.iter_errors(payload))
    claims["issuedAt"] = "2026-07-18T22:00:00Z"

    payload["command"] = "arbitrary remote command"
    assert list(validator.iter_errors(payload))


@pytest.mark.parametrize("value", ["not base64!", "AQI", "AQ=ID", "====", "A" * 88])
def test_signed_evidence_rejects_malformed_base64_signatures(value: str) -> None:
    payload: dict[str, JsonValue] = {
        "schemaVersion": "protection-lease.v1",
        "claims": {
            "workspaceId": "workspace-a",
            "deviceId": "device-a",
            "machineInstallationId": "1" * 32,
            "installationGeneration": "2" * 32,
            "sequence": 7,
            "issuedAt": "2026-07-18T22:00:00Z",
            "expiresAt": "2026-07-18T22:15:00Z",
            "snapshotSchemaVersion": "local-integrity-snapshot.v1",
            "snapshotDigest": "3" * 64,
            "previousLeaseDigest": "4" * 64,
            "signingKeyId": "device-key-a",
            "challenge": None,
        },
        "signature": {
            "algorithm": "ecdsa-p256-sha256",
            "keyId": "device-key-a",
            "value": value,
        },
    }

    assert list(_validator("protection-lease.v1").iter_errors(payload))


def test_observer_and_remediation_authorities_are_separate_and_allowlisted() -> None:
    assertion: dict[str, JsonValue] = {
        "schemaVersion": "observer-assertion.v1",
        "assertionId": "assertion-a",
        "workspaceId": "workspace-a",
        "observerId": "observer-a",
        "adapterId": "adapter-a",
        "externalDeviceId": "vendor-device-a",
        "observedAt": "2026-07-18T22:00:00Z",
        "expiresAt": "2026-07-18T22:10:00Z",
        "detection": {
            "state": "absent",
            "endpointOnline": True,
            "version": None,
            "packageIdentity": None,
            "reasonCodes": ["observer_current_absent"],
        },
        "remediation": {"state": "none", "jobId": None},
        "signature": {
            "algorithm": "ed25519",
            "keyId": "observer-key-a",
            "value": "A" * 86 + "==",
        },
    }
    _validator("observer-assertion.v1").validate(assertion)
    detection = assertion["detection"]
    assert isinstance(detection, dict)
    detection["reasonCodes"] = ["package_absent"]
    assert list(_validator("observer-assertion.v1").iter_errors(assertion))
    detection["reasonCodes"] = ["observer_current_absent"]
    assertion["remediation"] = {"state": "unknown", "jobId": None}
    assert list(_validator("observer-assertion.v1").iter_errors(assertion))
    assertion["remediation"] = {"state": "none", "jobId": "unexpected-job"}
    assert list(_validator("observer-assertion.v1").iter_errors(assertion))

    job: dict[str, JsonValue] = {
        "schemaVersion": "remediation-job.v1",
        "jobId": "job-a",
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "installationGeneration": "2" * 32,
        "action": "repair",
        "targetVersion": "3.1.0a6",
        "idempotencyKey": "repair-device-a-generation-2",
        "issuedAt": "2026-07-18T22:00:00Z",
        "expiresAt": "2026-07-18T22:15:00Z",
        "attemptLimit": 3,
        "signature": {
            "algorithm": "ed25519",
            "keyId": "cloud-remediation-a",
            "value": "A" * 86 + "==",
        },
    }
    validator = _validator("remediation-job.v1")
    validator.validate(job)
    job["action"] = "version-converge"
    job["targetVersion"] = None
    assert list(validator.iter_errors(job))
    job["action"] = "run-command"
    assert list(validator.iter_errors(job))


def test_confirmed_authorized_removal_precedes_pending_removal() -> None:
    contract = (SCHEMA_ROOT.parent / "self-protection-contract.md").read_text(encoding="utf-8")

    assert contract.index("Fresh observer confirms absence under a valid removal authorization") < contract.index(
        "Valid removal authorization is active and removal is not yet confirmed"
    )
