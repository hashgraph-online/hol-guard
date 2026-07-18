from __future__ import annotations

import base64
import hashlib
import json
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.mdm.health_lease_contract import (
    HEALTH_LEASE_SCHEMA,
    MAX_ACK_BYTES,
    MAX_LEASE_BYTES,
    HealthLeaseAck,
    HealthLeaseClaims,
    HealthLeaseOutbox,
    SignedHealthLease,
    canonical_json_bytes,
)


def _key() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = base64.urlsafe_b64encode(hashlib.sha256(public).digest()).decode("ascii").rstrip("=")
    return private, key_id


def _claims(key_id: str, **updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": HEALTH_LEASE_SCHEMA,
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": "1" * 32,
        "installationGeneration": "2" * 32,
        "sequence": 1,
        "issuedAt": "2026-07-18T14:00:00Z",
        "leaseExpiresAt": "2026-07-18T14:15:00Z",
        "snapshotSchemaVersion": "local-integrity-snapshot.v1",
        "snapshotDigest": "4" * 64,
        "previousLeaseDigest": None,
        "previousLeaseKeyId": None,
        "signingKeyId": key_id,
    }
    payload.update(updates)
    return payload


def _signed_lease(private: ec.EllipticCurvePrivateKey, key_id: str) -> SignedHealthLease:
    claims = HealthLeaseClaims.parse(_claims(key_id))
    signed = SignedHealthLease(
        claims,
        private.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256())),
    )
    return SignedHealthLease.parse(signed.canonical_bytes())


def _ack(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": "hol-guard-health-lease-ack.v1",
        "status": "accepted",
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": "1" * 32,
        "installationGeneration": "2" * 32,
        "sequence": 1,
        "leaseDigest": "4" * 64,
        "receivedAt": "2026-07-18T14:00:01.000Z",
    }
    payload.update(updates)
    return payload


def _snapshot() -> dict[str, object]:
    component = {"state": "healthy", "healthy": True, "reasonCode": "release_manifest_valid"}
    components = {
        name: dict(component)
        for name in (
            "manifest",
            "nativePackage",
            "managedPolicy",
            "ownershipAndAcl",
            "supervisor",
            "harnessCoverage",
            "installationIdentity",
            "leaseContinuity",
            "daemon",
            "commandShadowing",
            "update",
        )
    }
    components["deviceKey"] = {**component, "level": "os-protected"}
    components["supervisor"] = {**component, "state": "running"}
    return {
        "schemaVersion": "local-integrity-snapshot.v1",
        "generatedAt": "2026-07-18T14:00:00+00:00",
        "scope": "machine",
        "healthy": True,
        "assuranceLevel": "mdm-managed",
        "installOwner": "mdm",
        "platform": "Darwin",
        "architecture": "arm64",
        "identifiers": {
            "workspaceId": "workspace-a",
            "deviceId": "device-a",
            "machineInstallationId": "1" * 32,
            "installationGeneration": "2" * 32,
        },
        "product": {
            "version": "3.1.0a1",
            "buildId": None,
            "sourceCommit": None,
            "packageIdentity": "test",
            "manifestHash": None,
            "policyHash": None,
        },
        "components": components,
        "harnessCoverage": {"required": 0, "protected": 0, "degraded": 0, "missing": 0},
        "continuity": {
            "monotonicUptimeSeconds": 10.0,
            "sequence": 0,
            "previousLeaseDigest": None,
            "bootSessionId": "boot-a",
        },
        "reasonCodes": [],
        "remediationClass": "none",
    }


def _outbox(snapshot: dict[str, object]) -> HealthLeaseOutbox:
    private, key_id = _key()
    snapshot_bytes = canonical_json_bytes(snapshot)
    claims = HealthLeaseClaims.parse(_claims(key_id, snapshotDigest=hashlib.sha256(snapshot_bytes).hexdigest()))
    lease = SignedHealthLease(claims, private.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256())))
    return HealthLeaseOutbox(lease, snapshot_bytes)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(unexpected=True),
        lambda payload: payload.update(sequence=True),
        lambda payload: payload.update(workspaceId="../escape"),
        lambda payload: payload.update(workspaceId="wörkspace"),
        lambda payload: payload.update(leaseExpiresAt="2026-07-18T15:00:01Z"),
        lambda payload: payload.update(previousLeaseDigest="5" * 64),
        lambda payload: payload.update(signingKeyId="not-a-key-id"),
    ],
)
def test_claims_reject_unknown_malformed_and_inconsistent_fields(mutation: object) -> None:
    _, key_id = _key()
    payload = _claims(key_id)
    assert callable(mutation)
    mutation(payload)

    with pytest.raises(ValueError, match="health_lease_invalid"):
        HealthLeaseClaims.parse(payload)


def test_signed_lease_requires_exact_canonical_json_and_bounded_input() -> None:
    private, key_id = _key()
    lease = _signed_lease(private, key_id)
    canonical = lease.canonical_bytes()

    assert SignedHealthLease.parse(canonical) == lease
    with pytest.raises(ValueError, match="health_lease_invalid"):
        SignedHealthLease.parse(json.dumps(lease.to_dict(), indent=2).encode())
    with pytest.raises(ValueError, match="health_lease_invalid"):
        unexpected = lease.to_dict()
        unexpected["unexpected"] = True
        SignedHealthLease.parse(canonical_json_bytes(unexpected))
    with pytest.raises(ValueError, match="health_lease_invalid"):
        SignedHealthLease.parse(b"{" + b" " * MAX_LEASE_BYTES + b"}")


def test_signed_lease_parser_rejects_invalid_base64() -> None:
    private, key_id = _key()
    payload = _signed_lease(private, key_id).to_dict()
    cast(dict[str, object], payload["signature"])["value"] = "***"

    with pytest.raises(ValueError, match="health_lease_invalid"):
        SignedHealthLease.parse(canonical_json_bytes(payload))


def test_ack_accepts_portal_field_order_and_canonicalizes_durable_marker() -> None:
    payload = _ack()
    portal_order = json.dumps(payload, separators=(",", ":")).encode()

    ack = HealthLeaseAck.parse(portal_order)

    assert ack.status == "accepted"
    assert HealthLeaseAck.parse(ack.canonical_bytes()) == ack


@pytest.mark.parametrize(
    "updates",
    [
        {"status": "rejected"},
        {"workspaceId": "../escape"},
        {"sequence": True},
        {"sequence": 0},
        {"leaseDigest": "F" * 64},
        {"receivedAt": "2026-07-18T14:00:01Z"},
        {"receivedAt": "2026-07-18T14:00:01.000+00:00"},
    ],
)
def test_ack_rejects_malformed_fields(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="health_lease_ack_invalid"):
        HealthLeaseAck.parse(canonical_json_bytes(_ack(**updates)))


def test_ack_rejects_unknown_duplicate_and_oversized_input() -> None:
    unknown = _ack(unexpected=True)
    duplicate = (
        b'{"schemaVersion":"hol-guard-health-lease-ack.v1","status":"accepted","status":"replayed",'
        b'"workspaceId":"workspace-a","deviceId":"device-a","machineInstallationId":"'
        + b"1" * 32
        + b'","installationGeneration":"'
        + b"2" * 32
        + b'","sequence":1,"leaseDigest":"'
        + b"4" * 64
        + b'","receivedAt":"2026-07-18T14:00:01.000Z"}'
    )

    for payload in (canonical_json_bytes(unknown), duplicate, b"{" + b" " * MAX_ACK_BYTES + b"}"):
        with pytest.raises(ValueError, match="health_lease_ack_invalid"):
            HealthLeaseAck.parse(payload)


def test_outbox_rejects_oversized_snapshot() -> None:
    private, key_id = _key()
    snapshot = b"x" * (256 * 1024 + 1)
    claims = HealthLeaseClaims.parse(_claims(key_id, snapshotDigest=hashlib.sha256(snapshot).hexdigest()))
    lease = SignedHealthLease(claims, private.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256())))

    with pytest.raises(ValueError, match="health_lease_outbox_invalid"):
        HealthLeaseOutbox(lease, snapshot).canonical_bytes()


@pytest.mark.parametrize("container", [None, "identifiers", "product", "components", "harnessCoverage", "continuity"])
def test_outbox_rejects_unknown_snapshot_fields(container: str | None) -> None:
    snapshot = _snapshot()
    target = snapshot if container is None else cast(dict[str, object], snapshot[container])
    target["unexpected"] = True

    with pytest.raises(ValueError, match="health_lease_outbox_invalid"):
        _outbox(snapshot).canonical_bytes()


def test_snapshot_canonicalization_rejects_non_finite_numbers() -> None:
    snapshot = _snapshot()
    cast(dict[str, object], snapshot["continuity"])["monotonicUptimeSeconds"] = float("nan")

    with pytest.raises(ValueError, match="health_lease_json_invalid"):
        canonical_json_bytes(snapshot)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda snapshot: cast(dict[str, object], cast(dict[str, object], snapshot["components"])["manifest"]).update(
            state={}
        ),
        lambda snapshot: cast(list[object], snapshot["reasonCodes"]).append({}),
        lambda snapshot: cast(dict[str, object], snapshot["harnessCoverage"]).update(required=True),
        lambda snapshot: cast(dict[str, object], snapshot["product"]).update(version="x" * 129),
        lambda snapshot: cast(dict[str, object], snapshot["continuity"]).update(monotonicUptimeSeconds=-1),
    ],
)
def test_outbox_rejects_malformed_snapshot_values(mutation: object) -> None:
    snapshot = _snapshot()
    assert callable(mutation)
    mutation(snapshot)

    with pytest.raises(ValueError, match="health_lease_outbox_invalid"):
        _outbox(snapshot).canonical_bytes()


def test_sequence_requires_complete_prior_lease_chain() -> None:
    _, key_id = _key()
    chained = HealthLeaseClaims.parse(
        _claims(key_id, sequence=2, previousLeaseDigest="5" * 64, previousLeaseKeyId=key_id)
    )

    assert chained.sequence == 2
    for field in ("previousLeaseDigest", "previousLeaseKeyId"):
        invalid = _claims(key_id, sequence=2, previousLeaseDigest="5" * 64, previousLeaseKeyId=key_id)
        invalid[field] = None
        with pytest.raises(ValueError, match="health_lease_invalid"):
            HealthLeaseClaims.parse(invalid)
