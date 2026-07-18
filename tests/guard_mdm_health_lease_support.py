from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.mdm import continuity, health_lease
from codex_plugin_scanner.guard.mdm.contracts import LocalIntegritySnapshot, MachinePaths
from codex_plugin_scanner.guard.mdm.device_key import KeyGeneration
from codex_plugin_scanner.guard.mdm.health_lease_contract import (
    HEALTH_LEASE_SCHEMA,
    HealthLeaseClaims,
)

NOW = datetime(2026, 7, 18, 14, 0, tzinfo=timezone.utc)
INSTALLATION_ID = "1" * 32
GENERATION_ID = "2" * 32


def paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def key() -> tuple[ec.EllipticCurvePrivateKey, KeyGeneration]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = base64.urlsafe_b64encode(hashlib.sha256(public).digest()).decode("ascii").rstrip("=")
    return private, KeyGeneration(
        generation="3" * 32,
        key_id=key_id,
        public_key_spki=base64.b64encode(public).decode("ascii"),
        protection_level="os-protected",
        created_at="2026-07-18T13:00:00+00:00",
    )


def claims(key_id: str, **updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": HEALTH_LEASE_SCHEMA,
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": INSTALLATION_ID,
        "installationGeneration": GENERATION_ID,
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


def snapshot(sequence: int = 0, previous_digest: str | None = None) -> LocalIntegritySnapshot:
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
    return cast(
        LocalIntegritySnapshot,
        {
            "schemaVersion": "local-integrity-snapshot.v1",
            "generatedAt": "2026-07-18T14:00:00+00:00",
            "scope": "machine",
            "healthy": True,
            "assuranceLevel": "mdm-managed",
            "installOwner": "mdm",
            "platform": "Darwin",
            "architecture": "arm64",
            "identifiers": {
                "workspaceId": None,
                "deviceId": None,
                "machineInstallationId": INSTALLATION_ID,
                "installationGeneration": GENERATION_ID,
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
                "sequence": sequence,
                "previousLeaseDigest": previous_digest,
                "bootSessionId": "boot-a",
            },
            "reasonCodes": [],
            "remediationClass": "none",
        },
    )


def prepare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[MachinePaths, ec.EllipticCurvePrivateKey, KeyGeneration]:
    machine_paths = paths(tmp_path)
    machine_paths.state_root.mkdir(parents=True)
    private, generation = key()
    monkeypatch.setattr(continuity, "_private_regular_file", lambda _metadata: True)
    monkeypatch.setattr(health_lease, "_private_regular_file", lambda _metadata: True)
    monkeypatch.setattr(health_lease, "verified_machine_device_key_by_id", lambda *_args, **_kwargs: generation)
    monkeypatch.setattr(
        health_lease,
        "observe_boot",
        lambda **_kwargs: continuity.BootObservation("boot-a", 10_000_000_000),
    )
    record = continuity.InstallationContinuityRecord(
        machine_installation_id=INSTALLATION_ID,
        installation_generation=GENERATION_ID,
        generation_created_at="2026-07-18T13:00:00+00:00",
        key_id_at_generation_creation=generation.key_id,
        last_issued_sequence=0,
        last_lease_digest=None,
        last_lease_boot_session_id=None,
        last_lease_monotonic_uptime_ns=None,
        updated_at="2026-07-18T13:00:00+00:00",
        last_lease_key_id=None,
    )
    continuity._atomic_write(machine_paths, record)
    return machine_paths, private, generation


def signer(private: ec.EllipticCurvePrivateKey) -> health_lease.LeaseSigner:
    def sign(
        _paths: MachinePaths,
        _generation: KeyGeneration,
        lease_claims: HealthLeaseClaims,
        _system_name: str,
    ) -> bytes:
        return private.sign(lease_claims.signing_payload(), ec.ECDSA(hashes.SHA256()))

    return sign
