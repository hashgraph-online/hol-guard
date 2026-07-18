from __future__ import annotations

import base64
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.mdm import continuity, health_lease
from codex_plugin_scanner.guard.mdm.contracts import LocalIntegritySnapshot, MachinePaths
from codex_plugin_scanner.guard.mdm.device_key import KeyGeneration
from codex_plugin_scanner.guard.mdm.health_lease_contract import (
    HEALTH_LEASE_SCHEMA,
    HealthLeaseBinding,
    HealthLeaseClaims,
    HealthLeaseOutbox,
    SignedHealthLease,
    canonical_json_bytes,
)

_NOW = datetime(2026, 7, 18, 14, 0, tzinfo=timezone.utc)
_INSTALLATION_ID = "1" * 32
_GENERATION_ID = "2" * 32


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _key() -> tuple[ec.EllipticCurvePrivateKey, KeyGeneration]:
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


def _claims(key_id: str, **updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": HEALTH_LEASE_SCHEMA,
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": _INSTALLATION_ID,
        "installationGeneration": _GENERATION_ID,
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


def _snapshot(sequence: int = 0, previous_digest: str | None = None) -> LocalIntegritySnapshot:
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
        cast(
            object,
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
                    "machineInstallationId": _INSTALLATION_ID,
                    "installationGeneration": _GENERATION_ID,
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
        ),
    )


def _prepare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[MachinePaths, ec.EllipticCurvePrivateKey, KeyGeneration]:
    paths = _paths(tmp_path)
    paths.state_root.mkdir(parents=True)
    private, key = _key()
    monkeypatch.setattr(continuity, "_private_regular_file", lambda _metadata: True)
    monkeypatch.setattr(health_lease, "_private_regular_file", lambda _metadata: True)
    monkeypatch.setattr(health_lease, "verified_machine_device_key_by_id", lambda *_args, **_kwargs: key)
    monkeypatch.setattr(
        health_lease,
        "observe_boot",
        lambda **_kwargs: continuity.BootObservation("boot-a", 10_000_000_000),
    )
    record = continuity.InstallationContinuityRecord(
        machine_installation_id=_INSTALLATION_ID,
        installation_generation=_GENERATION_ID,
        generation_created_at="2026-07-18T13:00:00+00:00",
        key_id_at_generation_creation=key.key_id,
        last_issued_sequence=0,
        last_lease_digest=None,
        last_lease_boot_session_id=None,
        last_lease_monotonic_uptime_ns=None,
        updated_at="2026-07-18T13:00:00+00:00",
        last_lease_key_id=None,
    )
    continuity._atomic_write(paths, record)
    return paths, private, key


def _signer(private: ec.EllipticCurvePrivateKey) -> health_lease.LeaseSigner:
    def sign(
        _paths: MachinePaths,
        _generation: KeyGeneration,
        claims: HealthLeaseClaims,
        _system_name: str,
    ) -> bytes:
        return private.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256()))

    return sign


def test_outbox_rejects_oversized_snapshot() -> None:
    private, key = _key()
    snapshot = b"x" * (256 * 1024 + 1)
    claims = HealthLeaseClaims.parse(_claims(key.key_id, snapshotDigest=hashlib.sha256(snapshot).hexdigest()))
    lease = SignedHealthLease(
        claims,
        private.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256())),
    )

    with pytest.raises(ValueError, match="health_lease_outbox_invalid"):
        HealthLeaseOutbox(lease, snapshot).canonical_bytes()


@pytest.mark.parametrize("container", [None, "identifiers", "product", "components", "harnessCoverage", "continuity"])
def test_outbox_rejects_unknown_snapshot_fields(container: str | None) -> None:
    private, key = _key()
    snapshot = cast(dict[str, object], cast(object, _snapshot()))
    identifiers = cast(dict[str, object], snapshot["identifiers"])
    identifiers.update(workspaceId="workspace-a", deviceId="device-a")
    target = snapshot if container is None else cast(dict[str, object], snapshot[container])
    target["unexpected"] = True
    snapshot_bytes = canonical_json_bytes(snapshot)
    claims = HealthLeaseClaims.parse(_claims(key.key_id, snapshotDigest=hashlib.sha256(snapshot_bytes).hexdigest()))
    lease = SignedHealthLease(claims, private.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256())))

    with pytest.raises(ValueError, match="health_lease_outbox_invalid"):
        HealthLeaseOutbox(lease, snapshot_bytes).canonical_bytes()


def test_snapshot_canonicalization_rejects_non_finite_numbers() -> None:
    snapshot = cast(dict[str, object], cast(object, _snapshot()))
    continuity_payload = cast(dict[str, object], snapshot["continuity"])
    continuity_payload["monotonicUptimeSeconds"] = float("nan")

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
    private, key = _key()
    snapshot = cast(dict[str, object], cast(object, _snapshot()))
    cast(dict[str, object], snapshot["identifiers"]).update(workspaceId="workspace-a", deviceId="device-a")
    assert callable(mutation)
    mutation(snapshot)
    snapshot_bytes = canonical_json_bytes(snapshot)
    claims = HealthLeaseClaims.parse(_claims(key.key_id, snapshotDigest=hashlib.sha256(snapshot_bytes).hexdigest()))
    lease = SignedHealthLease(claims, private.sign(claims.signing_payload(), ec.ECDSA(hashes.SHA256())))

    with pytest.raises(ValueError, match="health_lease_outbox_invalid"):
        HealthLeaseOutbox(lease, snapshot_bytes).canonical_bytes()


def test_sequence_requires_complete_prior_lease_chain() -> None:
    _, key = _key()
    chained = HealthLeaseClaims.parse(
        _claims(
            key.key_id,
            sequence=2,
            previousLeaseDigest="5" * 64,
            previousLeaseKeyId=key.key_id,
        )
    )

    assert chained.sequence == 2
    for field in ("previousLeaseDigest", "previousLeaseKeyId"):
        invalid = _claims(
            key.key_id,
            sequence=2,
            previousLeaseDigest="5" * 64,
            previousLeaseKeyId=key.key_id,
        )
        invalid[field] = None
        with pytest.raises(ValueError, match="health_lease_invalid"):
            HealthLeaseClaims.parse(invalid)


def test_issue_binds_exact_normalized_snapshot_digest_and_verifies_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, private, key = _prepare(tmp_path, monkeypatch)

    outbox = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=_NOW,
        system_name="Darwin",
        snapshot_factory=_snapshot,
        signer=_signer(private),
    )

    decoded_snapshot = json.loads(outbox.snapshot_bytes)
    assert decoded_snapshot["identifiers"]["workspaceId"] == "workspace-a"
    assert decoded_snapshot["identifiers"]["deviceId"] == "device-a"
    assert outbox.lease.claims.snapshot_digest == hashlib.sha256(outbox.snapshot_bytes).hexdigest()
    private.public_key().verify(
        outbox.lease.signature,
        outbox.lease.claims.signing_payload(),
        ec.ECDSA(hashes.SHA256()),
    )
    assert outbox.lease.claims.signing_key_id == key.key_id


def test_issue_rejects_signature_from_an_unrelated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths, _private, _key_generation = _prepare(tmp_path, monkeypatch)
    attacker = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(OSError, match="health_lease_signature_invalid"):
        health_lease.issue_or_load_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            now=_NOW,
            system_name="Darwin",
            snapshot_factory=_snapshot,
            signer=_signer(attacker),
        )

    assert not (paths.state_root / "health-lease-outbox.json").exists()


def test_missing_pending_after_issuance_fails_without_reusing_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, private, _key = _prepare(tmp_path, monkeypatch)
    first = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=_NOW,
        system_name="Darwin",
        snapshot_factory=_snapshot,
        signer=_signer(private),
    )
    (paths.state_root / "health-lease-outbox.json").unlink()

    with pytest.raises(OSError, match="health_lease_outbox_absent"):
        health_lease.issue_or_load_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            now=_NOW + timedelta(minutes=1),
            system_name="Darwin",
            snapshot_factory=lambda: _snapshot(1, first.lease.digest),
            signer=_signer(private),
        )

    record = continuity._read_record(paths)
    assert record is not None and record.last_issued_sequence == 1
    assert record.last_lease_digest == first.lease.digest


def test_crash_after_outbox_write_recovers_byte_identical_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, private, _key_generation = _prepare(tmp_path, monkeypatch)

    def crash(stage: str) -> None:
        assert stage == "outbox-durable"
        raise RuntimeError("simulated-crash")

    with pytest.raises(RuntimeError, match="simulated-crash"):
        health_lease.issue_or_load_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            now=_NOW,
            system_name="Darwin",
            snapshot_factory=_snapshot,
            signer=_signer(private),
            crash_hook=crash,
        )
    outbox_path = paths.state_root / "health-lease-outbox.json"
    before = outbox_path.read_bytes()
    initial_record = continuity._read_record(paths)
    assert initial_record is not None and initial_record.last_issued_sequence == 0

    recovered = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=_NOW + timedelta(seconds=1),
        system_name="Darwin",
        snapshot_factory=lambda: pytest.fail("snapshot must not be recollected"),
        signer=lambda *_args, **_kwargs: pytest.fail("lease must not be resigned"),
    )

    assert recovered.canonical_bytes() == HealthLeaseOutbox.parse(before).canonical_bytes()
    assert outbox_path.read_bytes() == before
    record = continuity._read_record(paths)
    assert record is not None and record.last_issued_sequence == 1
    assert record.last_lease_digest == recovered.lease.digest


def test_pending_binding_conflict_and_expiry_fail_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, private, _key_generation = _prepare(tmp_path, monkeypatch)
    issued = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=_NOW,
        system_name="Darwin",
        snapshot_factory=_snapshot,
        signer=_signer(private),
    )
    outbox_path = paths.state_root / "health-lease-outbox.json"
    before = outbox_path.read_bytes()

    with pytest.raises(OSError, match="health_lease_pending_conflict"):
        health_lease.issue_or_load_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-b", "device-a"),
            now=_NOW + timedelta(seconds=1),
            system_name="Darwin",
        )
    with pytest.raises(OSError, match="health_lease_pending_expired"):
        health_lease.issue_or_load_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            now=_NOW + timedelta(minutes=15),
            system_name="Darwin",
        )

    assert outbox_path.read_bytes() == before
    assert health_lease.load_pending_health_lease(paths) == issued


def test_malformed_and_symlink_outbox_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths, _private, _key_generation = _prepare(tmp_path, monkeypatch)
    outbox_path = paths.state_root / "health-lease-outbox.json"
    outbox_path.write_bytes(b'{"schemaVersion":"wrong"}')

    with pytest.raises(ValueError, match="health_lease_outbox_invalid"):
        health_lease.load_pending_health_lease(paths)

    outbox_path.unlink()
    target = tmp_path / "attacker-controlled"
    target.write_text("{}", encoding="utf-8")
    outbox_path.symlink_to(target)
    with pytest.raises(PermissionError, match="health_lease_outbox_acl_invalid"):
        health_lease.load_pending_health_lease(paths)


def test_concurrent_issuance_creates_only_one_pending_lease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths, private, _key_generation = _prepare(tmp_path, monkeypatch)
    barrier = Barrier(2)

    def issue() -> HealthLeaseOutbox:
        barrier.wait()
        return health_lease.issue_or_load_pending_health_lease(
            paths,
            HealthLeaseBinding("workspace-a", "device-a"),
            now=_NOW,
            system_name="Darwin",
            snapshot_factory=_snapshot,
            signer=_signer(private),
        )

    results: list[HealthLeaseOutbox] = []
    conflicts: list[BlockingIOError] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        for future in (executor.submit(issue), executor.submit(issue)):
            try:
                results.append(future.result())
            except BlockingIOError as exc:
                conflicts.append(exc)

    assert results
    assert len(results) + len(conflicts) == 2
    retry = health_lease.issue_or_load_pending_health_lease(
        paths,
        HealthLeaseBinding("workspace-a", "device-a"),
        now=_NOW,
        system_name="Darwin",
    )
    assert all(result.canonical_bytes() == retry.canonical_bytes() for result in results)
    assert os.stat(paths.state_root / "health-lease-outbox.json").st_mode & 0o777 == 0o600
    record = continuity._read_record(paths)
    assert record is not None and record.last_issued_sequence == 1
