from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.mdm.cloud_control import (
    ACK_SCHEMA,
    ENROLL_SCHEMA,
    HEALTH_SCHEMA,
    ContractError,
    iso,
    public_pem,
    utcnow,
)

ROOT = Path(__file__).parents[1]
LAB = ROOT / "scripts" / "mdm" / "cloud-lab"
sys.path.insert(0, str(LAB))

from device_runtime import Device  # noqa: E402
from lab_common import Store, atomic  # noqa: E402

WORKSPACE = "workspace-mdm-alpha"
DEVICE = "device-a"
GENERATION = "a" * 32
TOKEN = "enrollment-token-device-a"


def managed_policy(mode: str) -> dict[str, object]:
    return {
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "settings": {"mode": mode},
        "lockedSettings": ["mode"],
        "requiredHarnesses": [],
        "update": {"owner": "mdm"},
    }


def enrolled_store(tmp_path: Path) -> Store:
    store = Store(
        tmp_path / "cloud.sqlite3",
        tmp_path / "cloud-key.pem",
        [
            {
                "workspaceId": WORKSPACE,
                "deviceId": DEVICE,
                "installationGeneration": GENERATION,
                "token": TOKEN,
            }
        ],
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = public_pem(private_key.public_key())
    store.enroll(
        {
            "schemaVersion": ENROLL_SCHEMA,
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "keyId": hashlib.sha256(public_key.encode()).hexdigest()[:32],
            "publicKeyPem": public_key,
            "token": TOKEN,
        }
    )
    return store


def test_remediation_idempotency_never_returns_a_phantom_job(tmp_path: Path) -> None:
    store = enrolled_store(tmp_path)
    request = {
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "jobId": "job-repair",
        "idempotencyKey": "idem-repair",
        "action": "repair",
        "parameters": {"scope": "machine"},
        "maxAttempts": 2,
    }
    created, first = store.create_job(request)
    repeated, second = store.create_job({key: value for key, value in request.items() if key != "jobId"})
    assert created is True
    assert repeated is False
    assert second == first
    state = store.state(WORKSPACE)
    assert [item["job_id"] for item in state["jobs"]] == ["job-repair"]
    with pytest.raises(ContractError, match="remediation_idempotency_conflict"):
        store.create_job({**request, "jobId": "job-other", "parameters": {"scope": "users"}})
    with pytest.raises(ContractError, match="remediation_job_id_conflict"):
        store.create_job(
            {
                **request,
                "idempotencyKey": "idem-other",
                "action": "integrity-scan",
                "parameters": {},
            }
        )
    assert [item["job_id"] for item in store.state(WORKSPACE)["jobs"]] == ["job-repair"]


def test_historical_ack_is_accepted_after_a_newer_assignment(tmp_path: Path) -> None:
    store = enrolled_store(tmp_path)
    first = store.publish(
        {
            "workspaceId": WORKSPACE,
            "deviceIds": [DEVICE],
            "policy": managed_policy("observe"),
            "rollback": False,
            "rollbackReason": None,
        }
    )
    second = store.publish(
        {
            "workspaceId": WORKSPACE,
            "deviceIds": [DEVICE],
            "policy": managed_policy("enforce"),
            "rollback": False,
            "rollbackReason": None,
        }
    )
    acknowledgement = {
        "schemaVersion": ACK_SCHEMA,
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "installationGeneration": GENERATION,
        "revision": first["revision"],
        "policyHash": first["policyHash"],
        "status": "applied",
        "reasonCode": None,
        "observedAt": iso(utcnow()),
        "requestId": "ack-first",
    }
    assert store.save_acknowledgement(WORKSPACE, DEVICE, GENERATION, acknowledgement) == {
        "accepted": True,
        "duplicate": False,
    }
    assert second["revision"] > first["revision"]
    assert store.state(WORKSPACE)["acks"][0]["revision"] == first["revision"]


def test_ack_and_health_duplicates_are_exact_not_blanket_409_success(tmp_path: Path) -> None:
    store = enrolled_store(tmp_path)
    assignment = store.publish(
        {
            "workspaceId": WORKSPACE,
            "deviceIds": [DEVICE],
            "policy": managed_policy("observe"),
            "rollback": False,
            "rollbackReason": None,
        }
    )
    now = iso(utcnow())
    acknowledgement = {
        "schemaVersion": ACK_SCHEMA,
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "installationGeneration": GENERATION,
        "revision": assignment["revision"],
        "policyHash": assignment["policyHash"],
        "status": "applied",
        "reasonCode": None,
        "observedAt": now,
        "requestId": "ack-1",
    }
    store.save_acknowledgement(WORKSPACE, DEVICE, GENERATION, acknowledgement)
    assert store.save_acknowledgement(WORKSPACE, DEVICE, GENERATION, acknowledgement)["duplicate"] is True
    with pytest.raises(ContractError, match="ack_request_conflict"):
        store.save_acknowledgement(
            WORKSPACE,
            DEVICE,
            GENERATION,
            {**acknowledgement, "status": "deferred", "reasonCode": "test_deferred"},
        )

    health = {
        "schemaVersion": HEALTH_SCHEMA,
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "installationGeneration": GENERATION,
        "sequence": 1,
        "appliedRevision": assignment["revision"],
        "appliedPolicyHash": assignment["policyHash"],
        "observedAt": now,
        "requestId": "health-1",
        "status": {"healthy": True},
    }
    store.save_health(WORKSPACE, DEVICE, GENERATION, health)
    assert store.save_health(WORKSPACE, DEVICE, GENERATION, health)["duplicate"] is True
    with pytest.raises(ContractError, match="health_request_conflict"):
        store.save_health(
            WORKSPACE,
            DEVICE,
            GENERATION,
            {**health, "status": {"healthy": False}},
        )


def test_remediation_success_waits_for_fresh_healthy_evidence(tmp_path: Path) -> None:
    store = enrolled_store(tmp_path)
    assignment = store.publish(
        {
            "workspaceId": WORKSPACE,
            "deviceIds": [DEVICE],
            "policy": managed_policy("enforce"),
            "rollback": False,
            "rollbackReason": None,
        }
    )
    _, job = store.create_job(
        {
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "idempotencyKey": "idem-repair",
            "action": "repair",
            "parameters": {"scope": "machine"},
            "maxAttempts": 2,
        }
    )
    result = {
        "jobId": job["jobId"],
        "status": "succeeded",
        "observedAt": iso(utcnow()),
        "detail": {"bounded": True},
    }
    assert store.save_remediation_result(WORKSPACE, DEVICE, GENERATION, result)["awaitingEvidence"] is True
    assert store.state(WORKSPACE)["jobs"][0]["status"] == "awaiting_evidence"
    store.save_health(
        WORKSPACE,
        DEVICE,
        GENERATION,
        {
            "schemaVersion": HEALTH_SCHEMA,
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "sequence": 1,
            "appliedRevision": assignment["revision"],
            "appliedPolicyHash": assignment["policyHash"],
            "observedAt": iso(utcnow()),
            "requestId": "health-verifies-repair",
            "status": {"healthy": True},
        },
    )
    assert store.state(WORKSPACE)["jobs"][0]["status"] == "succeeded"


def test_device_outbox_keeps_unproven_409_and_drops_only_exact_duplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = Device(
        tmp_path / "device",
        "http://cloud.invalid",
        WORKSPACE,
        DEVICE,
        GENERATION,
        TOKEN,
        tmp_path / "policy.json",
    )
    item = {"requestId": "ack-1"}
    device.outbox["acks"] = [item]
    responses = iter(
        [
            (409, {}, {"error": "ack_assignment_mismatch"}),
            (409, {}, {"error": "ack_duplicate"}),
        ]
    )

    def request(*_args: Any, **_kwargs: Any):
        return next(responses)

    monkeypatch.setattr(device, "request", request)
    device.flush()
    assert device.outbox["acks"] == [item]
    device.flush()
    assert device.outbox["acks"] == []


def test_dangling_policy_symlink_is_tampered_not_absent(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.symlink_to(tmp_path / "missing-target.json")
    device = Device(
        tmp_path / "device",
        "http://cloud.invalid",
        WORKSPACE,
        DEVICE,
        GENERATION,
        TOKEN,
        policy_path,
    )
    integrity = device.policy_integrity()
    assert integrity["state"] == "tampered"
    assert integrity["reason"] == "managed_policy_symlink"


def test_atomic_write_refuses_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    link = tmp_path / "managed-policy.json"
    link.symlink_to(target)
    with pytest.raises(ContractError, match="unsafe_destination_symlink"):
        atomic(link, b"replacement")
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_audit_chain_is_redacted_and_tamper_evident(tmp_path: Path) -> None:
    store = enrolled_store(tmp_path)
    store.audit(
        "test_event",
        WORKSPACE,
        DEVICE,
        {"accessToken": "secret-token", "nested": {"command": "curl attacker", "safe": "value"}},
    )
    state = store.state(WORKSPACE)
    assert state["auditChainValid"] is True
    serialized = json.dumps(state["audit"])
    assert "secret-token" not in serialized
    assert "curl attacker" not in serialized
    with store._db() as database:
        database.execute("UPDATE audit SET detail='{}' WHERE event='test_event'")
    assert store.verify_audit_chain() is False


def test_policy_files_remain_owner_only(tmp_path: Path) -> None:
    destination = tmp_path / "managed-policy.json"
    atomic(destination, b"{}")
    assert os.stat(destination).st_mode & 0o777 == 0o600


def test_explicit_blank_remediation_identifiers_are_rejected(
    tmp_path: Path,
) -> None:
    store = enrolled_store(tmp_path)
    base = {
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "action": "repair",
        "parameters": {"scope": "machine"},
        "maxAttempts": 2,
    }
    for field, error_code in (
        ("jobId", "job_id_invalid"),
        ("idempotencyKey", "idempotency_key_invalid"),
    ):
        for value in ("", "   "):
            with pytest.raises(
                ContractError,
                match=rf"^{error_code}$",
            ):
                store.create_job({**base, field: value})


def test_unhealthy_evidence_preserves_all_jobs_until_fresh_healthy_report(
    tmp_path: Path,
) -> None:
    store = enrolled_store(tmp_path)
    assignment = store.publish(
        {
            "workspaceId": WORKSPACE,
            "deviceIds": [DEVICE],
            "policy": managed_policy("enforce"),
            "rollback": False,
            "rollbackReason": None,
        }
    )
    for index in (1, 2):
        _, job = store.create_job(
            {
                "workspaceId": WORKSPACE,
                "deviceId": DEVICE,
                "idempotencyKey": f"idem-repair-{index}",
                "action": "repair",
                "parameters": {"scope": "machine"},
                "maxAttempts": 2,
            }
        )
        store.save_remediation_result(
            WORKSPACE,
            DEVICE,
            GENERATION,
            {
                "jobId": job["jobId"],
                "status": "succeeded",
                "observedAt": iso(utcnow()),
                "detail": {"bounded": True},
            },
        )

    unhealthy = store.save_health(
        WORKSPACE,
        DEVICE,
        GENERATION,
        {
            "schemaVersion": HEALTH_SCHEMA,
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "sequence": 1,
            "appliedRevision": assignment["revision"],
            "appliedPolicyHash": assignment["policyHash"],
            "observedAt": iso(utcnow()),
            "requestId": "health-unhealthy",
            "status": {"healthy": False, "reason": "integrity_pending"},
        },
    )
    assert unhealthy["verifiedJobs"] == []
    assert {item["status"] for item in store.state(WORKSPACE)["jobs"]} == {"awaiting_evidence"}

    healthy = store.save_health(
        WORKSPACE,
        DEVICE,
        GENERATION,
        {
            "schemaVersion": HEALTH_SCHEMA,
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "sequence": 2,
            "appliedRevision": assignment["revision"],
            "appliedPolicyHash": assignment["policyHash"],
            "observedAt": iso(utcnow()),
            "requestId": "health-healthy",
            "status": {"healthy": True},
        },
    )
    assert len(healthy["verifiedJobs"]) == 2
    assert {item["status"] for item in store.state(WORKSPACE)["jobs"]} == {"succeeded"}


@pytest.mark.parametrize("status", [429, 503, 599])
def test_device_outbox_preserves_retryable_transient_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    device = Device(
        tmp_path / f"device-{status}",
        "http://cloud.invalid",
        WORKSPACE,
        DEVICE,
        GENERATION,
        TOKEN,
        tmp_path / f"policy-{status}.json",
    )
    item = {"requestId": f"ack-{status}"}
    device.outbox["acks"] = [item]
    monkeypatch.setattr(
        device,
        "request",
        lambda *_args, **_kwargs: (
            status,
            {},
            {"error": f"transient-{status}"},
        ),
    )
    device.flush()
    assert device.outbox["acks"] == [item]


def test_audit_redaction_covers_suffixes_case_and_nested_arrays(
    tmp_path: Path,
) -> None:
    store = enrolled_store(tmp_path)
    store.audit(
        "redaction_probe",
        WORKSPACE,
        DEVICE,
        {
            "mySecret": "secret-one",
            "user_token": "secret-two",
            "PASSWORD": "secret-three",
            "nested": [
                {"PrivateKey": "secret-four", "safe": "visible"},
            ],
        },
    )
    serialized = json.dumps(store.state(WORKSPACE)["audit"])
    for secret in (
        "secret-one",
        "secret-two",
        "secret-three",
        "secret-four",
    ):
        assert secret not in serialized
    assert "visible" in serialized

    with store._db() as database:
        database.execute("UPDATE audit SET detail='not-json' WHERE event='redaction_probe'")
    assert store.verify_audit_chain() is False
