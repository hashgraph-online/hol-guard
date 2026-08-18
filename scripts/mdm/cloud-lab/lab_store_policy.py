from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from datetime import timedelta

from lab_support import _safe_identifier

from codex_plugin_scanner.guard.mdm.cloud_control import (
    CONFIG_SCHEMA,
    ContractError,
    iso,
    policy_hash,
    sign_config,
    utcnow,
    validate_ack,
    validate_health,
    validate_policy,
)


def _validate_publication(
    payload: Mapping[str, object],
) -> tuple[str, list[str], dict[str, object], bool, str | None]:
    if set(payload) != {"workspaceId", "deviceIds", "policy", "rollback", "rollbackReason"}:
        raise ContractError("publish_invalid")
    workspace = _safe_identifier(payload.get("workspaceId"), "workspace")
    devices = payload.get("deviceIds")
    policy = validate_policy(payload.get("policy"))
    rollback = payload.get("rollback")
    rollback_reason = payload.get("rollbackReason")
    if (
        not isinstance(devices, list)
        or not devices
        or any(not isinstance(device, str) for device in devices)
        or len(set(devices)) != len(devices)
    ):
        raise ContractError("publish_invalid")
    if not isinstance(rollback, bool):
        raise ContractError("publish_invalid")
    if rollback and (not isinstance(rollback_reason, str) or not rollback_reason.strip() or len(rollback_reason) > 512):
        raise ContractError("publish_invalid")
    if not rollback and rollback_reason is not None:
        raise ContractError("publish_invalid")
    normalized_devices = [_safe_identifier(device, "device") for device in devices]
    return (
        workspace,
        normalized_devices,
        policy,
        rollback,
        rollback_reason if isinstance(rollback_reason, str) else None,
    )


class StorePolicyMixin:
    """Desired-state publication, assignment history, acknowledgement, and health."""

    def publish(self, payload: Mapping[str, object]) -> dict[str, object]:
        workspace, normalized_devices, policy, rollback, rollback_reason = _validate_publication(payload)
        now = utcnow()
        policy_digest = policy_hash(policy)
        with self.lock, self._db() as database:
            enrolled: list[sqlite3.Row] = []
            for device in normalized_devices:
                row = database.execute(
                    "SELECT * FROM devices WHERE workspace=? AND device=?",
                    (workspace, device),
                ).fetchone()
                if not row:
                    raise ContractError("publish_device_unknown", 404)
                enrolled.append(row)
            revision = database.execute(
                "SELECT COALESCE(MAX(revision),0)+1 AS next_revision FROM policies WHERE workspace=?",
                (workspace,),
            ).fetchone()["next_revision"]
            database.execute(
                "INSERT INTO policies VALUES(?,?,?,?,?)",
                (workspace, revision, json.dumps(policy, sort_keys=True), policy_digest, iso(now)),
            )
            for row in enrolled:
                prior = database.execute(
                    "SELECT * FROM assignments WHERE workspace=? AND device=? AND generation=?",
                    (workspace, row["device"], row["generation"]),
                ).fetchone()
                previous_hash = prior["policy_hash"] if prior else None
                envelope = {
                    "schemaVersion": CONFIG_SCHEMA,
                    "workspaceId": workspace,
                    "deviceId": row["device"],
                    "installationGeneration": row["generation"],
                    "revision": revision,
                    "issuedAt": iso(now),
                    "notBefore": iso(now - timedelta(seconds=1)),
                    "expiresAt": iso(now + timedelta(hours=1)),
                    "policy": policy,
                    "policyHash": policy_digest,
                    "previousPolicyHash": previous_hash,
                    "rollback": {
                        "authorized": rollback,
                        "fromRevision": prior["revision"] if rollback and prior else None,
                        "reason": rollback_reason if rollback else None,
                    },
                    "signingKeyId": "lab-cloud-rsa-1",
                }
                signed = sign_config(envelope, self.key)
                encoded = json.dumps(signed, sort_keys=True)
                values = (
                    workspace,
                    row["device"],
                    row["generation"],
                    revision,
                    policy_digest,
                    previous_hash,
                    encoded,
                    iso(now),
                )
                database.execute(
                    "INSERT INTO assignment_history VALUES(?,?,?,?,?,?,?,?)",
                    values,
                )
                database.execute(
                    "INSERT INTO assignments VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(workspace,device,generation) DO UPDATE SET "
                    "revision=excluded.revision,policy_hash=excluded.policy_hash,"
                    "previous_hash=excluded.previous_hash,envelope=excluded.envelope,assigned_at=excluded.assigned_at",
                    values,
                )
        self.audit(
            "policy_published",
            workspace,
            "fleet",
            {
                "revision": revision,
                "policyHash": policy_digest,
                "deviceCount": len(normalized_devices),
                "rollback": rollback,
            },
        )
        return {"revision": revision, "policyHash": policy_digest}

    def configuration(
        self,
        workspace: str,
        device: str,
        generation: str,
        etag: str | None,
    ) -> tuple[int, dict[str, str], object | None]:
        with self._db() as database:
            row = database.execute(
                "SELECT * FROM assignments WHERE workspace=? AND device=? AND generation=?",
                (workspace, device, generation),
            ).fetchone()
        if not row:
            return 204, {}, None
        tag = f'"{row["revision"]}:{row["policy_hash"]}"'
        if etag == tag:
            return 304, {"etag": tag}, None
        return 200, {"etag": tag}, json.loads(row["envelope"])

    def save_acknowledgement(
        self,
        workspace: str,
        device: str,
        generation: str,
        payload: object,
    ) -> dict[str, object]:
        acknowledgement = validate_ack(payload, workspace, device, generation)
        encoded = json.dumps(acknowledgement, sort_keys=True)
        with self.lock, self._db() as database:
            existing = database.execute(
                "SELECT payload FROM acks WHERE request_id=?",
                (acknowledgement["requestId"],),
            ).fetchone()
            if existing:
                if existing["payload"] != encoded:
                    raise ContractError("ack_request_conflict", 409)
                return {"accepted": True, "duplicate": True}
            assignment = database.execute(
                "SELECT revision,policy_hash FROM assignment_history "
                "WHERE workspace=? AND device=? AND generation=? AND revision=?",
                (workspace, device, generation, acknowledgement["revision"]),
            ).fetchone()
            if not assignment or acknowledgement["policyHash"] != assignment["policy_hash"]:
                raise ContractError("ack_assignment_mismatch", 409)
            database.execute(
                "INSERT INTO acks VALUES(?,?,?,?,?,?,?,?)",
                (
                    acknowledgement["requestId"],
                    workspace,
                    device,
                    generation,
                    acknowledgement["revision"],
                    acknowledgement["policyHash"],
                    acknowledgement["status"],
                    encoded,
                ),
            )
        self.audit(
            "policy_acknowledged",
            workspace,
            device,
            {"revision": acknowledgement["revision"], "status": acknowledgement["status"]},
        )
        return {"accepted": True, "duplicate": False}

    def save_health(
        self,
        workspace: str,
        device: str,
        generation: str,
        payload: object,
    ) -> dict[str, object]:
        health = validate_health(payload, workspace, device, generation)
        encoded = json.dumps(health, sort_keys=True)
        verified_jobs: list[str] = []
        with self.lock, self._db() as database:
            existing_request = database.execute(
                "SELECT payload FROM health WHERE request_id=?", (health["requestId"],)
            ).fetchone()
            if existing_request:
                if existing_request["payload"] != encoded:
                    raise ContractError("health_request_conflict", 409)
                return {"accepted": True, "duplicate": True, "sequence": health["sequence"]}
            existing_sequence = database.execute(
                "SELECT payload FROM health WHERE workspace=? AND device=? AND generation=? AND sequence=?",
                (workspace, device, generation, health["sequence"]),
            ).fetchone()
            if existing_sequence:
                if existing_sequence["payload"] != encoded:
                    raise ContractError("health_sequence_conflict", 409)
                return {"accepted": True, "duplicate": True, "sequence": health["sequence"]}
            last = database.execute(
                "SELECT MAX(sequence) AS sequence FROM health WHERE workspace=? AND device=? AND generation=?",
                (workspace, device, generation),
            ).fetchone()["sequence"]
            if last is not None and health["sequence"] <= last:
                raise ContractError("health_sequence_replay", 409)
            if health["appliedRevision"] is not None:
                assignment = database.execute(
                    "SELECT policy_hash FROM assignment_history "
                    "WHERE workspace=? AND device=? AND generation=? AND revision=?",
                    (workspace, device, generation, health["appliedRevision"]),
                ).fetchone()
                if not assignment or assignment["policy_hash"] != health["appliedPolicyHash"]:
                    raise ContractError("health_assignment_mismatch", 409)
            database.execute(
                "INSERT INTO health VALUES(?,?,?,?,?,?)",
                (
                    health["requestId"],
                    workspace,
                    device,
                    generation,
                    health["sequence"],
                    encoded,
                ),
            )
            status = health.get("status")
            healthy = isinstance(status, dict) and status.get("healthy") is True
            if healthy:
                rows = list(
                    database.execute(
                        "SELECT job_id FROM jobs WHERE workspace=? AND device=? AND generation=? "
                        "AND status='awaiting_evidence' ORDER BY created_at",
                        (workspace, device, generation),
                    )
                )
                verified_jobs = [row["job_id"] for row in rows]
                if verified_jobs:
                    database.execute(
                        "UPDATE jobs SET status='succeeded',verified_at=? "
                        "WHERE workspace=? AND device=? AND generation=? AND status='awaiting_evidence'",
                        (health["observedAt"], workspace, device, generation),
                    )
        self.audit(
            "health_received",
            workspace,
            device,
            {
                "sequence": health["sequence"],
                "appliedRevision": health["appliedRevision"],
                "verifiedJobCount": len(verified_jobs),
            },
        )
        for job_id in verified_jobs:
            self.audit("remediation_verified", workspace, device, {"jobId": job_id})
        return {
            "accepted": True,
            "duplicate": False,
            "sequence": health["sequence"],
            "verifiedJobs": verified_jobs,
        }
