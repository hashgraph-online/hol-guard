from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from lab_support import _safe_identifier, _same_json, _validate_json_limits

from codex_plugin_scanner.guard.mdm.cloud_control import (
    REMEDIATION_SCHEMA,
    ContractError,
    iso,
    parse_time,
    utcnow,
    validate_remediation,
)


class StoreRemediationMixin:
    """Typed remediation idempotency, evidence gating, and fleet projection."""

    def create_job(self, payload: Mapping[str, object]) -> tuple[bool, dict[str, object]]:
        allowed = {
            "workspaceId",
            "deviceId",
            "jobId",
            "idempotencyKey",
            "action",
            "parameters",
            "maxAttempts",
        }
        if set(payload) - allowed:
            raise ContractError("remediation_request_invalid")
        workspace = _safe_identifier(payload.get("workspaceId"), "workspace")
        device = _safe_identifier(payload.get("deviceId"), "device")
        with self._db() as database:
            enrolled = database.execute(
                "SELECT * FROM devices WHERE workspace=? AND device=?",
                (workspace, device),
            ).fetchone()
        if not enrolled:
            raise ContractError("remediation_device_unknown", 404)
        job_id = (
            _safe_identifier(payload.get("jobId"), "job_id") if "jobId" in payload else "job-" + uuid.uuid4().hex[:20]
        )
        idempotency_key = (
            _safe_identifier(payload.get("idempotencyKey"), "idempotency_key")
            if "idempotencyKey" in payload
            else "idem-" + uuid.uuid4().hex[:20]
        )
        now = utcnow()
        job = {
            "schemaVersion": REMEDIATION_SCHEMA,
            "workspaceId": workspace,
            "deviceId": device,
            "installationGeneration": enrolled["generation"],
            "jobId": job_id,
            "idempotencyKey": idempotency_key,
            "action": payload.get("action"),
            "parameters": payload.get("parameters", {}),
            "createdAt": iso(now),
            "expiresAt": iso(now + timedelta(minutes=10)),
            "maxAttempts": payload.get("maxAttempts", 2),
        }
        validate_remediation(job, workspace, device, enrolled["generation"])
        immutable = {
            key: job[key]
            for key in (
                "workspaceId",
                "deviceId",
                "installationGeneration",
                "idempotencyKey",
                "action",
                "parameters",
                "maxAttempts",
            )
        }
        with self.lock, self._db() as database:
            existing = database.execute(
                "SELECT payload FROM jobs WHERE idempotency_key=?",
                (job["idempotencyKey"],),
            ).fetchone()
            if existing:
                existing_job = json.loads(existing["payload"])
                existing_immutable = {key: existing_job[key] for key in immutable}
                if not _same_json(existing_immutable, immutable):
                    raise ContractError("remediation_idempotency_conflict", 409)
                return False, existing_job
            job_id_collision = database.execute("SELECT 1 FROM jobs WHERE job_id=?", (job["jobId"],)).fetchone()
            if job_id_collision:
                raise ContractError("remediation_job_id_conflict", 409)
            database.execute(
                "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                (
                    job["jobId"],
                    workspace,
                    device,
                    enrolled["generation"],
                    json.dumps(job, sort_keys=True),
                    "pending",
                    None,
                    job["idempotencyKey"],
                    job["createdAt"],
                ),
            )
        self.audit(
            "remediation_created",
            workspace,
            device,
            {"jobId": job["jobId"], "action": job["action"]},
        )
        return True, job

    def jobs(self, workspace: str, device: str, generation: str) -> list[dict[str, object]]:
        with self._db() as database:
            return [
                json.loads(row["payload"])
                for row in database.execute(
                    "SELECT payload FROM jobs WHERE workspace=? AND device=? AND generation=? "
                    "AND status='pending' ORDER BY created_at,job_id",
                    (workspace, device, generation),
                )
            ]

    def save_remediation_result(
        self,
        workspace: str,
        device: str,
        generation: str,
        payload: object,
    ) -> dict[str, object]:
        if not isinstance(payload, dict) or set(payload) != {"jobId", "status", "observedAt", "detail"}:
            raise ContractError("remediation_result_invalid")
        job_id = _safe_identifier(payload.get("jobId"), "job_id")
        status = payload.get("status")
        if status not in {"succeeded", "failed"}:
            raise ContractError("remediation_result_invalid")
        observed_at = payload.get("observedAt")
        if not isinstance(observed_at, str):
            raise ContractError("remediation_result_invalid")
        parse_time(observed_at, "remediation_result_invalid")
        detail = payload.get("detail")
        _validate_json_limits(detail)
        encoded = json.dumps(payload, sort_keys=True)
        with self.lock, self._db() as database:
            row = database.execute(
                "SELECT * FROM jobs WHERE job_id=? AND workspace=? AND device=? AND generation=?",
                (job_id, workspace, device, generation),
            ).fetchone()
            if not row:
                raise ContractError("remediation_job_unknown", 404)
            if row["result"] is not None:
                if row["result"] != encoded:
                    raise ContractError("remediation_result_conflict", 409)
                return {
                    "accepted": True,
                    "duplicate": True,
                    "awaitingEvidence": row["status"] == "awaiting_evidence",
                }
            cloud_status = "awaiting_evidence" if status == "succeeded" else "failed"
            database.execute(
                "UPDATE jobs SET status=?,result=? WHERE job_id=?",
                (cloud_status, encoded, job_id),
            )
        self.audit(
            "remediation_executed",
            workspace,
            device,
            {"jobId": job_id, "executionStatus": status, "cloudStatus": cloud_status},
        )
        return {
            "accepted": True,
            "duplicate": False,
            "awaitingEvidence": cloud_status == "awaiting_evidence",
        }

    def state(self, workspace_id: str | None = None) -> dict[str, object]:
        scoped = workspace_id is not None
        params: tuple[object, ...] = (workspace_id,) if scoped else ()

        def select_rows(
            database: Any,
            unscoped_query: str,
            scoped_query: str,
        ) -> list[dict[str, Any]]:
            query = scoped_query if scoped else unscoped_query
            return [dict(row) for row in database.execute(query, params)]

        with self.lock, self._db() as database:
            result = {
                "schemaVersion": "hol-guard-mdm-cloud-state.v2",
                "devices": select_rows(
                    database,
                    "SELECT workspace,device,generation,key_id,last_seq,enrolled_at "
                    "FROM devices ORDER BY workspace,device",
                    "SELECT workspace,device,generation,key_id,last_seq,enrolled_at "
                    "FROM devices WHERE workspace=? ORDER BY workspace,device",
                ),
                "assignments": select_rows(
                    database,
                    "SELECT workspace,device,generation,revision,policy_hash,"
                    "previous_hash,assigned_at FROM assignments "
                    "ORDER BY workspace,device",
                    "SELECT workspace,device,generation,revision,policy_hash,"
                    "previous_hash,assigned_at FROM assignments "
                    "WHERE workspace=? ORDER BY workspace,device",
                ),
                "assignmentHistory": select_rows(
                    database,
                    "SELECT workspace,device,generation,revision,policy_hash,"
                    "previous_hash,assigned_at FROM assignment_history "
                    "ORDER BY workspace,device,revision",
                    "SELECT workspace,device,generation,revision,policy_hash,"
                    "previous_hash,assigned_at FROM assignment_history "
                    "WHERE workspace=? ORDER BY workspace,device,revision",
                ),
                "acks": select_rows(
                    database,
                    "SELECT request_id,workspace,device,generation,revision,"
                    "policy_hash,status FROM acks "
                    "ORDER BY workspace,device,revision,request_id",
                    "SELECT request_id,workspace,device,generation,revision,"
                    "policy_hash,status FROM acks WHERE workspace=? "
                    "ORDER BY workspace,device,revision,request_id",
                ),
                "health": select_rows(
                    database,
                    "SELECT request_id,workspace,device,generation,sequence "
                    "FROM health ORDER BY workspace,device,sequence",
                    "SELECT request_id,workspace,device,generation,sequence "
                    "FROM health WHERE workspace=? "
                    "ORDER BY workspace,device,sequence",
                ),
                "jobs": select_rows(
                    database,
                    "SELECT job_id,workspace,device,generation,status,"
                    "idempotency_key,created_at,verified_at FROM jobs "
                    "ORDER BY workspace,device,created_at,job_id",
                    "SELECT job_id,workspace,device,generation,status,"
                    "idempotency_key,created_at,verified_at FROM jobs "
                    "WHERE workspace=? "
                    "ORDER BY workspace,device,created_at,job_id",
                ),
                "audit": select_rows(
                    database,
                    "SELECT event,workspace,device,detail,at,previous_hash,event_hash FROM audit ORDER BY id",
                    "SELECT event,workspace,device,detail,at,previous_hash,"
                    "event_hash FROM audit WHERE workspace=? ORDER BY id",
                ),
            }
        result["auditChainValid"] = self.verify_audit_chain()
        return result
