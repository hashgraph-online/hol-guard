"""Owner-bound continuation claims and atomic durable finalization."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

import sqlite3
from collections.abc import Mapping

# ruff: noqa: F403,F405
from .store_base import *
from .store_policy import _approval_authority_revision
from .store_review_event_outbox_writes import append_request_snapshot_event


def _persist_continuation_events(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    evidence_id: str,
    events: list[tuple[str, dict[str, object]]],
    now: str,
) -> None:
    for event_name, payload in events:
        effect_key = sha256(f"{evidence_id}\0{event_name}".encode()).hexdigest()
        inserted = connection.execute(
            """insert or ignore into guard_continuation_effects
               (effect_key, request_id, evidence_id, event_name, created_at) values (?, ?, ?, ?, ?)""",
            (effect_key, request_id, evidence_id, event_name, now),
        )
        if inserted.rowcount:
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                (event_name, json.dumps(payload, sort_keys=True), now),
            )


def _append_terminal_review_event(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    action: str,
    evidence_id: str,
    resume_update: dict[str, object],
    now: str,
) -> None:
    status = resume_update.get("continuation_status")
    capability = resume_update.get("continuation_capability")
    reason = resume_update.get("continuation_reason")
    completed_at = resume_update.get("continuation_completed_at")
    evidence = resume_update.get("continuation_evidence")
    first_evidence = evidence[0] if isinstance(evidence, list) and evidence else None
    correlation_id = first_evidence.get("correlationId") if isinstance(first_evidence, dict) else None
    if not all(
        isinstance(value, str) and value for value in (status, capability, reason, completed_at, correlation_id)
    ):
        raise ValueError("terminal continuation result is incomplete")
    if status not in {
        "resumed",
        "already_resumed",
        "manual_retry_required",
        "blocked_not_resumed",
        "unsupported",
        "failed",
    }:
        raise ValueError("terminal continuation status is invalid")
    request = connection.execute(
        "select oauth_source from approval_requests where request_id = ?",
        (request_id,),
    ).fetchone()
    if request is None:
        raise ValueError("terminal continuation request is missing")
    append_request_snapshot_event(
        connection,
        request_id=request_id,
        source=str(request["oauth_source"]),
        event_type=f"review.continuation.{status}",
        occurred_at=now,
        continuation_result={
            "action": action,
            "capability": capability,
            "completedAt": completed_at,
            "correlationId": correlation_id,
            "evidenceId": evidence_id,
            "reason": reason,
            "status": status,
        },
    )


class StoreContinuationMixin:
    def claim_continuation_attempt(
        self,
        *,
        request_id: str,
        offer_hash: str,
        action: str,
        now: str,
        lease_seconds: float,
    ) -> str | None:
        """Acquire one durable continuation lease; stale claims are recoverable."""
        observed_at = datetime.fromisoformat(now)
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("continuation claim timestamp must be timezone-aware")
        if lease_seconds <= 0:
            raise ValueError("continuation claim lease must be positive")
        lease_expires_at = (observed_at + timedelta(seconds=lease_seconds)).isoformat()
        claim_id = f"claim-{uuid4().hex}"
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                """select state, lease_expires_at from guard_continuation_claims
                   where request_id = ? and offer_hash = ? and action = ?""",
                (request_id, offer_hash, action),
            ).fetchone()
            if row is not None and str(row["state"]) in {"completed", "waiting"}:
                return None
            if row is not None and str(row["state"]) == "claimed":
                raw_expiry = row["lease_expires_at"]
                if raw_expiry is not None:
                    expiry = datetime.fromisoformat(str(raw_expiry))
                    if expiry.tzinfo is not None and expiry.utcoffset() is not None and expiry > observed_at:
                        return None
            connection.execute(
                """
                insert into guard_continuation_claims (
                  request_id, offer_hash, action, state, claimed_at, lease_expires_at, claim_id, evidence_id
                )
                values (?, ?, ?, 'claimed', ?, ?, ?, null)
                on conflict(request_id, offer_hash, action) do update set
                  state = 'claimed', claimed_at = excluded.claimed_at,
                  lease_expires_at = excluded.lease_expires_at, claim_id = excluded.claim_id, evidence_id = null
                """,
                (request_id, offer_hash, action, now, lease_expires_at, claim_id),
            )
        return claim_id

    def finalize_continuation_attempt(
        self,
        *,
        request_id: str,
        offer_hash: str,
        action: str,
        claim_id: str | None,
        evidence_id: str,
        terminal: bool,
        resume_seed: dict[str, object],
        resume_update: dict[str, object],
        operation_update: dict[str, object] | None,
        events: list[tuple[str, dict[str, object]]],
        now: str,
        approval_decision: Mapping[str, object] | None = None,
    ) -> bool:
        """Finalize continuation evidence and optionally consume exact allow authority atomically."""

        with self._connect() as connection:
            connection.execute("begin immediate")
            if approval_decision is not None:
                approval_id = approval_decision.get("approval_id")
                authority_revision = approval_decision.get("_approval_authority_revision")
                if (
                    not isinstance(approval_id, str)
                    or not approval_id
                    or not isinstance(authority_revision, int)
                    or isinstance(authority_revision, bool)
                    or authority_revision < 0
                    or approval_decision.get("action") != "allow"
                    or self.approval_reuse_claim_disposition(approval_decision) != "consumed"
                ):
                    connection.rollback()
                    return False
                integrity_key, integrity_key_id = self._policy_integrity_secret_material(create=False)
                if integrity_key is None or integrity_key_id is None:
                    connection.rollback()
                    return False
                if _approval_authority_revision(connection) != authority_revision:
                    connection.rollback()
                    return False
                claimed = self._claim_local_once_approval_by_id_locked(
                    connection,
                    approval_id=approval_id,
                    now=now,
                    expected_decision=approval_decision,
                    integrity_key=integrity_key,
                    integrity_key_id=integrity_key_id,
                )
                if claimed is None:
                    connection.rollback()
                    return False
            claim = connection.execute(
                """select state, claim_id, evidence_id from guard_continuation_claims
                   where request_id = ? and offer_hash = ? and action = ?""",
                (request_id, offer_hash, action),
            ).fetchone()
            if claim_id is not None:
                if claim is not None and str(claim["state"]) == "completed":
                    connection.rollback()
                    return False
                if claim is None or str(claim["state"]) != "claimed" or str(claim["claim_id"]) != claim_id:
                    raise RuntimeError("continuation claim ownership changed before finalization")
            if claim is not None and str(claim["state"]) == "completed":
                stored_evidence_id = claim["evidence_id"]
                if stored_evidence_id is not None and str(stored_evidence_id) != evidence_id:
                    connection.rollback()
                    return False
            persist_request_resume_seed(
                connection,
                request_id=request_id,
                operation_id=cast(str | None, resume_seed.get("operation_id")),
                harness=str(resume_seed["harness"]),
                strategy=str(resume_seed["strategy"]),
                supported=bool(resume_seed["supported"]),
                thread_id=cast(str | None, resume_seed.get("thread_id")),
                now=now,
            )
            persist_request_resume_update(
                connection,
                request_id=request_id,
                resolution_action=cast(str | None, resume_update.get("resolution_action")),
                strategy=cast(str | None, resume_update.get("strategy")),
                supported=cast(bool | None, resume_update.get("supported")),
                status=str(resume_update["status"]),
                reason=cast(str | None, resume_update.get("reason")),
                message=cast(str | None, resume_update.get("message")),
                last_error=cast(str | None, resume_update.get("last_error")),
                attempt_count=int(cast(int, resume_update["attempt_count"])),
                last_attempt_at=cast(str | None, resume_update.get("last_attempt_at")),
                sent_at=cast(str | None, resume_update.get("sent_at")),
                now=now,
                continuation_contract_version=cast(str | None, resume_update.get("continuation_contract_version")),
                continuation_capability=cast(str | None, resume_update.get("continuation_capability")),
                continuation_status=cast(str | None, resume_update.get("continuation_status")),
                continuation_reason=cast(str | None, resume_update.get("continuation_reason")),
                continuation_evidence=cast(list[dict[str, object]] | None, resume_update.get("continuation_evidence")),
                continuation_offer_hash=cast(str | None, resume_update.get("continuation_offer_hash")),
                continuation_action=cast(str | None, resume_update.get("continuation_action")),
                continuation_completed_at=cast(str | None, resume_update.get("continuation_completed_at")),
                continuation_cancelled_at=cast(str | None, resume_update.get("continuation_cancelled_at")),
            )
            if operation_update is not None:
                connection.execute(
                    """update guard_operations set status = ?, metadata_json = ?, updated_at = ?
                       where operation_id = ?""",
                    (
                        str(operation_update["status"]),
                        json.dumps(operation_update["metadata"], sort_keys=True),
                        now,
                        str(operation_update["operation_id"]),
                    ),
                )
            connection.execute(
                """
                insert into guard_continuation_claims (
                  request_id, offer_hash, action, state, claimed_at, lease_expires_at, claim_id, evidence_id
                ) values (?, ?, ?, ?, ?, null, null, ?)
                on conflict(request_id, offer_hash, action) do update set
                  state = excluded.state, claimed_at = excluded.claimed_at, lease_expires_at = null,
                  claim_id = null, evidence_id = excluded.evidence_id
                """,
                (request_id, offer_hash, action, "completed" if terminal else "waiting", now, evidence_id),
            )
            _persist_continuation_events(
                connection,
                request_id=request_id,
                evidence_id=evidence_id,
                events=events,
                now=now,
            )
            if terminal:
                _append_terminal_review_event(
                    connection,
                    request_id=request_id,
                    action=action,
                    evidence_id=evidence_id,
                    resume_update=resume_update,
                    now=now,
                )
        return True
