"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from .local_authority_integrity import sign_local_authority_payload, verify_local_authority_payload
from .policy_integrity import PolicyIntegrityVerificationResult

# ruff: noqa: F403,F405
from .store_base import *

_LOCAL_ONCE_INTEGRITY_PURPOSE = "guard-local-once-approval"


def _list_events_query(limit: int, event_name: str | None) -> tuple[str, tuple[object, ...]]:
    query = """
        select event_id, event_name, payload_json, occurred_at
        from guard_events
    """
    params: tuple[object, ...] = ()
    if event_name is not None:
        query += " where event_name = ?"
        params = (event_name,)
    query += " order by occurred_at desc, event_id desc limit ?"
    return query, (*params, limit)


def _local_once_approval_is_reusable(artifact_id: str) -> bool:
    return ":package-request:" in artifact_id


class StoreEventReceiptsMixin:
    def record_local_once_approval(
        self,
        *,
        request_id: str,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        action: str,
        created_at: str,
        expires_at: str,
    ) -> str | None:
        if not artifact_id or not artifact_hash:
            return None
        created_at = _canonical_utc_timestamp(created_at)
        expires_at = _canonical_utc_timestamp(expires_at)
        if _timestamp_has_expired(expires_at, now=created_at):
            raise ValueError("local approval expiry must be after its creation time")
        approval_id = uuid4().hex
        workspace_key = _workspace_policy_key(workspace)
        key, key_id = self._policy_integrity_secret_material(create=True)
        if key is None or key_id is None:
            return None
        signing_row: dict[str, object] = {
            "approval_id": approval_id,
            "request_id": request_id,
            "harness": harness,
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "workspace": workspace_key,
            "publisher": publisher,
            "action": action,
            "created_at": created_at,
            "expires_at": expires_at,
            "claimed_at": None,
        }
        integrity = sign_local_authority_payload(
            signing_row,
            key=key,
            key_id=key_id,
            purpose=_LOCAL_ONCE_INTEGRITY_PURPOSE,
            signed_at=created_at,
        )
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_local_once_approvals (
                  approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
                  created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
                  integrity_key_id, signed_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    request_id,
                    harness,
                    artifact_id,
                    artifact_hash,
                    workspace_key,
                    publisher,
                    action,
                    created_at,
                    expires_at,
                    integrity["integrity_version"],
                    integrity["payload_hash"],
                    integrity["payload_mac"],
                    integrity["integrity_key_id"],
                    integrity["signed_at"],
                ),
            )
        return approval_id

    @staticmethod
    def _peek_local_once_approval_lookup_locked(
        connection: sqlite3.Connection,
        *,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        now: str,
        integrity_key: bytes | None = None,
        integrity_key_id: str | None = None,
    ) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        if not artifact_id or not artifact_hash:
            return None, None
        workspace_key = _workspace_policy_key(workspace)
        row = connection.execute(
            """
            select approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
                   created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
                   integrity_key_id, signed_at
            from guard_local_once_approvals
            where claimed_at is null
              and harness = ?
              and artifact_id = ?
              and artifact_hash = ?
              and julianday(expires_at) > julianday(?)
              and (workspace is null or workspace = ?)
              and (publisher is null or publisher = ?)
            order by created_at desc
            limit 1
            """,
            (harness, artifact_id, artifact_hash, now, workspace_key, publisher),
        ).fetchone()
        if row is None:
            return None, None
        integrity_result = _verify_local_once_approval(
            row,
            key=integrity_key,
            key_id=integrity_key_id,
        )
        if integrity_result.status != "valid":
            return None, _local_once_approval_integrity_failure(row, integrity_result=integrity_result)
        return _local_once_approval_payload(row), None

    @staticmethod
    def _peek_local_once_approval_locked(
        connection: sqlite3.Connection,
        *,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        now: str,
        integrity_key: bytes | None = None,
        integrity_key_id: str | None = None,
    ) -> dict[str, object] | None:
        decision, _integrity_failure = StoreEventReceiptsMixin._peek_local_once_approval_lookup_locked(
            connection,
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            integrity_key=integrity_key,
            integrity_key_id=integrity_key_id,
        )
        return decision

    @staticmethod
    def _claim_local_once_approval_by_id_locked(
        connection: sqlite3.Connection,
        *,
        approval_id: str,
        now: str,
        expected_decision: Mapping[str, object] | None = None,
        integrity_key: bytes | None = None,
        integrity_key_id: str | None = None,
        consume: bool = True,
    ) -> dict[str, object] | None:
        now = _canonical_utc_timestamp(now)
        row = connection.execute(
            """
            select approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
                   created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
                   integrity_key_id, signed_at
            from guard_local_once_approvals
            where approval_id = ? and claimed_at is null
              and julianday(expires_at) > julianday(?)
            """,
            (approval_id, now),
        ).fetchone()
        if row is None:
            return None
        integrity_result = _verify_local_once_approval(
            row,
            key=integrity_key,
            key_id=integrity_key_id,
        )
        if integrity_result.status != "valid" or integrity_key is None or integrity_key_id is None:
            return None
        decision = _local_once_approval_payload(row)
        identity_keys = (
            "action",
            "approval_id",
            "artifact_hash",
            "artifact_id",
            "expires_at",
            "harness",
            "integrity_key_id",
            "integrity_status",
            "integrity_version",
            "publisher",
            "request_id",
            "source",
            "signed_at",
            "updated_at",
            "workspace",
        )
        if expected_decision is not None and any(
            decision.get(key) != expected_decision.get(key) for key in identity_keys
        ):
            return None
        if not consume:
            return decision
        claimed_row = {**_local_once_approval_signed_payload(row), "claimed_at": now}
        claimed_integrity = sign_local_authority_payload(
            claimed_row,
            key=integrity_key,
            key_id=integrity_key_id,
            purpose=_LOCAL_ONCE_INTEGRITY_PURPOSE,
            signed_at=now,
        )
        claim_cursor = connection.execute(
            """
            update guard_local_once_approvals
            set claimed_at = ?, integrity_version = ?, payload_hash = ?, payload_mac = ?,
                integrity_key_id = ?, signed_at = ?
            where approval_id = ? and claimed_at is null
            """,
            (
                now,
                claimed_integrity["integrity_version"],
                claimed_integrity["payload_hash"],
                claimed_integrity["payload_mac"],
                claimed_integrity["integrity_key_id"],
                claimed_integrity["signed_at"],
                approval_id,
            ),
        )
        if claim_cursor.rowcount != 1:
            return None
        return decision

    @staticmethod
    def _claim_local_once_approval_locked(
        connection: sqlite3.Connection,
        *,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        now: str,
        integrity_key: bytes | None = None,
        integrity_key_id: str | None = None,
    ) -> dict[str, object] | None:
        decision = StoreEventReceiptsMixin._peek_local_once_approval_locked(
            connection,
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            integrity_key=integrity_key,
            integrity_key_id=integrity_key_id,
        )
        if decision is None:
            return None
        # Preserve the legacy package replay behavior for existing consuming
        # resolution callers. Current-policy-first callers explicitly claim a
        # selected decision only after approval reuse is accepted.
        decision_artifact_id = decision.get("artifact_id")
        if isinstance(decision_artifact_id, str) and _local_once_approval_is_reusable(decision_artifact_id):
            return decision
        return StoreEventReceiptsMixin._claim_local_once_approval_by_id_locked(
            connection,
            approval_id=str(decision["approval_id"]),
            now=now,
            integrity_key=integrity_key,
            integrity_key_id=integrity_key_id,
        )

    def peek_local_once_approval(
        self,
        *,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        now: str,
    ) -> dict[str, object] | None:
        """Return exact unexpired approval evidence without consuming it."""

        integrity_key, integrity_key_id = self._policy_integrity_secret_material(create=False)
        with self._connect() as connection:
            return self._peek_local_once_approval_locked(
                connection,
                harness=harness,
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=now,
                integrity_key=integrity_key,
                integrity_key_id=integrity_key_id,
            )

    def claim_local_once_approval(
        self,
        approval_id: str,
        *,
        claimed_at: str,
        expected_decision: Mapping[str, object] | None = None,
    ) -> bool:
        """Atomically consume previously inspected approval evidence by id."""

        integrity_key, integrity_key_id = self._policy_integrity_secret_material(create=False)
        with self._connect() as connection:
            connection.execute("begin immediate")
            decision = self._claim_local_once_approval_by_id_locked(
                connection,
                approval_id=approval_id,
                now=claimed_at,
                expected_decision=expected_decision,
                integrity_key=integrity_key,
                integrity_key_id=integrity_key_id,
            )
            if decision is None:
                return False
            connection.execute(
                """
                insert into guard_events (event_name, payload_json, occurred_at)
                values (?, ?, ?)
                """,
                (
                    "approval.local_once_applied",
                    json.dumps(
                        {
                            "approval_id": decision.get("approval_id"),
                            "request_id": decision.get("request_id"),
                            "harness": decision.get("harness"),
                            "artifact_id": decision.get("artifact_id"),
                        }
                    ),
                    claimed_at,
                ),
            )
            return True

    def claim_remote_once_receipt(
        self,
        receipt_id: str,
        *,
        request_id: str,
        claimed_at: str,
    ) -> bool:
        with self._connect() as connection:
            connection.execute("begin immediate")
            try:
                connection.execute(
                    """
                    insert into guard_remote_once_receipts (receipt_id, request_id, claimed_at)
                    values (?, ?, ?)
                    """,
                    (receipt_id, request_id, claimed_at),
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def release_remote_once_receipt(self, receipt_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "delete from guard_remote_once_receipts where receipt_id = ?",
                (receipt_id,),
            )

    def has_remote_once_receipt(self, receipt_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "select 1 from guard_remote_once_receipts where receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        return row is not None

    def list_events(self, limit: int = 100, event_name: str | None = None) -> list[dict[str, object]]:
        query, params = _list_events_query(limit, event_name)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            items.append(
                {
                    "event_id": int(row["event_id"]),
                    "event_name": str(row["event_name"]),
                    "occurred_at": str(row["occurred_at"]),
                    "payload": payload,
                }
            )
        return items

    def list_events_after(
        self,
        event_id: int,
        *,
        limit: int = 100,
        event_names: tuple[str, ...] | None = None,
    ) -> list[dict[str, object]]:
        query = """
            select event_id, event_name, payload_json, occurred_at
            from guard_events
            where event_id > ?
        """
        params: list[object] = [event_id]
        if event_names:
            placeholders = ", ".join("?" for _ in event_names)
            query += f" and event_name in ({placeholders})"
            params.extend(event_names)
        query += " order by event_id asc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            items.append(
                {
                    "event_id": int(row["event_id"]),
                    "event_name": str(row["event_name"]),
                    "occurred_at": str(row["occurred_at"]),
                    "payload": payload,
                }
            )
        return items


def _local_once_approval_signed_payload(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "approval_id": _row_value(row, "approval_id"),
        "request_id": _row_value(row, "request_id"),
        "harness": _row_value(row, "harness"),
        "artifact_id": _row_value(row, "artifact_id"),
        "artifact_hash": _row_value(row, "artifact_hash"),
        "workspace": _row_value(row, "workspace"),
        "publisher": _row_value(row, "publisher"),
        "action": _row_value(row, "action"),
        "created_at": _row_value(row, "created_at"),
        "expires_at": _row_value(row, "expires_at"),
        "claimed_at": _row_value(row, "claimed_at"),
    }


def _local_once_approval_integrity(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "integrity_version": _row_value(row, "integrity_version"),
        "payload_hash": _row_value(row, "payload_hash"),
        "payload_mac": _row_value(row, "payload_mac"),
        "integrity_key_id": _row_value(row, "integrity_key_id"),
        "signed_at": _row_value(row, "signed_at"),
    }


def _verify_local_once_approval(
    row: Mapping[str, object],
    *,
    key: bytes | None,
    key_id: str | None,
) -> PolicyIntegrityVerificationResult:
    return verify_local_authority_payload(
        _local_once_approval_signed_payload(row),
        _local_once_approval_integrity(row),
        key=key,
        key_id=key_id,
        purpose=_LOCAL_ONCE_INTEGRITY_PURPOSE,
    )


def _local_once_approval_integrity_failure(
    row: Mapping[str, object],
    *,
    integrity_result: PolicyIntegrityVerificationResult,
) -> dict[str, object]:
    return {
        "approval_id": _row_value(row, "approval_id"),
        "decision_id": None,
        "harness": _row_value(row, "harness"),
        "artifact_id": _row_value(row, "artifact_id"),
        "scope": "artifact",
        "source": "approval-gate-once",
        "integrity_status": integrity_result.status,
        "integrity_message": integrity_result.message,
    }


def _local_once_approval_payload(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "action": str(row["action"]),
        "approval_id": str(row["approval_id"]),
        "artifact_hash": row["artifact_hash"],
        "artifact_id": row["artifact_id"],
        "decision_id": None,
        "expires_at": row["expires_at"],
        "harness": str(row["harness"]),
        "integrity_key_id": row["integrity_key_id"],
        "integrity_status": "valid",
        "integrity_version": row["integrity_version"],
        "owner": None,
        "publisher": row["publisher"],
        "reason": "approved once in review",
        "request_id": str(row["request_id"]),
        "scope": "artifact",
        "source": "approval-gate-once",
        "signed_at": row["signed_at"],
        "updated_at": str(row["created_at"]),
        "workspace": row["workspace"],
    }


def _row_value(row: Mapping[str, object], key: str) -> object:
    try:
        return row[key]
    except KeyError:
        return None
