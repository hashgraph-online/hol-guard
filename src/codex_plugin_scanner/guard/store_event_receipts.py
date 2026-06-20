"""GuardStore domain mixin extracted from store.py."""

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


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
        approval_id = uuid4().hex
        workspace_key = _workspace_policy_key(workspace)
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_local_once_approvals (
                  approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
                  created_at, expires_at, claimed_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null)
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
                ),
            )
        return approval_id

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
    ) -> dict[str, object] | None:
        if not artifact_id or not artifact_hash:
            return None
        workspace_key = _workspace_policy_key(workspace)
        row = connection.execute(
            """
            select approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
                   created_at, expires_at
            from guard_local_once_approvals
            where claimed_at is null
              and harness = ?
              and artifact_id = ?
              and artifact_hash = ?
              and expires_at > ?
              and (workspace is null or workspace = ?)
              and (publisher is null or publisher = ?)
            order by created_at desc
            limit 1
            """,
            (harness, artifact_id, artifact_hash, now, workspace_key, publisher),
        ).fetchone()
        if row is None:
            return None
        claim_cursor = connection.execute(
            "update guard_local_once_approvals set claimed_at = ? where approval_id = ? and claimed_at is null",
            (now, str(row["approval_id"])),
        )
        if claim_cursor.rowcount != 1:
            return None
        return {
            "action": str(row["action"]),
            "approval_id": str(row["approval_id"]),
            "artifact_hash": row["artifact_hash"],
            "artifact_id": row["artifact_id"],
            "decision_id": None,
            "expires_at": row["expires_at"],
            "harness": str(row["harness"]),
            "owner": None,
            "publisher": row["publisher"],
            "reason": "approved once in review",
            "request_id": str(row["request_id"]),
            "scope": "artifact",
            "source": "approval-gate-once",
            "updated_at": str(row["created_at"]),
            "workspace": row["workspace"],
        }

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
        query = """
            select event_id, event_name, payload_json, occurred_at
            from guard_events
        """
        params: tuple[object, ...] = ()
        if event_name is not None:
            query += " where event_name = ?"
            params = (event_name,)
        query += " order by occurred_at desc, event_id desc limit ?"
        params = (*params, limit)
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
