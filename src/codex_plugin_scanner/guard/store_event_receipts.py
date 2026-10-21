"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from .local_authority_integrity import verify_local_authority_payload
from .policy_integrity import PolicyIntegrityVerificationResult

# ruff: noqa: F403,F405
from .store_base import *
from .store_local_once_authority import (
    local_once_integrity_purpose,
    persist_local_once_approval,
)


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
        key, key_id = self._policy_integrity_secret_material(create=True)
        if key is None or key_id is None:
            return None
        with self._connect() as connection:
            return persist_local_once_approval(
                connection,
                request_id=request_id,
                harness=harness,
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                action=action,
                created_at=created_at,
                expires_at=expires_at,
                integrity_key=key,
                integrity_key_id=key_id,
            )

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
    payload = {
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
    authority_kind = _row_value(row, "authority_kind")
    if authority_kind is not None:
        payload["authority_kind"] = authority_kind
    return payload


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
    authority_kind = _row_value(row, "authority_kind")
    return verify_local_authority_payload(
        _local_once_approval_signed_payload(row),
        _local_once_approval_integrity(row),
        key=key,
        key_id=key_id,
        purpose=local_once_integrity_purpose(authority_kind),
    )


def _local_once_approval_payload(row: Mapping[str, object]) -> dict[str, object]:
    payload = {
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
    authority_kind = _row_value(row, "authority_kind")
    if authority_kind is not None:
        payload["authority_kind"] = authority_kind
    return payload


def _row_value(row: Mapping[str, object], key: str) -> object:
    try:
        return row[key]
    except KeyError:
        return None
