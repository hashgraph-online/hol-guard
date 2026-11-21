"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .native_store_policy import encode_key
from .store_base import *

LOCAL_ONCE_LEGACY_AUTHORITY_KIND = "legacy"
EXACT_CLOUD_AUTHORITY_KIND = "exact-cloud"


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
        authority_kind: str = LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
    ) -> str | None:
        """Mint exact one-shot authority for an approval granted on this install.

        The row written here is the authority a later native review reads to
        allow an execution without asking again, so the resident signs it where
        the verdict is decided. This side reads the install key out of the
        keyring and ships it; it signs nothing and decides nothing. An install
        with no key material has no authority to mint, which is why that case
        answers ``None`` rather than calling.
        """

        key, key_id = self._policy_integrity_secret_material(create=True)
        if key is None or key_id is None:
            return None
        approval_id = self._native_store_call(
            "record_local_once_approval",
            {
                "request_id": request_id,
                "harness": harness,
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "workspace": workspace,
                "publisher": publisher,
                "action": action,
                "created_at": created_at,
                "expires_at": expires_at,
                "authority_kind": authority_kind,
                "integrity_key_b64": encode_key(key),
                "integrity_key_id": key_id,
            },
        )
        return None if approval_id is None else str(approval_id)

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
