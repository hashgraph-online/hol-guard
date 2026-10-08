"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from collections.abc import Sequence
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import cast

# ruff: noqa: F403,F405
from .store_base import *
from .store_receipt_rollups import reconcile_dirty_receipt_rollups, reconcile_pending_receipt_events


class StoreCloudEventsMixin:
    def reserve_sync_sequence(
        self,
        state_key: str,
        field: str,
        now: str,
        *,
        floor: int = 0,
    ) -> int:
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (state_key,),
            ).fetchone()
            payload: dict[str, object] = {}
            if row is not None:
                decoded = json.loads(str(row["payload_json"]))
                if isinstance(decoded, dict):
                    payload = decoded
            current = payload.get(field, 0)
            current_sequence = current if isinstance(current, int) and not isinstance(current, bool) else 0
            sequence = max(current_sequence, floor) + 1
            payload[field] = sequence
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (state_key, json.dumps(payload), now),
            )
            return sequence

    def _review_memory_oauth_rebind(
        self, state_key: str, payload: Mapping[str, object] | Sequence[object] | None
    ) -> bool:
        if state_key != self._oauth_local_credentials_state_key:
            return False
        if not self.get_sync_payload("guard_review_memory_registry"):
            return False
        existing = self.get_sync_payload(state_key)
        if not isinstance(existing, dict) or not isinstance(payload, Mapping):
            return True
        fields = (
            "issuer",
            "client_id",
            "grant_id",
            "machine_id",
            "device_id",
            "installation_id",
            "workspace_id",
            "dpop_public_jwk_thumbprint",
        )
        return any(existing.get(field) != payload.get(field) for field in fields)

    def _notify_review_memory_rebind(self) -> None:
        from .native_policy_snapshot import notify_native_policy_mutation

        notify_native_policy_mutation(self.guard_home)

    def set_sync_payload(self, state_key: str, payload: Mapping[str, object] | Sequence[object], now: str) -> None:
        oauth_changed = state_key == _OAUTH_LOCAL_CREDENTIALS_STATE_KEY or state_key.startswith(
            _OAUTH_LOCAL_CREDENTIALS_STATE_KEY + ":"
        )
        if oauth_changed:
            self._clear_oauth_secret_payload_cache()
        memory_rebind = self._review_memory_oauth_rebind(state_key, payload)
        with self._extension_control_authority_lock() if memory_rebind else nullcontext():
            if memory_rebind:
                self._invalidate_native_extension_control_policy()
            with self._connect() as connection:
                if memory_rebind:
                    self._clear_review_policy_memory_locked(connection)
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (state_key, json.dumps(payload), now),
                )
        if memory_rebind:
            self._notify_review_memory_rebind()
        if oauth_changed:
            from .review_event_wake import review_event_wake_signal

            review_event_wake_signal(self.path).notify()

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (state_key,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        if isinstance(payload, (dict, list)):
            return payload
        return None

    def set_cloud_exceptions(self, items: list[dict[str, object]], now: str) -> None:
        self.set_sync_payload("cloud_exceptions", items, now)

    def list_cloud_exceptions(self, harness: str | None = None) -> list[dict[str, object]]:
        from .cloud_exceptions import (
            build_cloud_exceptions_from_policy_bundle,
            cloud_exception_to_dict,
            dedupe_cloud_exceptions,
            list_active_cloud_exceptions,
        )
        from .synced_policy import SyncPayloadReader, validated_synced_policy_bundle

        policy_bundle = validated_synced_policy_bundle(cast(SyncPayloadReader, cast(object, self)))
        if policy_bundle is None:
            return []
        try:
            device_metadata = self.get_device_metadata()
            device_id = str(device_metadata["installation_id"])
        except (KeyError, OSError, RuntimeError, TypeError, ValueError):
            return []
        acknowledgement = self.get_sync_payload("policy_bundle_ack")
        parsed_items = build_cloud_exceptions_from_policy_bundle(
            policy_bundle,
            device_id=device_id,
            policy_bundle_ack=acknowledgement if isinstance(acknowledgement, dict) else None,
        )
        active_items = list_active_cloud_exceptions(dedupe_cloud_exceptions(parsed_items), harness=harness)
        return [cloud_exception_to_dict(item) for item in active_items]

    def delete_sync_payload(self, state_key: str) -> None:
        if state_key == _OAUTH_LOCAL_CREDENTIALS_STATE_KEY:
            self._clear_oauth_secret_payload_cache()
        memory_rebind = self._review_memory_oauth_rebind(state_key, None)
        with self._extension_control_authority_lock() if memory_rebind else nullcontext():
            if memory_rebind:
                self._invalidate_native_extension_control_policy()
            with self._connect() as connection:
                if memory_rebind:
                    self._clear_review_policy_memory_locked(connection)
                connection.execute(
                    "delete from sync_state where state_key = ?",
                    (state_key,),
                )
        if memory_rebind:
            self._notify_review_memory_rebind()

    def delete_sync_payloads(self, state_keys: list[str]) -> int:
        if not state_keys:
            return 0
        placeholders = ",".join("?" for _ in state_keys)
        memory_rebind = any(self._review_memory_oauth_rebind(state_key, None) for state_key in state_keys)
        with self._extension_control_authority_lock() if memory_rebind else nullcontext():
            if memory_rebind:
                self._invalidate_native_extension_control_policy()
            with self._connect() as connection:
                if memory_rebind:
                    self._clear_review_policy_memory_locked(connection)
                cursor = connection.execute(
                    f"delete from sync_state where state_key in ({placeholders})",
                    tuple(state_keys),
                )
                count = int(cursor.rowcount if cursor.rowcount is not None else 0)
        if memory_rebind:
            self._notify_review_memory_rebind()
        return count

    def add_guard_event_v1(self, event: GuardEventV1) -> None:
        with self._connect() as connection:
            self._add_guard_event_v1(connection, event)

    def _add_guard_event_v1(self, connection: sqlite3.Connection, event: GuardEventV1) -> None:
        payload = event.to_dict()
        existing = connection.execute(
            "select event_id from guard_cloud_events where idempotency_key = ?",
            (event.idempotency_key,),
        ).fetchone()
        if existing is None:
            pending_count = self._count_guard_event_upload_capacity(connection)
            if pending_count >= self._guard_event_queue_limit:
                capacity_row = connection.execute(
                    "select payload_json from sync_state where state_key = ?",
                    ("guard_event_queue_capacity",),
                ).fetchone()
                capacity_payload: dict[str, object] = {}
                if capacity_row is not None:
                    try:
                        parsed_capacity_payload = json.loads(capacity_row["payload_json"])
                    except (json.JSONDecodeError, TypeError, ValueError):
                        parsed_capacity_payload = {}
                    if isinstance(parsed_capacity_payload, dict):
                        capacity_payload = parsed_capacity_payload
                rejected_count_value = capacity_payload.get("rejectedCount", 0)
                rejected_count = (
                    rejected_count_value
                    if isinstance(rejected_count_value, int) and not isinstance(rejected_count_value, bool)
                    else 0
                ) + 1
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (
                        "guard_event_queue_capacity",
                        json.dumps(
                            {
                                "exhausted": True,
                                "firstRejectedAt": capacity_payload.get("firstRejectedAt", event.occurred_at),
                                "lastRejectedAt": event.occurred_at,
                                "limit": self._guard_event_queue_limit,
                                "pendingCount": pending_count,
                                "rejectedCount": rejected_count,
                                "rejectedEventType": event.event_type,
                            },
                            sort_keys=True,
                        ),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                return
        connection.execute(
            """
            insert or ignore into guard_cloud_events (
              event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
            )
            values (?, ?, ?, ?, ?, null)
            """,
            (
                event.event_id,
                event.idempotency_key,
                event.event_type,
                json.dumps(payload, sort_keys=True),
                event.occurred_at,
            ),
        )

    def list_guard_events_v1(
        self,
        *,
        uploaded: bool | None = None,
        limit: int = 200,
        after: tuple[str, str] | None = None,
    ) -> list[dict[str, object]]:
        query = """
            select event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
            from guard_cloud_events
        """
        params: list[object] = []
        filters: list[str] = []
        if uploaded is True:
            filters.append("uploaded_at is not null")
        elif uploaded is False:
            filters.append("uploaded_at is null")
        if after is not None:
            occurred_at, event_id = after
            filters.append("(occurred_at > ? or (occurred_at = ? and event_id > ?))")
            params.extend((occurred_at, occurred_at, event_id))
        if filters:
            query += " where " + " and ".join(filters)
        query += " order by occurred_at asc, event_id asc limit ?"
        params.append(limit)
        with self._connect() as connection:
            if receipt_rollups_need_backfill(connection):
                backfill_receipt_rollups(connection)
            else:
                reconcile_dirty_receipt_rollups(connection)
            reconcile_pending_receipt_events(connection)
            rows = connection.execute(query, tuple(params)).fetchall()
        events: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            events.append(
                {
                    "event_id": str(row["event_id"]),
                    "idempotency_key": str(row["idempotency_key"]),
                    "event_type": str(row["event_type"]),
                    "occurred_at": str(row["occurred_at"]),
                    "uploaded_at": row["uploaded_at"],
                    "payload": payload,
                }
            )
        return events

    def count_guard_events_v1(self, *, uploaded: bool | None = None) -> int:
        with self._connect() as connection:
            return self._count_guard_events_v1_in_connection(connection, uploaded=uploaded)

    @staticmethod
    def _count_guard_events_v1_in_connection(connection: sqlite3.Connection, *, uploaded: bool | None = None) -> int:
        query = "select count(*) as count from guard_cloud_events"
        if uploaded is True:
            query += " where uploaded_at is not null"
        elif uploaded is False:
            query += " where uploaded_at is null"
        row = connection.execute(query).fetchone()
        return int(row["count"]) if row is not None else 0

    def _count_guard_event_upload_capacity(self, connection: sqlite3.Connection) -> int:
        """Count events that can still be uploaded.

        A native activity row quarantined after a binding change stays stored and
        unacknowledged. It must not take a slot from an event the current binding
        can still send.
        """

        ledger = connection.execute(
            "select 1 from sqlite_master where type = 'table' and name = ?",
            ("native_activity_projection_ledger",),
        ).fetchone()
        if ledger is None:
            return self._count_guard_events_v1_in_connection(connection, uploaded=False)
        row = connection.execute(
            """
            select count(*) as count
            from guard_cloud_events as event
            where event.uploaded_at is null
              and not exists (
                select 1
                from native_activity_projection_ledger as ledger
                where ledger.idempotency_key = event.idempotency_key
                  and ledger.state = 'quarantined'
              )
            """
        ).fetchone()
        return int(row["count"]) if row is not None else 0

    def mark_guard_events_v1_uploaded(self, event_ids: list[str], uploaded_at: str) -> int:
        clean_ids = [event_id for event_id in event_ids if event_id.strip()]
        if not clean_ids:
            return 0
        placeholders = ", ".join("?" for _ in clean_ids)
        with self._connect() as connection:
            cursor = connection.execute(
                f"update guard_cloud_events set uploaded_at = ? where event_id in ({placeholders})",
                (uploaded_at, *clean_ids),
            )
            pending_count = self._count_guard_event_upload_capacity(connection)
            if pending_count < self._guard_event_queue_limit:
                capacity_row = connection.execute(
                    "select payload_json from sync_state where state_key = ?",
                    ("guard_event_queue_capacity",),
                ).fetchone()
                if capacity_row is not None:
                    try:
                        capacity_payload = json.loads(capacity_row["payload_json"])
                    except (json.JSONDecodeError, TypeError, ValueError):
                        capacity_payload = {}
                    if not isinstance(capacity_payload, dict):
                        capacity_payload = {}
                    capacity_payload.update(
                        {
                            "exhausted": False,
                            "pendingCount": pending_count,
                            "recoveredAt": uploaded_at,
                        }
                    )
                    connection.execute(
                        """
                        update sync_state
                        set payload_json = ?, updated_at = ?
                        where state_key = ?
                        """,
                        (
                            json.dumps(capacity_payload, sort_keys=True),
                            uploaded_at,
                            "guard_event_queue_capacity",
                        ),
                    )
            return int(cursor.rowcount)

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_events (event_name, payload_json, occurred_at)
                values (?, ?, ?)
                """,
                (event_name, json.dumps(payload), now),
            )
