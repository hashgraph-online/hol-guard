"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


class StoreCloudEventsMixin:
    def set_managed_install(
        self,
        harness: str,
        active: bool,
        workspace: str | None,
        manifest: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into managed_installs (harness, active, workspace, manifest_json, updated_at)
                values (?, ?, ?, ?, ?)
                on conflict(harness) do update set
                  active = excluded.active,
                  workspace = excluded.workspace,
                  manifest_json = excluded.manifest_json,
                  updated_at = excluded.updated_at
                """,
                (harness, 1 if active else 0, workspace, json.dumps(manifest), now),
            )

    def get_managed_install(self, harness: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select harness, active, workspace, manifest_json, updated_at from managed_installs where harness = ?",
                (harness,),
            ).fetchone()
        if row is None:
            return None
        return {
            "harness": str(row["harness"]),
            "active": bool(row["active"]),
            "workspace": row["workspace"],
            "manifest": json.loads(str(row["manifest_json"])),
            "updated_at": str(row["updated_at"]),
        }

    def list_managed_installs(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select harness, active, workspace, manifest_json, updated_at
                from managed_installs
                order by harness asc
                """
            ).fetchall()
        return [
            {
                "harness": str(row["harness"]),
                "active": bool(row["active"]),
                "workspace": row["workspace"],
                "manifest": json.loads(str(row["manifest_json"])),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def cache_advisories(self, advisories: list[dict[str, object]], now: str) -> int:
        stored = 0
        with self._connect() as connection:
            for advisory in advisories:
                cache_key = self._advisory_cache_key(advisory)
                connection.execute(
                    """
                    insert into publisher_cache (publisher_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(publisher_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (cache_key, json.dumps(advisory), now),
                )
                stored += 1
        return stored

    def list_cached_advisories(self, limit: int | None = 100) -> list[dict[str, object]]:
        with self._connect() as connection:
            if limit is None:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    limit ?
                    """,
                    (limit,),
                ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                continue
            items.append(
                {
                    "cache_key": str(row["publisher_key"]),
                    "updated_at": str(row["updated_at"]),
                    **payload,
                }
            )
        return items

    def cache_supply_chain_bundle(
        self,
        workspace_id: str,
        response: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_supply_chain_bundle(
                connection,
                workspace_id=workspace_id,
                response=response,
                cached_at=now,
            )

    def get_cached_supply_chain_bundle(self, workspace_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_supply_chain_bundle(connection, workspace_id=workspace_id)

    def cache_supply_chain_evaluation(
        self,
        *,
        workspace_id: str,
        package_intent_hash: str,
        feed_snapshot_hash: str,
        policy_hash: str,
        scoring_version: str,
        bundle_version: str,
        decision: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_supply_chain_evaluation(
                connection,
                workspace_id=workspace_id,
                package_intent_hash=package_intent_hash,
                feed_snapshot_hash=feed_snapshot_hash,
                policy_hash=policy_hash,
                scoring_version=scoring_version,
                bundle_version=bundle_version,
                decision=decision,
                updated_at=now,
            )

    def get_cached_supply_chain_evaluation(
        self,
        *,
        workspace_id: str,
        package_intent_hash: str,
        feed_snapshot_hash: str,
        policy_hash: str,
        scoring_version: str,
        bundle_version: str,
    ) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_supply_chain_evaluation(
                connection,
                workspace_id=workspace_id,
                package_intent_hash=package_intent_hash,
                feed_snapshot_hash=feed_snapshot_hash,
                policy_hash=policy_hash,
                scoring_version=scoring_version,
                bundle_version=bundle_version,
            )

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

    def set_sync_payload(self, state_key: str, payload: Mapping[str, object] | Sequence[object], now: str) -> None:
        if state_key == _OAUTH_LOCAL_CREDENTIALS_STATE_KEY or state_key.startswith(
            _OAUTH_LOCAL_CREDENTIALS_STATE_KEY + ":"
        ):
            self._clear_oauth_secret_payload_cache()
        with self._connect() as connection:
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
            build_cloud_exceptions_from_stored_items,
            cloud_exception_to_dict,
            list_active_cloud_exceptions,
        )

        payload = self.get_sync_payload("cloud_exceptions")
        raw_items: list[dict[str, object]] = []
        if isinstance(payload, list):
            raw_items = [item for item in payload if isinstance(item, dict)]
        elif isinstance(payload, dict):
            nested = payload.get("items")
            if isinstance(nested, list):
                raw_items = [item for item in nested if isinstance(item, dict)]
        parsed_items = build_cloud_exceptions_from_stored_items(raw_items)
        active_items = list_active_cloud_exceptions(parsed_items, harness=harness)
        return [cloud_exception_to_dict(item) for item in active_items]

    def delete_sync_payload(self, state_key: str) -> None:
        if state_key == _OAUTH_LOCAL_CREDENTIALS_STATE_KEY:
            self._clear_oauth_secret_payload_cache()
        with self._connect() as connection:
            connection.execute(
                "delete from sync_state where state_key = ?",
                (state_key,),
            )

    def delete_sync_payloads(self, state_keys: list[str]) -> int:
        if not state_keys:
            return 0
        placeholders = ",".join("?" for _ in state_keys)
        with self._connect() as connection:
            cursor = connection.execute(
                f"delete from sync_state where state_key in ({placeholders})",
                tuple(state_keys),
            )
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

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
            pending_count = self._count_guard_events_v1_in_connection(connection, uploaded=False)
            if pending_count >= self._guard_event_queue_limit:
                drop_count = pending_count - self._guard_event_queue_limit + 1
                cursor = connection.execute(
                    """
                    delete from guard_cloud_events
                    where event_id in (
                        select event_id
                        from guard_cloud_events
                        where uploaded_at is null
                        order by occurred_at asc, event_id asc
                        limit ?
                    )
                    """,
                    (drop_count,),
                )
                dropped_count = int(cursor.rowcount) if cursor.rowcount is not None and cursor.rowcount > 0 else 0
                if dropped_count > 0:
                    connection.execute(
                        """
                        insert into guard_events (event_name, payload_json, occurred_at)
                        values (?, ?, ?)
                        """,
                        (
                            "cloud_event_queue_overflow",
                            json.dumps(
                                {
                                    "dropped_count": dropped_count,
                                    "queue_limit": self._guard_event_queue_limit,
                                    "incoming_event_type": event.event_type,
                                }
                            ),
                            _now(),
                        ),
                    )
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

    def list_guard_events_v1(self, *, uploaded: bool | None = None, limit: int = 200) -> list[dict[str, object]]:
        query = """
            select event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
            from guard_cloud_events
        """
        params: list[object] = []
        if uploaded is True:
            query += " where uploaded_at is not null"
        elif uploaded is False:
            query += " where uploaded_at is null"
        query += " order by occurred_at asc, event_id asc limit ?"
        params.append(limit)
        with self._connect() as connection:
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
