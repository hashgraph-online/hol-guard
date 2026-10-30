"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import cast

# ruff: noqa: F403,F405
from .managed_install_revision import bump_managed_install_revision
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
        from .codex_install_transaction import codex_install_transaction
        from .runtime_transition import assert_transition_mutation_allowed

        try:
            with codex_install_transaction(self.guard_home, self.path, actor="managed-install-record"):
                assert_transition_mutation_allowed(self.guard_home)
                self._set_managed_install_owned(harness, active, workspace, manifest, now)
        finally:
            bump_managed_install_revision()

    def _set_managed_install_owned(
        self, harness: str, active: bool, workspace: str | None, manifest: dict[str, object], now: str
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

    def compare_and_set_managed_installs(
        self,
        changes: Sequence[tuple[str, tuple[dict[str, object] | None, ...], dict[str, object] | None]],
        *,
        before_mutation: Callable[[], None],
    ) -> bool:
        """Compare every row before invoking the file inverse; commit rows together.

        A crash during the callback rolls SQLite back. The signed file plan
        can then recover its independently durable before/after byte states.
        """
        try:
            from .codex_install_transaction import require_codex_install_owner

            require_codex_install_owner(self.guard_home)
            harnesses = [change[0] for change in changes]
            if len(harnesses) != len(set(harnesses)):
                raise ValueError("Duplicate managed-install transition target")
            with self._connect() as connection:
                # These rows participate in the durable file inverse. Preserve
                # them across power loss as well as process interruption.
                connection.execute("pragma synchronous=FULL")
                connection.execute("begin immediate")
                for harness, allowed, replacement in changes:
                    if not allowed or (replacement is not None and replacement.get("harness") != harness):
                        raise ValueError("Invalid managed-install transition target")
                    row = connection.execute(
                        "select harness, active, workspace, manifest_json, updated_at "
                        "from managed_installs where harness = ?",
                        (harness,),
                    ).fetchone()
                    current = (
                        None
                        if row is None
                        else {
                            "harness": str(row["harness"]),
                            "active": bool(row["active"]),
                            "workspace": row["workspace"],
                            "manifest": json.loads(str(row["manifest_json"])),
                            "updated_at": str(row["updated_at"]),
                        }
                    )
                    if current not in allowed:
                        return False
                before_mutation()
                for harness, _allowed, replacement in changes:
                    if replacement is None:
                        connection.execute("delete from managed_installs where harness = ?", (harness,))
                    else:
                        connection.execute(
                            """insert into managed_installs (harness, active, workspace, manifest_json, updated_at)
                            values (?, ?, ?, ?, ?) on conflict(harness) do update set
                            active = excluded.active, workspace = excluded.workspace,
                            manifest_json = excluded.manifest_json, updated_at = excluded.updated_at""",
                            (
                                harness,
                                1 if replacement["active"] else 0,
                                replacement["workspace"],
                                json.dumps(replacement["manifest"]),
                                replacement["updated_at"],
                            ),
                        )
            return True
        finally:
            bump_managed_install_revision()

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

    def set_sync_payload(self, state_key: str, payload: Mapping[str, object] | Sequence[object], now: str) -> None:
        oauth_changed = state_key == _OAUTH_LOCAL_CREDENTIALS_STATE_KEY or state_key.startswith(
            _OAUTH_LOCAL_CREDENTIALS_STATE_KEY + ":"
        )
        if oauth_changed:
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
        if oauth_changed:
            from .review_event_wake import review_event_wake_signal

            review_event_wake_signal(self.path).notify()

    def insert_sync_payload_if_absent(self, state_key: str, payload: Mapping[str, object], now: str) -> None:
        """Store ``payload`` only when ``state_key`` has no row; an existing row always wins."""

        with self._connect() as connection:
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do nothing
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
        self._native_store_call(
            "add_guard_event_v1",
            {
                "event": event.to_dict(),
                "event_queue_limit": self._guard_event_queue_limit,
                "now": datetime.now(timezone.utc).isoformat(),
            },
        )

    def _add_guard_event_v1(self, connection: sqlite3.Connection, event: GuardEventV1) -> None:
        payload = event.to_dict()
        existing = connection.execute(
            "select event_id from guard_cloud_events where idempotency_key = ?",
            (event.idempotency_key,),
        ).fetchone()
        if existing is None:
            pending_count = self._count_guard_events_v1_in_connection(connection, uploaded=False)
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

    def list_guard_events_v1(self, *, uploaded: bool | None = None, limit: int = 200) -> list[dict[str, object]]:
        return self._native_store_call(
            "list_guard_events_v1",
            {"uploaded": uploaded, "limit": limit, "now": datetime.now(timezone.utc).isoformat()},
        )

    def count_guard_events_v1(self, *, uploaded: bool | None = None) -> int:
        return int(self._native_store_call("count_guard_events_v1", {"uploaded": uploaded}))

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
        return int(
            self._native_store_call(
                "mark_guard_events_v1_uploaded",
                {
                    "event_ids": event_ids,
                    "uploaded_at": uploaded_at,
                    "event_queue_limit": self._guard_event_queue_limit,
                },
            )
        )

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        self._native_store_call(
            "add_event",
            {"event_name": event_name, "payload_json": json.dumps(payload), "occurred_at": now},
        )
