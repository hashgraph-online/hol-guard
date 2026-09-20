"""Sync-state mutations shared by the existing cloud event store mixin."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .native_policy_authority_state_keys import NATIVE_POLICY_AUTHORITY_SYNC_KEYS
from .workspace_preference_authority import reject_private_preference_key

# pyright: reportAttributeAccessIssue=false


def _notify_native_policy_source_mutation(store: object, state_key: str, *, oauth_changed: bool = False) -> None:
    if state_key not in NATIVE_POLICY_AUTHORITY_SYNC_KEYS and not oauth_changed:
        return
    # Keep the store dependency direction acyclic. Publisher registration lives
    # behind this lazy facade and a write with no active publisher is a no-op.
    from .native_policy_snapshot import notify_native_policy_mutation

    notify_native_policy_mutation(store.guard_home, require_source_authority=True)


class StoreSyncPayloadMutationsMixin:
    def reserve_sync_sequence(
        self,
        state_key: str,
        field: str,
        now: str,
        *,
        floor: int = 0,
    ) -> int:
        from . import store_cloud_events as _cloud_events_api

        _cloud_events_api.reject_private_inventory_key(state_key)
        reject_private_preference_key(state_key)
        if state_key == _cloud_events_api.INVENTORY_CONTEXT_KEY:
            raise ValueError("Inventory selection is not a sequence counter.")
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (state_key,),
            ).fetchone()
            payload: dict[str, object] = {}
            if row is not None:
                decoded = _cloud_events_api.json.loads(str(row["payload_json"]))
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
                (state_key, _cloud_events_api.json.dumps(payload), now),
            )
            return sequence

    def set_sync_payload(
        self,
        state_key: str,
        payload: Mapping[str, object] | Sequence[object],
        now: str,
    ) -> None:
        from . import store_cloud_events as _cloud_events_api

        _cloud_events_api.reject_private_inventory_key(state_key)
        reject_private_preference_key(state_key)
        if state_key == _cloud_events_api.INVENTORY_CONTEXT_KEY:
            with self.hold_oauth_credential_lock():
                self._set_sync_payload_unlocked(state_key, payload, now)
            return
        if _cloud_events_api.is_oauth_credential_key(state_key):
            with self.hold_oauth_credential_lock():
                self._set_oauth_sync_payload_unlocked(state_key, payload, now)
            return
        self._set_sync_payload_unlocked(state_key, payload, now)

    def _set_oauth_sync_payload_unlocked(
        self,
        state_key: str,
        payload: Mapping[str, object] | Sequence[object],
        now: str,
        *,
        preserve_epoch: str | None = None,
    ) -> None:
        from . import store_cloud_events as _cloud_events_api

        if not _cloud_events_api.is_oauth_credential_key(state_key):
            raise ValueError("Invalid credential state key.")
        self._set_sync_payload_unlocked(state_key, payload, now, preserve_epoch=preserve_epoch)

    def _set_sync_payload_unlocked(
        self,
        state_key: str,
        payload: Mapping[str, object] | Sequence[object],
        now: str,
        *,
        preserve_epoch: str | None = None,
    ) -> None:
        from . import store_cloud_events as _cloud_events_api

        _cloud_events_api.reject_private_inventory_key(state_key)
        reject_private_preference_key(state_key)
        if state_key == _cloud_events_api.INVENTORY_CONTEXT_KEY:
            # Metadata and the public row must consume the same immutable copy,
            # even if the caller mutates its dictionary while this write runs.
            payload = _cloud_events_api.json.loads(_cloud_events_api.json.dumps(payload))
        oauth_changed = _cloud_events_api.is_oauth_credential_key(state_key)
        if oauth_changed:
            self._clear_oauth_secret_payload_cache()
        with self._connect() as connection:
            if state_key == _cloud_events_api.INVENTORY_CONTEXT_KEY:
                connection.execute("begin immediate")
                _cloud_events_api.record_inventory_context_mutation(connection, payload, now)
            if oauth_changed:
                if preserve_epoch is not None:
                    authority = _cloud_events_api.read_connection_authority(connection, state_key)
                    if authority.state != "ready" or authority.epoch != preserve_epoch:
                        raise RuntimeError("The connection changed before credentials could be refreshed.")
                else:
                    _cloud_events_api.advance_connection_epoch(connection, state_key, now)
                if isinstance(payload, _cloud_events_api.Mapping):
                    payload = {**payload, _cloud_events_api.CONNECTION_AUTHORITY_VERSION_KEY: 1}
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (state_key, _cloud_events_api.json.dumps(payload), now),
            )
        _notify_native_policy_source_mutation(self, state_key, oauth_changed=oauth_changed)
        if oauth_changed:
            from .review_event_wake import review_event_wake_signal

            review_event_wake_signal(self.path).notify()

    def delete_sync_payload(self, state_key: str) -> None:
        self.delete_sync_payloads([state_key])

    def delete_sync_payloads(self, state_keys: list[str]) -> int:
        from . import store_cloud_events as _cloud_events_api

        state_keys = list(state_keys)
        for key in state_keys:
            _cloud_events_api.reject_private_inventory_key(key)
            reject_private_preference_key(key)
        if any(
            _cloud_events_api.is_oauth_credential_key(key) or key == _cloud_events_api.INVENTORY_CONTEXT_KEY
            for key in state_keys
        ):
            with self.hold_oauth_credential_lock():
                return self._delete_sync_payloads_unlocked(state_keys)
        return self._delete_sync_payloads_unlocked(state_keys)

    def _delete_sync_payloads_unlocked(self, state_keys: list[str]) -> int:
        from . import store_cloud_events as _cloud_events_api

        state_keys = list(state_keys)
        for key in state_keys:
            _cloud_events_api.reject_private_inventory_key(key)
            reject_private_preference_key(key)
        if not state_keys:
            return 0
        credential_keys = {key for key in state_keys if _cloud_events_api.is_oauth_credential_key(key)}
        if credential_keys:
            self._clear_oauth_secret_payload_cache()
        placeholders = ",".join("?" for _ in state_keys)
        with self._connect() as connection:
            if _cloud_events_api.INVENTORY_CONTEXT_KEY in state_keys:
                connection.execute("begin immediate")
                _cloud_events_api.record_inventory_context_mutation(connection, None, _cloud_events_api._now())
            for key in sorted(credential_keys):
                _cloud_events_api.advance_connection_epoch(connection, key, _cloud_events_api._now())
            cursor = connection.execute(
                f"delete from sync_state where state_key in ({placeholders})",
                tuple(state_keys),
            )
            deleted = int(cursor.rowcount if cursor.rowcount is not None else 0)
        for key in state_keys:
            _notify_native_policy_source_mutation(
                self,
                key,
                oauth_changed=key in credential_keys,
            )
        return deleted
