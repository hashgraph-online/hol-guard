"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import cast

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
        from .native_owned import codex_install_transaction
        from .runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(self.guard_home, self.path, actor="managed-install-record"):
            assert_transition_mutation_allowed(self.guard_home)
            self._set_managed_install_owned(harness, active, workspace, manifest, now)

    def managed_install_revision(self) -> int:
        """How many writes the managed-install table has seen, as the runtime counts them."""
        return int(self._native_store_call("get_managed_install_revision", {}))

    def _set_managed_install_owned(
        self, harness: str, active: bool, workspace: str | None, manifest: dict[str, object], now: str
    ) -> None:
        self._native_store_call(
            "set_managed_install",
            {
                "harness": harness,
                "active": active,
                "workspace": workspace,
                "manifest_json": json.dumps(manifest),
                "now": now,
            },
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
        from .native_owned import require_codex_install_owner

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
            connection.execute(
                """insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)
                on conflict(state_key) do update set
                payload_json = json_object('revision',
                    coalesce(json_extract(sync_state.payload_json, '$.revision'), 0) + 1),
                updated_at = excluded.updated_at""",
                (
                    "managed_install_revision",
                    '{"revision": 1}',
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return True

    def get_managed_install(self, harness: str) -> dict[str, object] | None:
        row = self._native_store_call("get_managed_install", {"harness": harness})
        return None if row is None else _managed_install_row(row)

    def list_managed_installs(self) -> list[dict[str, object]]:
        return [_managed_install_row(row) for row in self._native_store_call("list_managed_installs", {})]

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
        oauth_changed = _is_oauth_credentials_key(state_key)
        args = {"state_key": state_key, "payload": _payload_arg(payload), "now": now}
        if not oauth_changed:
            self._native_store_call("set_sync_payload", args)
            return
        self._clear_oauth_secret_payload_cache()
        self._native_store_call("write_credential_sync_payload", args)
        from .review_event_wake import review_event_wake_signal

        review_event_wake_signal(self.path).notify()

    def insert_sync_payload_if_absent(self, state_key: str, payload: Mapping[str, object], now: str) -> None:
        """Store ``payload`` only when ``state_key`` has no row; an existing row always wins."""

        self._native_store_call(
            "insert_sync_payload_if_absent",
            {"state_key": state_key, "payload": _payload_arg(payload), "now": now},
        )

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        # Read in Python on purpose: device identity and the Cloud sync profile
        # are read before the native store is provisioned, and a malformed row
        # must raise ValueError so status views report it instead of a blank.
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

    def record_command_queue_lease_limit(self, state_key: str, limit: int, *, now: str) -> bool:
        """Merge a queue lane's exact Review lease batch limit into its stored row.

        Only the limit is written; every other field keeps its stored value.
        Returns whether the row changed.
        """

        answer = self._native_store_call(
            "record_command_queue_lease_limit", {"state_key": state_key, "limit": limit, "now": now}
        )
        return isinstance(answer, dict) and answer.get("saved") is True

    def transition_command_queue_state(
        self,
        state_key: str,
        transition: str,
        *,
        now: str,
        at: str | None = None,
        pending: dict[str, object] | None = None,
        **detail: object,
    ) -> dict[str, object]:
        """Move a queue lane's stored row through one named job step.

        The native store owns which fields each step sets and removes, and
        merges them into the stored row so every other field keeps its stored
        value. ``at`` is the time the step records, ``now`` the row's write
        time. ``detail`` carries a step's other inputs (``job``,
        ``failed_state``, ``error``) and ``route_error``, which is sent as
        given: ``None`` clears the stored route error. Returns the merged row.
        """

        args: dict[str, object] = {"state_key": state_key, "transition": transition, "now": now, **detail}
        if at is not None:
            args["at"] = at
        if pending is not None:
            args["pending"] = pending
        answer = self._native_store_call("transition_command_queue_state", args)
        state = answer.get("state") if isinstance(answer, dict) else None
        if not isinstance(state, dict):
            raise RuntimeError("native queue state transition returned no state")
        return dict(state)

    def transition_cloud_review_sync_state(
        self,
        state_key: str,
        transition: str,
        *,
        now: str,
        **detail: object,
    ) -> dict[str, object]:
        """Move the Cloud Review sync state row through one named sync step.

        The native store owns which fields each step sets and merges them into
        the stored row, so every other field keeps its stored value. ``detail``
        carries the step's inputs (``binding_key``, ``limits``, ``counts``,
        ``outbox``, ``delivery_binding``, ``error``, ``error_code``,
        ``keep_auth_code``). Returns the merged row.
        """

        answer = self._native_store_call(
            "transition_cloud_review_sync_state",
            {"state_key": state_key, "transition": transition, "now": now, **detail},
        )
        state = answer.get("state") if isinstance(answer, dict) else None
        if not isinstance(state, dict):
            raise RuntimeError("native review sync state transition returned no state")
        return dict(state)

    def workspace_review_enrollment_due(self, auth: dict[str, object], *, now: str) -> list[str] | None:
        """The binding for ``auth`` when a workspace enrollment check is due.

        The native store builds the binding from the connection fields and
        reads the schedule row. ``None`` means no check is due, either because
        the connection is incomplete or the last check is still fresh.
        """

        answer = self._native_store_call("workspace_review_enrollment_due", {"auth": auth, "now": now})
        if not isinstance(answer, dict) or answer.get("due") is not True:
            return None
        binding = answer.get("binding")
        if not isinstance(binding, list) or not all(isinstance(field, str) for field in binding):
            raise RuntimeError("native workspace enrollment check returned no binding")
        return [str(field) for field in binding]

    def record_workspace_review_enrollment(
        self,
        binding: list[str],
        *,
        outcome: str,
        now: str,
        **detail: object,
    ) -> dict[str, object]:
        """Record one workspace enrollment check and schedule the next.

        ``outcome`` is ``enrolled`` (with ``record``, the installed authority
        text) or ``unavailable`` (with ``http_status``, or ``error_type`` and
        an optional ``error_code``). Returns the stored row.
        """

        answer = self._native_store_call(
            "record_workspace_review_enrollment",
            {"binding": binding, "outcome": outcome, "now": now, **detail},
        )
        state = answer.get("state") if isinstance(answer, dict) else None
        if not isinstance(state, dict):
            raise RuntimeError("native workspace enrollment record returned no state")
        return dict(state)

    def list_cloud_exceptions(self, harness: str | None = None) -> list[dict[str, object]]:
        from .native_runner_authority import NativeRunnerAuthorityError
        from .runtime.runner_native_sync import cloud_exceptions
        from .synced_policy import PolicyTrustRowsReader, validated_synced_policy_bundle

        policy_bundle = validated_synced_policy_bundle(cast(PolicyTrustRowsReader, cast(object, self)))
        if policy_bundle is None:
            return []
        try:
            device_metadata = self.get_device_metadata()
            device_id = str(device_metadata["installation_id"])
        except (KeyError, OSError, RuntimeError, TypeError, ValueError):
            return []
        acknowledgement = self.get_sync_payload("policy_bundle_ack")
        try:
            return cloud_exceptions(
                policy_bundle,
                device_id=device_id,
                policy_bundle_ack=acknowledgement if isinstance(acknowledgement, dict) else None,
                harness=harness,
                active_at=datetime.now(timezone.utc).isoformat(),
            )
        except NativeRunnerAuthorityError:
            # An exception only ever widens what runs, so one the runtime could
            # not read is not listed as in force.
            return []

    def delete_sync_payload(self, state_key: str) -> None:
        if _is_oauth_credentials_key(state_key):
            self._clear_oauth_secret_payload_cache()
        self._native_store_call("delete_sync_payload", {"state_key": state_key})

    def delete_sync_payloads(self, state_keys: list[str]) -> int:
        if not state_keys:
            return 0
        if any(_is_oauth_credentials_key(state_key) for state_key in state_keys):
            self._clear_oauth_secret_payload_cache()
        deleted = self._native_store_call("delete_sync_payloads", {"state_keys": list(state_keys)})
        if not isinstance(deleted, int) or isinstance(deleted, bool):
            raise RuntimeError("native delete_sync_payloads returned no count")
        return deleted

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


def _managed_install_row(row: dict[str, object]) -> dict[str, object]:
    """The native row with its manifest decoded as the SQLite read did."""
    return {
        "harness": str(row["harness"]),
        "active": bool(row["active"]),
        "workspace": row["workspace"],
        "manifest": json.loads(str(row["manifest_json"])),
        "updated_at": str(row["updated_at"]),
    }


def _is_oauth_credentials_key(state_key: str) -> bool:
    """The OAuth credential row, or one scoped to a credential namespace."""

    return state_key == _OAUTH_LOCAL_CREDENTIALS_STATE_KEY or state_key.startswith(
        _OAUTH_LOCAL_CREDENTIALS_STATE_KEY + ":"
    )


def _payload_arg(payload: Mapping[str, object] | Sequence[object]) -> object:
    """A mapping as a plain dict and a sequence as a list; the native store refuses anything else."""

    if isinstance(payload, Mapping):
        return dict(payload)
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
        return list(payload)
    return payload
