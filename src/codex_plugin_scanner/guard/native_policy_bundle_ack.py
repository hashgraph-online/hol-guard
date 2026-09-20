"""Promote a received bundle ACK only behind the accepted native publication.

SQLite owns the write reservation first; taking the publisher condition never
waits. A busy condition rolls back, so publisher paths that need the store cannot
form a lock cycle. The commit contains only ACK bookkeeping, not source writes.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from .mdm.policy import managed_policy_cache_read_only
from .native_mode import native_mode_requires_rust
from .native_policy_bundle_acceptance import NativeAcceptedPolicyBundle, accepted_policy_bundle_locked
from .native_policy_publication_lock import hold_policy_publication_mutation
from .native_policy_snapshot_codec import _valid_digest_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .native_policy_snapshot_publisher_scoped import _policy_fingerprint, compiled_scoped_policy
from .oauth_connection_authority import OAuthConnectionSnapshot
from .policy_bundle_ack_contract import generic_ack_matches_bundle, validated_generic_policy_acknowledgement
from .policy_bundle_generic_ack import generic_policy_bundle_acknowledgement
from .policy_canonical_rollout import canonical_policy_enforcement_enabled
from .runtime.sync_response_authority import hold_sync_response_authority

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

_ACCEPTANCE_KEY = "native_policy_bundle_ack_acceptance"


def _payload(connection: sqlite3.Connection, key: str) -> dict[str, object] | None:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (key,)).fetchone()
    if row is None:
        return None
    value: object = json.loads(str(row[0]))
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _non_database_inputs(
    values: tuple[tuple[str, tuple[int, int, int, int] | None], ...], database_path: str
) -> tuple[tuple[str, object], ...]:
    # The held SQLite write reservation and observer data_version fence cover
    # SQL data. Our own journal creation must not look like a policy mutation.
    journals = {database_path + suffix for suffix in ("-wal", "-shm", "-journal")}
    return tuple(
        (path, metadata[2] if path == database_path and metadata is not None else metadata)
        for path, metadata in values
        if path not in journals
    )


def _write_payload(connection: sqlite3.Connection, key: str, payload: dict[str, object], now: str) -> None:
    connection.execute(
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) "
        "on conflict(state_key) do update set payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        (key, json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False), now),
    )


def _valid_retained_binding(record: dict[str, object]) -> bool:
    epoch, binding = record.get("epoch"), record.get("binding")
    if type(epoch) is not int or epoch < 0 or not isinstance(binding, dict):
        return False
    fields = {
        "generation",
        "policy_digest",
        "source_input_digest",
        "runtime_identity",
        "resident_generation",
        "mode",
    }
    if "command_extensions_bound" in binding:
        if binding["command_extensions_bound"] is not True:
            return False
        fields.add("command_extensions_bound")
    if set(binding) != fields:
        return False
    for field in ("generation", "resident_generation"):
        value = binding[field]
        if type(value) is not int or value <= 0:
            return False
    return binding["mode"] in ("enforce", "observe") and all(
        _valid_digest_v3(binding[field]) for field in ("policy_digest", "source_input_digest", "runtime_identity")
    )


def commit_native_policy_bundle_acknowledgement(
    publisher: NativePolicySnapshotPublisher,
    acceptance: NativeAcceptedPolicyBundle,
    *,
    expected_connection: OAuthConnectionSnapshot | None = None,
) -> dict[str, object] | None:
    """Return a durable applied ACK, or leave the prior received state unchanged.

    Reconstruct current authenticated authority outside the write reservation.
    A data_version observer detects every intervening commit, including A→B→A.
    Source/config/resident currency and expiry are checked at the commit barrier.
    No existing ACK, including an old applied ACK, supplies native acceptance.
    """
    store = publisher.store
    source = acceptance.source
    installation_id = source.get("device_id")
    workspace_id = source.get("workspace_id")
    if not isinstance(installation_id, str) or not isinstance(workspace_id, str):
        return None

    def lane_selected() -> bool:
        return native_mode_requires_rust() and canonical_policy_enforcement_enabled(
            device_id=installation_id, workspace_id=workspace_id
        )

    if not lane_selected():
        return None
    try:
        with (
            managed_policy_cache_read_only(),
            hold_policy_publication_mutation(publisher.guard_home),
            store._connect() as observer,
            store._connect() as connection,
        ):
            version = observer.execute("pragma data_version").fetchone()[0]
            before = publisher._current_input_fingerprint()
            config, inputs = compiled_scoped_policy(publisher)
            after = publisher._current_input_fingerprint()
            database = str(store.path)
            metadata = _non_database_inputs(after[0], database)
            if (
                _non_database_inputs(before[0], database) != metadata
                or before[1] != after[1]
                or observer.execute("pragma data_version").fetchone()[0] != version
                or inputs.input_digest != acceptance.binding.source_input_digest
                or source not in inputs.sources
                or _policy_fingerprint(config) != (publisher._published_config_digest, acceptance.binding.mode)
            ):
                return None
            with hold_sync_response_authority(store, expected_connection):
                resident_directory = publisher._resident_directory_fingerprint()
                connection.execute("pragma busy_timeout=0")
                connection.execute("begin immediate")
                # Never wait for the publication condition while reserving SQL.
                if not publisher._condition.acquire(blocking=False):
                    connection.rollback()
                    return None
                try:
                    bundle = _payload(connection, "policy_bundle")
                    previous = _payload(connection, "policy_bundle_ack")
                    if bundle is None or previous is None:
                        connection.rollback()
                        return None

                    def current_after_resident_confirmation() -> bool:
                        # Resident confirmation may race source, lane or expiry
                        # changes. Recheck those after it, including before the
                        # retained-ACK early return, while SQL and epoch are held.
                        if (
                            publisher._confirm_resident_fingerprint(
                                after[1], after[1], acceptance.binding.resident_generation, resident_directory
                            )
                            is None
                        ):
                            return False
                        now_ms = int(publisher._wall_clock() * 1000)
                        fingerprint = publisher._current_input_fingerprint()
                        return (
                            now_ms < acceptance.expires_at_ms
                            and (inputs.expires_at_ms is None or inputs.expires_at_ms > now_ms)
                            and lane_selected()
                            and accepted_policy_bundle_locked(publisher, bundle=bundle, installation_id=installation_id)
                            == acceptance
                            and observer.execute("pragma data_version").fetchone()[0] == version
                            and _non_database_inputs(fingerprint[0], database) == metadata
                            and fingerprint[1] == after[1]
                        )

                    if (
                        not current_after_resident_confirmation()
                        or validated_generic_policy_acknowledgement(previous)[0] is None
                        or not generic_ack_matches_bundle(previous, bundle, device_id=installation_id)
                    ):
                        connection.rollback()
                        return None
                    record = {
                        "source": source,
                        "binding": acceptance.binding.to_request_binding(),
                        "epoch": acceptance.epoch,
                    }
                    retained = _payload(connection, _ACCEPTANCE_KEY)
                    if previous.get("status") == "applied" and retained == {**record, "ack": previous}:
                        connection.rollback()
                        return previous
                    now = (
                        datetime.fromtimestamp(publisher._wall_clock(), timezone.utc).isoformat().replace("+00:00", "Z")
                    )
                    # Same-source re-publication is fresh native evidence, but does
                    # not rewrite the historical wire ACK or its original timestamp.
                    same_historical_ack = (
                        previous.get("status") == "applied"
                        and retained is not None
                        and set(retained) == {"source", "binding", "epoch", "ack"}
                        and retained.get("source") == source
                        and retained.get("ack") == previous
                        and _valid_retained_binding(retained)
                    )
                    acknowledged = (
                        previous
                        if same_historical_ack
                        else generic_policy_bundle_acknowledgement(
                            device_id=installation_id,
                            policy_bundle=bundle,
                            synced_at=now,
                            applied=True,
                            previous=previous,
                        )
                    )
                    if not acknowledged:
                        connection.rollback()
                        return None
                    if not same_historical_ack:
                        _write_payload(connection, "policy_bundle_ack", acknowledged, now)
                    _write_payload(connection, _ACCEPTANCE_KEY, {**record, "ack": acknowledged}, now)
                    if not current_after_resident_confirmation():
                        connection.rollback()
                        return None
                    connection.commit()
                    return acknowledged
                finally:
                    if connection.in_transaction:
                        connection.rollback()
                    publisher._condition.release()
    except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error, NativePolicySnapshotError):
        return None
