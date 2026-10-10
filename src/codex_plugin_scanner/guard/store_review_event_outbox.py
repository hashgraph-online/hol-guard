"""Store API for append-only Guard Cloud Review event delivery.

Every method runs in the native resident (``guard_store`` op). This mixin keeps
only the process-local concerns: the storage-access gate, fatal-store recovery,
outbox wake notification, wall-clock timestamps, and DTO shaping.
"""

from __future__ import annotations

# pyright: reportAny=false, reportAttributeAccessIssue=false, reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnusedCallResult=false
import json
import sqlite3
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from . import store_review_event_outbox_schema
from .native_guard_store import native_guard_store_call
from .sqlite_errors import sqlite_error_is_busy_locked
from .store_base import sqlite_connect_timeout_seconds
from .store_review_event_acknowledgment import release_unacked_snapshot_gaps
from .store_review_event_outbox_binding import (
    load_review_oauth_binding,
    normalized_delivery_binding,
)

_SENTINEL = "\u0000requeued\u0000"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _positive_sequences(sequences: Sequence[int]) -> list[int]:
    return sorted({int(sequence) for sequence in sequences if int(sequence) > 0})


def _identity(
    oauth_subject_hash: object, workspace_id: object, machine_id: object, machine_installation_id: object
) -> dict[str, object]:
    return {
        "oauth_subject_hash": oauth_subject_hash,
        "workspace_id": workspace_id,
        "machine_id": machine_id,
        "machine_installation_id": machine_installation_id,
    }


def _marker_parts(marker_payload: Mapping[str, object]) -> list[str]:
    rendered = json.dumps({**marker_payload, "requeued": _SENTINEL})
    token = json.dumps(_SENTINEL)
    before, separator, after = rendered.partition(token)
    if not separator or token in after:
        raise ValueError("Review requeue marker payload is not representable.")
    return [before, after]


class StoreReviewEventOutboxMixin:
    def append_native_application_observation(
        self,
        request_id: str,
        *,
        native_application_result: Mapping[str, object],
        request_snapshot: Mapping[str, object],
    ) -> int:
        """Atomically project already-observed core consumption; never grant execution."""
        from .runtime.native_cloud_review_v4 import decode_native_application_result
        from .store_review_event_outbox_schema import REVIEW_REQUEST_SNAPSHOT_COLUMNS
        from .store_review_event_outbox_writes import append_request_snapshot_event
        from .store_review_event_outbox_writes import request_snapshot as load_snapshot

        application = decode_native_application_result(dict(native_application_result))
        if application is None or request_snapshot.get("request_id") != request_id:
            raise ValueError("native_application_positive_invalid")
        marker_key = "guard_native_application_observation.v4:" + request_id
        with self._connect() as connection:
            connection.execute("begin immediate")
            prior = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (marker_key,),
            ).fetchone()
            if prior is not None:
                marker = json.loads(prior["payload_json"])
                if (
                    not isinstance(marker, dict)
                    or marker.get("application") != application
                    or type(marker.get("stream_sequence")) is not int
                ):
                    raise ValueError("native_application_immutable_binding_conflict")
                return marker["stream_sequence"]
            current = load_snapshot(connection, request_id)
            if current is None:
                raise ValueError("native_application_pending_request_missing")
            mutable = {"status", "resolution_action", "resolution_scope", "resolved_at", "reason"}
            if any(
                current.get(key) != request_snapshot.get(key)
                for key in REVIEW_REQUEST_SNAPSHOT_COLUMNS
                if key not in mutable
            ):
                raise ValueError("native_application_pending_request_changed")
            binding = load_review_oauth_binding(connection, self._guard_source)
            prior_binding = connection.execute(
                "select oauth_subject_hash, workspace_id, machine_id, machine_installation_id "
                "from guard_review_outbox_request_sequences where local_request_id = ?",
                (request_id,),
            ).fetchone()
            if (
                binding is None
                or prior_binding is None
                or any(
                    prior_binding[key] != binding[key]
                    for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
                )
            ):
                raise ValueError("native_application_delivery_cohort_changed")
            consumed_at = application.get("consumedAt")
            decision_receipt_id = application.get("decisionReceiptId")
            if not isinstance(consumed_at, str) or not isinstance(decision_receipt_id, str):
                raise ValueError("native_application_positive_invalid")
            if current["status"] == "pending":
                connection.execute(
                    "update approval_requests set status = 'resolved', resolution_action = 'allow', "
                    "resolution_scope = 'once', resolved_at = ?, reason = ? "
                    "where request_id = ? and status = 'pending'",
                    (
                        consumed_at,
                        "native_approval_v4_consumed:" + decision_receipt_id,
                        request_id,
                    ),
                )
            sequence = append_request_snapshot_event(
                connection,
                request_id=request_id,
                source=self._guard_source,
                event_type="review.native_application.applied",
                occurred_at=consumed_at,
                native_application_result=application,
                request_snapshot=request_snapshot,
            )
            if sequence <= 0:
                raise ValueError("native_application_outbox_append_failed")
            marker_json = json.dumps(
                {
                    "schema": "guard-native-application-observation.v4",
                    "application": application,
                    "stream_sequence": sequence,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            connection.execute(
                "insert into sync_state (state_key,payload_json,updated_at) values (?,?,?)",
                (marker_key, marker_json, application["consumedAt"]),
            )
            return sequence

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any:
        timeout_seconds = sqlite_connect_timeout_seconds()
        if timeout_seconds <= 0:
            raise TimeoutError("Guard storage operation deadline expired.")
        # One deadline for the whole call: the gate wait, startup, SQLite busy
        # wait and transport all draw from it, so none can outlast the caller.
        deadline = time.monotonic() + timeout_seconds
        failure: sqlite3.DatabaseError | None = None
        generation: int | None = None
        payload: Any = None
        profiler = self._sqlite_profiler()
        with self._hold_storage_gate(exclusive=False):
            started = time.monotonic()
            try:
                payload, generation = native_guard_store_call(
                    store_path=self.path,
                    guard_home=self.guard_home,
                    source=self._guard_source,
                    method=method,
                    args=args,
                    deadline_monotonic=deadline,
                )
            except sqlite3.DatabaseError as error:
                failure = error
                if sqlite_error_is_busy_locked(error):
                    profiler.record_busy_locked()
            finally:
                profiler.record_transaction((time.monotonic() - started) * 1000)
        self._repair_store_permissions()
        if failure is not None:
            # The operation already ran against the failed store: recover it for
            # the next call, then surface this failure.
            try:
                self._recover_fatal_sqlite_store(failure)
            except Exception as recovery_error:
                raise recovery_error from failure
            raise failure
        store_review_event_outbox_schema.notify_review_event_wake(self.path, generation)
        return payload

    def repair_rejected_review_correlation(
        self, *, event_sequence: int, binding: Mapping[str, str], changed_at: str
    ) -> int:
        return int(
            self._native_store_call(
                "repair_rejected_review_correlation",
                {"event_sequence": event_sequence, "binding": dict(binding), "changed_at": changed_at},
            )
        )

    def requeue_pending_review_events(
        self,
        *,
        changed_at: str,
        require_binding: bool = False,
        snapshot_repair_sequences: dict[str, int] | None = None,
        request_ids: set[str] | None = None,
        request_snapshots: Mapping[str, Mapping[str, object]] | None = None,
    ) -> int:
        return int(
            self._native_store_call(
                "requeue_pending_review_events",
                {
                    "changed_at": changed_at,
                    "require_binding": require_binding,
                    "snapshot_repair_sequences": snapshot_repair_sequences,
                    "request_ids": None if request_ids is None else sorted(request_ids),
                    "request_snapshots": None if request_snapshots is None else dict(request_snapshots),
                },
            )
        )

    def requeue_pending_review_events_with_marker(
        self,
        *,
        changed_at: str,
        marker_key: str,
        marker_payload: Mapping[str, object],
        require_binding: bool = False,
        only_retry_identity_drift: bool = False,
        request_ids: set[str] | None = None,
        request_snapshots: Mapping[str, Mapping[str, object]] | None = None,
    ) -> int:
        return int(
            self._native_store_call(
                "requeue_pending_review_events_with_marker",
                {
                    "changed_at": changed_at,
                    "marker_key": marker_key,
                    "marker_json_parts": _marker_parts(marker_payload),
                    "require_binding": require_binding,
                    "only_retry_identity_drift": only_retry_identity_drift,
                    "request_ids": None if request_ids is None else sorted(request_ids),
                    "request_snapshots": None if request_snapshots is None else dict(request_snapshots),
                    "native_replay": marker_payload.get("native_replay") is True
                    or marker_payload.get("schema") == "guard-cloud-review-native-workspace-review-request.v1",
                },
            )
        )

    def list_pending_review_request_ids(
        self,
        *,
        binding: Mapping[str, str],
        limit: int,
        after_request_id: str | None = None,
        through_request_id: str | None = None,
        descending: bool = False,
    ) -> list[str]:
        ids = self._native_store_call(
            "list_pending_review_request_ids",
            {
                "binding": dict(binding),
                "limit": limit,
                "after_request_id": after_request_id,
                "through_request_id": through_request_id,
                "descending": descending,
            },
        )
        return [str(request_id) for request_id in ids]

    def list_review_event_snapshots(self, request_id: str) -> list[dict[str, object]]:
        """Newest-first snapshot history, read in resident-bounded pages.

        The resident caps each reply, so it returns a byte-bounded page plus a
        cursor; this method follows the cursor until the history is exhausted.
        """

        snapshots: list[dict[str, object]] = []
        cursor: dict[str, object] | None = None
        while True:
            page = self._native_store_call(
                "list_review_event_snapshots",
                {"request_id": request_id, **({"after": cursor} if cursor is not None else {})},
            )
            snapshots.extend(dict(snapshot) for snapshot in page["snapshots"])
            following = page.get("next")
            if following is None:
                return snapshots
            if following == cursor:
                raise ValueError("Review snapshot paging made no progress.")
            cursor = dict(following)

    def get_review_event_oauth_binding(self) -> dict[str, str] | None:
        binding = self._native_store_call("get_review_event_oauth_binding", {})
        return dict(binding) if binding is not None else None

    def refresh_review_event_outbox_binding_for_identity(
        self,
        workspace_id: str,
        *,
        oauth_subject_hash: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        return int(
            self._native_store_call(
                "refresh_review_event_outbox_binding_for_identity",
                _identity(oauth_subject_hash, workspace_id, machine_id, machine_installation_id),
            )
        )

    def refresh_review_event_outbox_binding(self) -> int:
        return int(self._native_store_call("refresh_review_event_outbox_binding", {}))

    def reassign_quarantined_review_events(
        self,
        *,
        approved_source: str,
        approved_workspace_id: str,
        only_unbound: bool = False,
    ) -> int:
        return int(
            self._native_store_call(
                "reassign_quarantined_review_events",
                {
                    "approved_source": approved_source,
                    "approved_workspace_id": approved_workspace_id,
                    "only_unbound": only_unbound,
                },
            )
        )

    def count_recoverable_unbound_review_events(self) -> int:
        return int(self._native_store_call("count_recoverable_unbound_review_events", {}))

    def list_ready_review_events(
        self,
        *,
        now: str,
        limit: int,
        workspace_id: str | None = None,
        oauth_subject_hash: str | None = None,
        machine_id: str | None = None,
        machine_installation_id: str | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, object]]:
        del newest_first
        arguments = {
            "now": now,
            "limit": int(limit),
            **_identity(oauth_subject_hash, workspace_id, machine_id, machine_installation_id),
        }
        while True:
            # The resident returns a byte-bounded prefix of the ready rows. A row
            # too large to cross the resident reply cap by itself arrives alone,
            # flagged, without its payload: it can never be uploaded, so it is
            # dead-lettered exactly like an event over the upload byte limit.
            events = [dict(event) for event in self._native_store_call("list_ready_review_events", arguments)]
            if not (events and events[0].get("payload_oversized") is True):
                return events
            oversized = events[0]
            changed = self.quarantine_review_event(
                int(oversized["sequence"]),
                reason="event_exceeds_upload_limit",
                error="A Cloud Review event exceeds the negotiated upload byte limit.",
                oauth_subject_hash=str(oversized["oauth_subject_hash"]),
                workspace_id=str(oversized["workspace_id"]),
                machine_id=str(oversized["machine_id"]),
                machine_installation_id=str(oversized["machine_installation_id"]),
            )
            if changed < 1:
                raise ValueError("An oversized Review event could not be quarantined.")

    def release_unacked_snapshot_gaps(
        self,
        sequences: Sequence[int],
        *,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        """Drop ready source-gap rows covered by an accepted snapshot."""

        released = sorted({int(sequence) for sequence in sequences if int(sequence) > 0})
        if not released:
            return 0
        binding = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        with self._connect() as connection:
            connection.execute("begin immediate")
            return release_unacked_snapshot_gaps(
                connection,
                source=self._guard_source,
                sequences=released,
                binding=binding,
            )

    def acknowledge_review_events(
        self,
        sequences: Sequence[int],
        *,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        """Compact the acknowledged deliverable prefix; retain quarantined evidence."""

        acknowledged = _positive_sequences(sequences)
        if not acknowledged:
            return 0
        return int(
            self._native_store_call(
                "acknowledge_review_events",
                {
                    "sequences": acknowledged,
                    "acknowledged_at": _now(),
                    **_identity(oauth_subject_hash, workspace_id, machine_id, machine_installation_id),
                },
            )
        )

    def retry_review_events(
        self,
        sequences: Sequence[int],
        *,
        now: str,
        error: str,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        normalized = _positive_sequences(sequences)
        if not normalized:
            return 0
        return int(
            self._native_store_call(
                "retry_review_events",
                {
                    "sequences": normalized,
                    "now": now,
                    "fallback_now": _now(),
                    "error": error,
                    **_identity(oauth_subject_hash, workspace_id, machine_id, machine_installation_id),
                },
            )
        )

    def quarantine_review_event(
        self,
        sequence: int,
        *,
        reason: str,
        error: str,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        """Dead-letter one invalid event without acknowledging or deleting it."""

        return int(
            self._native_store_call(
                "quarantine_review_event",
                {
                    "sequence": int(sequence),
                    "reason": reason,
                    "error": error,
                    **_identity(oauth_subject_hash, workspace_id, machine_id, machine_installation_id),
                },
            )
        )

    def review_event_outbox_status(
        self,
        *,
        now: str,
        workspace_id: str | None = None,
        oauth_subject_hash: str | None = None,
        machine_id: str | None = None,
        machine_installation_id: str | None = None,
    ) -> dict[str, object]:
        status = self._native_store_call(
            "review_event_outbox_status",
            {"now": now, **_identity(oauth_subject_hash, workspace_id, machine_id, machine_installation_id)},
        )
        return dict(status)
