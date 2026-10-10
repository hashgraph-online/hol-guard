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
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

from . import store_review_event_outbox_schema
from .native_guard_store import native_guard_store_call
from .store_base import sqlite_connect_timeout_seconds

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
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        timeout_seconds = sqlite_connect_timeout_seconds()
        if timeout_seconds <= 0:
            raise TimeoutError("Guard storage operation deadline expired.")
        failure: sqlite3.DatabaseError | None = None
        generation: int | None = None
        payload: object = None
        with self._hold_storage_gate(exclusive=False):
            try:
                payload, generation = native_guard_store_call(
                    store_path=self.path,
                    guard_home=self.guard_home,
                    source=self._guard_source,
                    method=method,
                    args=args,
                    busy_timeout_seconds=timeout_seconds,
                )
            except sqlite3.DatabaseError as error:
                failure = error
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
        snapshots = self._native_store_call("list_review_event_snapshots", {"request_id": request_id})
        return [dict(snapshot) for snapshot in snapshots]

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
        events = self._native_store_call(
            "list_ready_review_events",
            {
                "now": now,
                "limit": int(limit),
                **_identity(oauth_subject_hash, workspace_id, machine_id, machine_installation_id),
            },
        )
        return [dict(event) for event in events]

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
