"""SQLite application boundary for native workspace-review decisions."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX = "native_workspace_review.receipt:"
_RECEIPT_BINDINGS = (
    "claim_id",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "scope_binding",
    "request_binding",
    "action_binding",
    "intent_binding",
    "revision_binding",
    "policy_binding",
    "retry_scope_binding",
    "request_snapshot_digest",
)


def _receipt_payload(receipt: Mapping[str, object], request_id: str, action: str) -> str:
    expected_decision = "deny" if action == "block" else "allow"
    if (
        receipt.get("request_id") != request_id
        or receipt.get("decision") != expected_decision
        or receipt.get("status") not in {"verified", "replayed"}
        or receipt.get("replayed") is not (receipt.get("status") == "replayed")
    ):
        raise ValueError("native_workspace_review_receipt_invalid")
    for field in (*_RECEIPT_BINDINGS, "envelope_digest", "authority_record_digest"):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("native_workspace_review_receipt_invalid")
    return json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class _NativeStore(Protocol):
    def _native_approval_read(self, method: str, args: dict[str, object]) -> Any: ...


class _NativeReplayStore(Protocol):
    @property
    def guard_source(self) -> str: ...

    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


def _request_snapshot(request: Mapping[str, object]) -> str:
    return json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class StoreNativeWorkspaceReviewMixin:
    """Apply a native decision after the resident has durably claimed it."""

    def resolve_native_workspace_review_request(
        self: _NativeStore,
        request_id: str,
        *,
        resolution_action: str,
        expected_request: Mapping[str, object],
        resolved_at: str,
        native_replayed: bool,
        native_receipt: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if resolution_action not in {"allow", "block"}:
            return {"resolved": False, "error": "native_workspace_review_decision_invalid"}
        if not isinstance(expected_request, Mapping):
            return {"resolved": False, "error": "native_workspace_review_request_invalid"}
        try:
            expected_snapshot = _request_snapshot(expected_request)
        except (TypeError, ValueError):
            return {"resolved": False, "error": "native_workspace_review_request_invalid"}
        try:
            if native_receipt is not None and native_receipt.get("replayed") is not native_replayed:
                raise ValueError("native_workspace_review_receipt_invalid")
            receipt_json = (
                _receipt_payload(native_receipt, request_id, resolution_action) if native_receipt is not None else None
            )
        except (TypeError, ValueError):
            return {"resolved": False, "error": "native_workspace_review_receipt_invalid"}
        return self._native_approval_read(
            "resolve_native_workspace_review_request",
            {
                "request_id": request_id,
                "resolution_action": resolution_action,
                "expected_snapshot": expected_snapshot,
                "resolved_at": resolved_at,
                "native_replayed": native_replayed,
                "native_receipt_json": receipt_json,
            },
        )

    def native_workspace_review_replay_marker(
        self: _NativeReplayStore,
        request_id: str,
        *,
        binding: Mapping[str, str],
        now: str,
        force_probe: bool = False,
    ) -> dict[str, object]:
        """Read a pending request's replay marker and whether it is due for a probe.

        Returns ``key`` (the marker row), ``marker`` (the stored object or
        ``None``) and ``due``.
        """

        answer = self._native_store_call(
            "native_workspace_review_replay_marker",
            {
                "source": self.guard_source,
                "request_id": request_id,
                "binding": dict(binding),
                "now": now,
                "force_probe": force_probe,
            },
        )
        if not isinstance(answer, dict):
            raise RuntimeError("native replay marker read returned no answer")
        return dict(answer)

    def transition_native_workspace_review_replay_marker(
        self: _NativeReplayStore,
        request_id: str,
        step: str,
        *,
        binding: Mapping[str, str],
        now: str,
        changed_at: str | None = None,
        **detail: object,
    ) -> dict[str, object]:
        """Move a pending request's replay marker through one named step.

        The native store owns the marker rules. ``probed`` takes the probe's
        ``authority`` and returns ``action``: ``failed`` and ``accepted`` wrote
        the marker, ``requeue`` returns the ``seed`` to requeue events with.
        ``requeued`` takes that ``seed`` and the requeue ``count``.
        ``accepted`` takes the ``authority`` and an optional ``fallback``
        marker and returns ``result``: ``accepted``, ``already`` or
        ``unmatched``.
        """

        answer = self._native_store_call(
            "transition_native_workspace_review_replay_marker",
            {
                "source": self.guard_source,
                "request_id": request_id,
                "step": step,
                "binding": dict(binding),
                "now": now,
                "changed_at": changed_at,
                **detail,
            },
        )
        if not isinstance(answer, dict):
            raise RuntimeError("native replay marker transition returned no answer")
        return dict(answer)

    def native_workspace_review_replay_scan(
        self: _NativeReplayStore, *, binding: Mapping[str, str]
    ) -> tuple[str | None, str | None]:
        """Return where the next replay batch starts: ``(cursor, through_request_id)``.

        ``through_request_id`` is ``None`` when a new snapshot of pending
        requests should be taken.
        """

        answer = self._native_store_call(
            "native_workspace_review_replay_scan",
            {"source": self.guard_source, "binding": dict(binding)},
        )
        if not isinstance(answer, dict):
            raise RuntimeError("native replay scan read returned no answer")
        cursor = answer.get("cursor")
        through = answer.get("through_request_id")
        return (cursor if isinstance(cursor, str) else None), (through if isinstance(through, str) else None)

    def record_native_workspace_review_replay_scan(
        self: _NativeReplayStore,
        *,
        binding: Mapping[str, str],
        request_ids: Sequence[str],
        limit: int,
        through_request_id: str | None,
        changed_at: str,
    ) -> dict[str, object]:
        """Save replay scan progress once a batch of ``request_ids`` has completed.

        The native store decides the next cursor, so an empty or short batch,
        or one that reached ``through_request_id``, finishes the snapshot.
        """

        answer = self._native_store_call(
            "record_native_workspace_review_replay_scan",
            {
                "source": self.guard_source,
                "binding": dict(binding),
                "request_ids": list(request_ids),
                "limit": limit,
                "through_request_id": through_request_id,
                "changed_at": changed_at,
            },
        )
        if not isinstance(answer, dict):
            raise RuntimeError("native replay scan record returned no answer")
        return dict(answer)


__all__ = ["NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX", "StoreNativeWorkspaceReviewMixin"]
