"""Regression coverage for Cloud command local request snapshot paging."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_executors, local_request_snapshots


class PagingStore:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.payloads: dict[str, object] = {}

    def get_sync_payload(self, key: str) -> object | None:
        return self.payloads.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        del now
        self.payloads[key] = payload

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> object | None:
        del allow_primary
        return None

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        del harness, search
        if status != "pending":
            return []
        rows = [_approval_request_row(index) for index in range(130)]
        if cursor:
            padded = cursor + ("=" * (-len(cursor) % 4))
            decoded = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
            marker_last_seen = decoded["last_seen_at"]
            marker_request_id = decoded["request_id"]
            rows = [
                row
                for row in rows
                if (
                    str(row["last_seen_at"]) < marker_last_seen
                    or (str(row["last_seen_at"]) == marker_last_seen and str(row["request_id"]) < marker_request_id)
                )
            ]
        return rows if limit is None else rows[:limit]


def _approval_request_row(index: int) -> dict[str, object]:
    return {
        "request_id": f"req-pending-{index:03d}",
        "status": "pending",
        "harness": "codex",
        "artifact_id": f"artifact-{index:03d}",
        "artifact_hash": "b" * 64,
        "policy_action": "require-reapproval",
        "recommended_scope": "artifact",
        "created_at": "2026-05-14T11:58:00.000Z",
        "last_seen_at": f"2026-05-14T11:{59 - (index // 10):02d}:{59 - (index % 10):02d}.000Z",
        "queue_group_id": "queue-group-1",
        "action_envelope_json": {
            "action_type": "shell_command",
            "command": "npm install minimist@1.2.8",
            "tool_name": "Bash",
        },
    }


def test_local_request_snapshot_payload_stays_under_cloud_byte_budget(tmp_path: Path) -> None:
    class HugePayloadStore(PagingStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            rows = super().list_approval_requests(
                status=status,
                harness=harness,
                limit=limit,
                cursor=cursor,
                search=search,
            )
            for row in rows:
                row["risk_summary"] = "SECRET_TOKEN=" + ("x" * 20_000)
                row["why_now"] = "review context " + ("y" * 20_000)
                envelope = row["action_envelope_json"]
                if isinstance(envelope, dict):
                    envelope["command"] = "npm install minimist@1.2.8 " + ("--flag value " * 2_000)
            return rows

    store = HugePayloadStore(tmp_path / "guard-home")
    store.payloads["cloud_receipt_redaction_level"] = {"level": "none"}
    payload = command_executors._local_request_snapshot_payload(store)

    payload_size = len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    assert payload_size <= local_request_snapshots.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES
    assert payload["pendingComplete"] is False
    assert payload["pendingCount"] == command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    first_request = payload["requests"][0]
    assert isinstance(first_request, dict)
    request_payload = first_request["requestPayload"]
    assert isinstance(request_payload, dict)
    assert "truncated" in str(request_payload["risk_summary"])
    assert "truncated" in str(request_payload["command_text"])


def test_local_request_snapshot_pending_is_cursorless(tmp_path: Path) -> None:
    """Pending snapshots must NOT persist cursors so every call sees the newest batch.

    The implementation invariant (local_request_snapshots.py line 175) is
    ``use_cursor = status != "pending"`` — pending status never reads or
    writes a paging cursor.  Each call therefore returns the same first
    batch (rows 0-124) regardless of prior calls.
    """
    store = PagingStore(tmp_path / "guard-home")

    # First snapshot: rows 0-124 (limit = 125).
    first_payload = command_executors._local_request_snapshot_payload(store)
    assert first_payload["pendingComplete"] is False
    assert first_payload["pendingCount"] == command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    assert first_payload["requests"][0]["localRequestId"] == "req-pending-000"
    assert first_payload["requests"][-1]["localRequestId"] == "req-pending-124"

    # Second snapshot: pending status does NOT persist cursors,
    # so every call returns the same first batch (rows 0-124).
    # This is the new live-request invariant: each lease covers
    # the newest pending rows without advancing a store cursor.
    second_payload = command_executors._local_request_snapshot_payload(store)
    assert second_payload["pendingComplete"] is False
    assert second_payload["pendingCount"] == command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    assert second_payload["requests"][0]["localRequestId"] == "req-pending-000"
    assert second_payload["requests"][-1]["localRequestId"] == "req-pending-124"

    # Third snapshot confirms the invariant holds across repeated calls.
    third_payload = command_executors._local_request_snapshot_payload(store)
    assert third_payload["pendingComplete"] is False
    assert third_payload["pendingCount"] == command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    assert third_payload["requests"][0]["localRequestId"] == "req-pending-000"
    assert third_payload["requests"][-1]["localRequestId"] == "req-pending-124"


def test_local_request_snapshot_includes_newest_pending_after_truncation(tmp_path: Path) -> None:
    """Prove a newly inserted request appears on the next snapshot despite prior truncation."""

    class FreshRowStore(PagingStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.inserted_rows: list[dict[str, object]] = []

        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del harness, search
            if status != "pending":
                return []
            # In the DB, newest requests come first. Insert fresh rows
            # at the front so they naturally rank within the limit window.
            rows = list(self.inserted_rows) + [_approval_request_row(i) for i in range(125)]
            return rows if limit is None else rows[:limit]

    store = FreshRowStore(tmp_path / "guard-home")

    # Initial snapshot: truncated at 125, so rows 125-129 are hidden.
    first_payload = command_executors._local_request_snapshot_payload(store)
    assert len(first_payload["requests"]) == command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    assert first_payload["requests"][-1]["localRequestId"] == "req-pending-124"

    # Insert a brand-new request whose created_at is later than all backlog rows.
    now_iso = "2026-07-04T12:00:00.000Z"
    new_request = {
        "request_id": "req-pending-fresh",
        "status": "pending",
        "harness": "codex",
        "artifact_id": "artifact-new",
        "artifact_hash": "a" * 64,
        "policy_action": "require-approval",
        "recommended_scope": "artifact",
        "created_at": now_iso,
        "last_seen_at": now_iso,
        "queue_group_id": "queue-group-1",
        "action_envelope_json": {
            "action_type": "shell_command",
            "command": "npm install fresh-pkg@2.0.0",
            "tool_name": "Bash",
        },
    }
    store.inserted_rows.append(new_request)

    # Second snapshot: the newly inserted request must be visible in the
    # returned batch because pending snapshots never store a cursor that
    # would hide it.
    second_payload = command_executors._local_request_snapshot_payload(store)
    request_ids = {r["localRequestId"] for r in second_payload["requests"]}
    assert "req-pending-fresh" in request_ids

    # Third snapshot: the fresh request persists across repeated calls,
    # proving the cursorless invariant holds for injected rows too.
    third_payload = command_executors._local_request_snapshot_payload(store)
    third_ids = {r["localRequestId"] for r in third_payload["requests"]}
    assert "req-pending-fresh" in third_ids
    # The persisted snapshot cursor key must NOT contain a pending cursor,
    # otherwise the next call could skip fresh rows.
    stored_cursor = store.get_sync_payload(
        "guard_command_local_request_snapshot_cursor"
    )
    assert stored_cursor is None or "pending" not in stored_cursor
