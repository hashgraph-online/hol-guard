"""Regression coverage for Cloud command local request snapshot paging."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_executors


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


def test_local_request_snapshot_pages_large_pending_backlog(tmp_path: Path) -> None:
    store = PagingStore(tmp_path / "guard-home")

    first_payload = command_executors._local_request_snapshot_payload(store)
    second_payload = command_executors._local_request_snapshot_payload(store)
    third_payload = command_executors._local_request_snapshot_payload(store)

    assert first_payload["pendingComplete"] is False
    assert first_payload["pendingCount"] == command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    assert first_payload["requests"][0]["localRequestId"] == "req-pending-000"
    assert first_payload["requests"][-1]["localRequestId"] == "req-pending-124"
    assert second_payload["pendingComplete"] is False
    assert second_payload["pendingCount"] == 5
    assert second_payload["requests"][0]["localRequestId"] == "req-pending-125"
    assert second_payload["requests"][-1]["localRequestId"] == "req-pending-129"
    assert third_payload["pendingComplete"] is False
    assert third_payload["pendingCount"] == command_executors.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    assert third_payload["requests"][0]["localRequestId"] == "req-pending-000"
    assert third_payload["requests"][-1]["localRequestId"] == "req-pending-124"
