"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# ruff: noqa: F403,F405
from .store_base import *


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _guard_session_row(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "session_id": str(row["session_id"]),
        "harness": str(row["harness"]),
        "surface": str(row["surface"]),
        "status": str(row["status"]),
        "client_name": str(row["client_name"]),
        "client_title": str(row["client_title"]) if row["client_title"] is not None else None,
        "client_version": str(row["client_version"]) if row["client_version"] is not None else None,
        "workspace": str(row["workspace"]) if row["workspace"] is not None else None,
        "capabilities": json.loads(str(row["capabilities_json"])),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def _guard_operation_row(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "operation_id": str(row["operation_id"]),
        "session_id": str(row["session_id"]),
        "harness": str(row["harness"]),
        "operation_type": str(row["operation_type"]),
        "status": str(row["status"]),
        "approval_request_ids": json.loads(str(row["approval_request_ids_json"])),
        "resume_token": str(row["resume_token"]) if row["resume_token"] is not None else None,
        "metadata": json.loads(str(row["metadata_json"])),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def _guard_item_row(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "item_id": str(row["item_id"]),
        "operation_id": str(row["operation_id"]),
        "item_type": str(row["item_type"]),
        "lifecycle": str(row["lifecycle"]),
        "payload": json.loads(str(row["payload_json"])),
        "created_at": str(row["created_at"]),
    }


def _guard_attachment_row(row: Mapping[str, Any]) -> dict[str, object]:
    return {
        "client_id": str(row["client_id"]),
        "surface": str(row["surface"]),
        "session_id": str(row["session_id"]) if row["session_id"] is not None else None,
        "metadata": json.loads(str(row["metadata_json"])),
        "lease_id": str(row["lease_id"]),
        "lease_expires_at": str(row["lease_expires_at"]) if row["lease_expires_at"] is not None else None,
        "attached_at": str(row["attached_at"]),
        "last_seen_at": str(row["last_seen_at"]),
    }


class StoreSessionsMixin:
    """Sessions, operations, items, client leases and surface opens.

    The resident owns every persisted fact (merge of retry lineage, lease
    arithmetic, liveness). Python supplies instants, the lease identifier and
    the JSON text of structured values, then shapes the raw rows it gets back.
    """

    def upsert_guard_session(
        self,
        *,
        session_id: str,
        harness: str,
        surface: str,
        status: str,
        client_name: str,
        client_title: str | None,
        client_version: str | None,
        workspace: str | None,
        capabilities: list[str],
        now: str,
    ) -> dict[str, object]:
        row = self._native_store_call(
            "upsert_guard_session",
            {
                "session_id": session_id,
                "harness": harness,
                "surface": surface,
                "status": status,
                "client_name": client_name,
                "client_title": client_title,
                "client_version": client_version,
                "workspace": workspace,
                "capabilities_json": json.dumps(capabilities),
                "now": now,
            },
        )
        return _guard_session_row(row)

    def get_guard_session(self, session_id: str) -> dict[str, object] | None:
        row = self._native_store_call("get_guard_session", {"session_id": session_id})
        return None if row is None else _guard_session_row(row)

    def list_guard_sessions(self, status: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        rows = self._native_store_call("list_guard_sessions", {"status": status, "limit": limit})
        return [_guard_session_row(row) for row in rows]

    def upsert_guard_operation(
        self,
        *,
        operation_id: str,
        session_id: str,
        harness: str,
        operation_type: str,
        status: str,
        approval_request_ids: list[str],
        resume_token: str | None,
        metadata: dict[str, object],
        now: str,
    ) -> dict[str, object]:
        row = self._native_store_call(
            "upsert_guard_operation",
            {
                "operation_id": operation_id,
                "session_id": session_id,
                "harness": harness,
                "operation_type": operation_type,
                "status": status,
                "approval_request_ids_json": json.dumps(approval_request_ids),
                "resume_token": resume_token,
                "metadata_json": json.dumps(metadata),
                "now": now,
            },
        )
        return _guard_operation_row(row)

    def get_guard_operation(self, operation_id: str) -> dict[str, object] | None:
        row = self._native_store_call("get_guard_operation", {"operation_id": operation_id})
        return None if row is None else _guard_operation_row(row)

    def list_guard_operations(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        rows = self._native_store_call("list_guard_operations", {"session_id": session_id, "limit": limit})
        return [_guard_operation_row(row) for row in rows]

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        row = self._native_store_call("get_guard_operation_for_approval_request", {"request_id": request_id})
        return None if row is None else _guard_operation_row(row)

    def get_request_resume(self, request_id: str) -> dict[str, object] | None:
        return self._native_store_call("get_request_resume", {"request_id": request_id})

    def get_latest_request_resume(self, *, harness: str | None = None) -> dict[str, object] | None:
        return self._native_store_call("get_latest_request_resume", {"harness": harness})

    def add_guard_operation_item(
        self,
        *,
        item_id: str,
        operation_id: str,
        item_type: str,
        lifecycle: str,
        payload: dict[str, object],
        now: str,
    ) -> dict[str, object]:
        row = self._native_store_call(
            "add_guard_operation_item",
            {
                "item_id": item_id,
                "operation_id": operation_id,
                "item_type": item_type,
                "lifecycle": lifecycle,
                "payload_json": json.dumps(payload),
                "now": now,
            },
        )
        return _guard_item_row(row)

    def list_guard_client_attachments(
        self,
        *,
        surface: str | None = None,
        session_id: str | None = None,
        active_within_seconds: int = 60,
    ) -> list[dict[str, object]]:
        rows = self._native_store_call(
            "list_guard_client_attachments",
            {
                "surface": surface,
                "session_id": session_id,
                "active_within_seconds": active_within_seconds,
                "now": _utc_now_iso(),
            },
        )
        return [_guard_attachment_row(row) for row in rows]

    def record_guard_surface_open(self, *, surface: str, open_key: str, now: str) -> None:
        self._native_store_call("record_guard_surface_open", {"surface": surface, "open_key": open_key, "now": now})

    def has_guard_surface_open(self, *, surface: str, open_key: str) -> bool:
        return bool(self._native_store_call("has_guard_surface_open", {"surface": surface, "open_key": open_key}))
