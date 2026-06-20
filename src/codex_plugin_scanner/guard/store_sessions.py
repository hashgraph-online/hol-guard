"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


class StoreSessionsMixin:
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
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_sessions (
                  session_id,
                  harness,
                  surface,
                  status,
                  client_name,
                  client_title,
                  client_version,
                  workspace,
                  capabilities_json,
                  created_at,
                  updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(session_id) do update set
                  harness = excluded.harness,
                  surface = excluded.surface,
                  status = excluded.status,
                  client_name = excluded.client_name,
                  client_title = excluded.client_title,
                  client_version = excluded.client_version,
                  workspace = excluded.workspace,
                  capabilities_json = excluded.capabilities_json,
                  updated_at = excluded.updated_at
                """,
                (
                    session_id,
                    harness,
                    surface,
                    status,
                    client_name,
                    client_title,
                    client_version,
                    workspace,
                    json.dumps(capabilities),
                    now,
                    now,
                ),
            )
        session = self.get_guard_session(session_id)
        if session is None:
            raise RuntimeError(f"Guard session {session_id} was not persisted.")
        return session

    def get_guard_session(self, session_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select session_id, harness, surface, status, client_name, client_title, client_version, workspace,
                       capabilities_json, created_at, updated_at
                from guard_sessions
                where session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
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

    def list_guard_sessions(self, status: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        query = """
            select session_id, harness, surface, status, client_name, client_title, client_version, workspace,
                   capabilities_json, created_at, updated_at
            from guard_sessions
        """
        params: list[object] = []
        if status is not None:
            query += " where status = ?"
            params.append(status)
        query += " order by updated_at desc, session_id desc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
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
            for row in rows
        ]

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
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_operations (
                  operation_id,
                  session_id,
                  harness,
                  operation_type,
                  status,
                  approval_request_ids_json,
                  resume_token,
                  metadata_json,
                  created_at,
                  updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(operation_id) do update set
                  session_id = excluded.session_id,
                  harness = excluded.harness,
                  operation_type = excluded.operation_type,
                  status = excluded.status,
                  approval_request_ids_json = excluded.approval_request_ids_json,
                  resume_token = excluded.resume_token,
                  metadata_json = excluded.metadata_json,
                  updated_at = excluded.updated_at
                """,
                (
                    operation_id,
                    session_id,
                    harness,
                    operation_type,
                    status,
                    json.dumps(approval_request_ids),
                    resume_token,
                    json.dumps(metadata),
                    now,
                    now,
                ),
            )
        operation = self.get_guard_operation(operation_id)
        if operation is None:
            raise RuntimeError(f"Guard operation {operation_id} was not persisted.")
        return operation

    def get_guard_operation(self, operation_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select operation_id, session_id, harness, operation_type, status, approval_request_ids_json,
                       resume_token, metadata_json, created_at, updated_at
                from guard_operations
                where operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
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

    def list_guard_operations(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        query = """
            select operation_id, session_id, harness, operation_type, status, approval_request_ids_json,
                   resume_token, metadata_json, created_at, updated_at
            from guard_operations
        """
        params: list[object] = []
        if session_id is not None:
            query += " where session_id = ?"
            params.append(session_id)
        query += " order by updated_at desc, operation_id desc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
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
            for row in rows
        ]

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select operation_id, session_id, harness, operation_type, status, approval_request_ids_json,
                       resume_token, metadata_json, created_at, updated_at
                from guard_operations
                where approval_request_ids_json like ?
                order by updated_at desc, operation_id desc
                """,
                (f"%{request_id}%",),
            ).fetchall()
        for row in rows:
            approval_request_ids = json.loads(str(row["approval_request_ids_json"]))
            if request_id not in {str(item) for item in approval_request_ids}:
                continue
            return {
                "operation_id": str(row["operation_id"]),
                "session_id": str(row["session_id"]),
                "harness": str(row["harness"]),
                "operation_type": str(row["operation_type"]),
                "status": str(row["status"]),
                "approval_request_ids": approval_request_ids,
                "resume_token": str(row["resume_token"]) if row["resume_token"] is not None else None,
                "metadata": json.loads(str(row["metadata_json"])),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
        return None

    def seed_request_resume(
        self,
        *,
        request_id: str,
        operation_id: str | None,
        harness: str,
        strategy: str,
        supported: bool,
        thread_id: str | None,
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_request_resume_seed(
                connection,
                request_id=request_id,
                operation_id=operation_id,
                harness=harness,
                strategy=strategy,
                supported=supported,
                thread_id=thread_id,
                now=now,
            )

    def get_request_resume(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_request_resume(connection, request_id)

    def get_latest_request_resume(self, *, harness: str | None = None) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_latest_request_resume(connection, harness=harness)

    def update_request_resume(
        self,
        *,
        request_id: str,
        resolution_action: str | None,
        strategy: str | None,
        supported: bool | None,
        status: str,
        reason: str | None,
        message: str | None,
        last_error: str | None,
        attempt_count: int,
        last_attempt_at: str | None,
        sent_at: str | None,
        now: str,
    ) -> None:
        with self._connect() as connection:
            persist_request_resume_update(
                connection,
                request_id=request_id,
                resolution_action=resolution_action,
                strategy=strategy,
                supported=supported,
                status=status,
                reason=reason,
                message=message,
                last_error=last_error,
                attempt_count=attempt_count,
                last_attempt_at=last_attempt_at,
                sent_at=sent_at,
                now=now,
            )

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
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_operation_items (
                  item_id, operation_id, item_type, lifecycle, payload_json, created_at
                )
                values (?, ?, ?, ?, ?, ?)
                """,
                (item_id, operation_id, item_type, lifecycle, json.dumps(payload), now),
            )
        items = self.list_guard_operation_items(operation_id)
        for item in items:
            if item["item_id"] == item_id:
                return item
        raise RuntimeError(f"Guard operation item {item_id} was not persisted.")

    def list_guard_operation_items(self, operation_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select item_id, operation_id, item_type, lifecycle, payload_json, created_at
                from guard_operation_items
                where operation_id = ?
                order by created_at asc, item_id asc
                """,
                (operation_id,),
            ).fetchall()
        return [
            {
                "item_id": str(row["item_id"]),
                "operation_id": str(row["operation_id"]),
                "item_type": str(row["item_type"]),
                "lifecycle": str(row["lifecycle"]),
                "payload": json.loads(str(row["payload_json"])),
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

    def attach_guard_client(
        self,
        *,
        client_id: str,
        surface: str,
        session_id: str | None,
        metadata: dict[str, object],
        lease_seconds: int,
        now: str,
    ) -> dict[str, object]:
        lease_id = uuid4().hex
        lease_expires_at = _lease_expiry(now, lease_seconds)
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_client_attachments (
                  client_id, surface, session_id, metadata_json, lease_id, lease_expires_at, attached_at, last_seen_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(client_id) do update set
                  surface = excluded.surface,
                  session_id = excluded.session_id,
                  metadata_json = excluded.metadata_json,
                  lease_id = excluded.lease_id,
                  lease_expires_at = excluded.lease_expires_at,
                  last_seen_at = excluded.last_seen_at
                """,
                (client_id, surface, session_id, json.dumps(metadata), lease_id, lease_expires_at, now, now),
            )
        item = self.get_guard_client_attachment(client_id)
        if item is not None:
            return item
        raise RuntimeError(f"Guard client attachment {client_id} was not persisted.")

    def renew_guard_client_attachment(
        self,
        *,
        client_id: str,
        lease_id: str,
        lease_seconds: int,
        now: str,
    ) -> dict[str, object] | None:
        lease_expires_at = _lease_expiry(now, lease_seconds)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update guard_client_attachments
                set last_seen_at = ?, lease_expires_at = ?
                where client_id = ? and lease_id = ?
                """,
                (now, lease_expires_at, client_id, lease_id),
            )
        if cursor.rowcount <= 0:
            return None
        return self.get_guard_client_attachment(client_id)

    def get_guard_client_attachment(self, client_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select
                  client_id, surface, session_id, metadata_json,
                  lease_id, lease_expires_at, attached_at, last_seen_at
                from guard_client_attachments
                where client_id = ?
                """,
                (client_id,),
            ).fetchone()
        if row is None:
            return None
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

    def list_guard_client_attachments(
        self,
        *,
        surface: str | None = None,
        session_id: str | None = None,
        active_within_seconds: int = 60,
    ) -> list[dict[str, object]]:
        query = """
            select client_id, surface, session_id, metadata_json, lease_id, lease_expires_at, attached_at, last_seen_at
            from guard_client_attachments
        """
        params: list[object] = []
        filters: list[str] = []
        if surface is not None:
            filters.append("surface = ?")
            params.append(surface)
        if session_id is not None:
            filters.append("session_id = ?")
            params.append(session_id)
        if filters:
            query += " where " + " and ".join(filters)
        query += " order by last_seen_at desc, client_id asc"
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        cutoff = datetime.now(timezone.utc).timestamp() - max(active_within_seconds, 0)
        items: list[dict[str, object]] = []
        for row in rows:
            lease_expires_at = row["lease_expires_at"]
            if lease_expires_at is not None:
                expires_at = datetime.fromisoformat(str(lease_expires_at)).timestamp()
                if expires_at < datetime.now(timezone.utc).timestamp():
                    continue
            else:
                last_seen = datetime.fromisoformat(str(row["last_seen_at"])).timestamp()
                if last_seen < cutoff:
                    continue
            items.append(
                {
                    "client_id": str(row["client_id"]),
                    "surface": str(row["surface"]),
                    "session_id": str(row["session_id"]) if row["session_id"] is not None else None,
                    "metadata": json.loads(str(row["metadata_json"])),
                    "lease_id": str(row["lease_id"]),
                    "lease_expires_at": str(row["lease_expires_at"]) if row["lease_expires_at"] is not None else None,
                    "attached_at": str(row["attached_at"]),
                    "last_seen_at": str(row["last_seen_at"]),
                }
            )
        return items

    def record_guard_surface_open(self, *, surface: str, open_key: str, now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_surface_opens (surface, open_key, opened_at)
                values (?, ?, ?)
                on conflict(surface, open_key) do update set
                  opened_at = excluded.opened_at
                """,
                (surface, open_key, now),
            )

    def has_guard_surface_open(self, *, surface: str, open_key: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "select 1 from guard_surface_opens where surface = ? and open_key = ?",
                (surface, open_key),
            ).fetchone()
        return row is not None
