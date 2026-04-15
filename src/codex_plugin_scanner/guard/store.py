"""SQLite-backed local Guard persistence."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .models import GuardApprovalRequest, GuardArtifact, GuardReceipt, GuardRuntimeState, PolicyDecision
from .store_approvals import (
    add_approval_request as persist_approval_request,
)
from .store_approvals import (
    approval_schema_statement,
)
from .store_approvals import (
    count_approval_requests as count_pending_approval_requests,
)
from .store_approvals import (
    get_approval_request as load_approval_request,
)
from .store_approvals import (
    list_approval_requests as load_approval_requests,
)
from .store_approvals import (
    resolve_approval_request as persist_approval_resolution,
)


class GuardStore:
    """Local SQLite store for Guard state."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.guard_home.mkdir(parents=True, exist_ok=True)
        self.path = self.guard_home / "guard.db"
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        statements = (
            """
            create table if not exists harness_installations (
              harness text primary key,
              active integer not null,
              workspace text,
              config_path text,
              metadata_json text not null default '{}',
              updated_at text not null
            )
            """,
            """
            create table if not exists artifact_snapshots (
              artifact_id text not null,
              harness text not null,
              snapshot_json text not null,
              artifact_hash text not null,
              recorded_at text not null,
              primary key (artifact_id, harness)
            )
            """,
            """
            create table if not exists artifact_hashes (
              artifact_id text not null,
              harness text not null,
              artifact_hash text not null,
              recorded_at text not null
            )
            """,
            """
            create table if not exists artifact_diffs (
              diff_id integer primary key autoincrement,
              artifact_id text not null,
              harness text not null,
              changed_fields_json text not null,
              previous_hash text,
              current_hash text not null,
              recorded_at text not null
            )
            """,
            """
            create table if not exists artifact_inventory (
              artifact_id text not null,
              harness text not null,
              artifact_name text not null,
              artifact_type text not null,
              source_scope text not null,
              config_path text not null,
              publisher text,
              origin_url text,
              launch_command text,
              transport text,
              first_seen_at text not null,
              last_seen_at text not null,
              last_changed_at text,
              last_approved_at text,
              removed_at text,
              present integer not null default 1,
              last_policy_action text not null,
              artifact_hash text not null,
              primary key (artifact_id, harness)
            )
            """,
            """
            create table if not exists policy_decisions (
              decision_id integer primary key autoincrement,
              harness text not null,
              scope text not null,
              artifact_id text,
              artifact_hash text,
              workspace text,
              publisher text,
              action text not null,
              reason text,
              owner text,
              source text not null default 'local',
              expires_at text,
              updated_at text not null
            )
            """,
            """
            create table if not exists runtime_receipts (
              receipt_id text primary key,
              harness text not null,
              artifact_id text not null,
              artifact_hash text not null,
              policy_decision text not null,
              capabilities_summary text not null default '',
              changed_capabilities_json text not null,
              provenance_summary text not null,
              user_override text,
              artifact_name text,
              source_scope text,
              timestamp text not null
            )
            """,
            """
            create table if not exists publisher_cache (
              publisher_key text primary key,
              payload_json text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists sync_state (
              state_key text primary key,
              payload_json text not null,
              updated_at text not null
            )
            """,
            """
            create table if not exists guard_events (
              event_id integer primary key autoincrement,
              event_name text not null,
              payload_json text not null,
              occurred_at text not null
            )
            """,
            """
            create table if not exists guard_runtime_state (
              state_key text primary key,
              session_id text not null,
              daemon_host text not null,
              daemon_port integer not null,
              started_at text not null,
              last_heartbeat_at text not null
            )
            """,
            """
            create table if not exists managed_installs (
              harness text primary key,
              active integer not null,
              workspace text,
              manifest_json text not null,
              updated_at text not null
            )
            """,
            approval_schema_statement(),
        )
        with self._connect() as connection:
            for statement in statements:
                connection.execute(statement)
            self._ensure_policy_column(connection, "publisher", "text")
            self._ensure_policy_column(connection, "artifact_hash", "text")
            self._ensure_policy_column(connection, "owner", "text")
            self._ensure_policy_column(connection, "source", "text not null default 'local'")
            self._ensure_policy_column(connection, "expires_at", "text")
            self._ensure_runtime_receipts_column(connection, "capabilities_summary", "text not null default ''")
            self._ensure_approval_column(connection, "artifact_type", "text not null default 'artifact'")
            self._ensure_approval_column(connection, "launch_target", "text")
            self._ensure_approval_column(connection, "transport", "text")
            self._ensure_approval_column(connection, "risk_summary", "text")
            self._ensure_approval_column(connection, "risk_signals_json", "text not null default '[]'")
            self._ensure_approval_column(connection, "artifact_label", "text")
            self._ensure_approval_column(connection, "source_label", "text")
            self._ensure_approval_column(connection, "trigger_summary", "text")
            self._ensure_approval_column(connection, "why_now", "text")
            self._ensure_approval_column(connection, "launch_summary", "text")
            self._ensure_approval_column(connection, "risk_headline", "text")
            self._ensure_approval_column(connection, "workspace", "text")

    @staticmethod
    def _ensure_policy_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(policy_decisions)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table policy_decisions add column {column_name} {column_type}")

    @staticmethod
    def _ensure_runtime_receipts_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(runtime_receipts)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table runtime_receipts add column {column_name} {column_type}")

    @staticmethod
    def _ensure_approval_column(connection: sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(approval_requests)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table approval_requests add column {column_name} {column_type}")

    def list_table_names(self) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute("select name from sqlite_master where type = 'table'").fetchall()
        return sorted(str(row["name"]) for row in rows)

    def save_snapshot(
        self,
        harness: str,
        artifact_id: str,
        snapshot: dict[str, object],
        artifact_hash: str,
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into artifact_snapshots (artifact_id, harness, snapshot_json, artifact_hash, recorded_at)
                values (?, ?, ?, ?, ?)
                on conflict(artifact_id, harness) do update set
                  snapshot_json = excluded.snapshot_json,
                  artifact_hash = excluded.artifact_hash,
                  recorded_at = excluded.recorded_at
                """,
                (artifact_id, harness, json.dumps(snapshot), artifact_hash, now),
            )
            connection.execute(
                "insert into artifact_hashes (artifact_id, harness, artifact_hash, recorded_at) values (?, ?, ?, ?)",
                (artifact_id, harness, artifact_hash, now),
            )

    def get_snapshot(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select snapshot_json from artifact_snapshots where artifact_id = ? and harness = ?",
                (artifact_id, harness),
            ).fetchone()
        if row is None:
            return None
        return json.loads(str(row["snapshot_json"]))

    def list_snapshots(self, harness: str) -> dict[str, dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "select artifact_id, snapshot_json from artifact_snapshots where harness = ?",
                (harness,),
            ).fetchall()
        return {str(row["artifact_id"]): json.loads(str(row["snapshot_json"])) for row in rows}

    def delete_snapshot(self, harness: str, artifact_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "delete from artifact_snapshots where artifact_id = ? and harness = ?",
                (artifact_id, harness),
            )

    def record_diff(
        self,
        harness: str,
        artifact_id: str,
        changed_fields: list[str],
        previous_hash: str | None,
        current_hash: str,
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into artifact_diffs (
                  artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at
                )
                values (?, ?, ?, ?, ?, ?)
                """,
                (artifact_id, harness, json.dumps(changed_fields), previous_hash, current_hash, now),
            )

    def record_inventory_artifact(
        self,
        *,
        artifact: GuardArtifact,
        artifact_hash: str,
        policy_action: str,
        changed: bool,
        now: str,
        approved: bool,
    ) -> None:
        launch_command = None
        if artifact.command:
            launch_command = " ".join([artifact.command, *artifact.args]).strip()
        with self._connect() as connection:
            existing = connection.execute(
                """
                select first_seen_at from artifact_inventory where artifact_id = ? and harness = ?
                """,
                (artifact.artifact_id, artifact.harness),
            ).fetchone()
            first_seen_at = str(existing["first_seen_at"]) if existing is not None else now
            last_changed_at = now if changed else None
            last_approved_at = now if approved else None
            connection.execute(
                """
                insert into artifact_inventory (
                  artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher,
                  origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at,
                  last_approved_at, removed_at, present, last_policy_action, artifact_hash
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(artifact_id, harness) do update set
                  artifact_name = excluded.artifact_name,
                  artifact_type = excluded.artifact_type,
                  source_scope = excluded.source_scope,
                  config_path = excluded.config_path,
                  publisher = excluded.publisher,
                  origin_url = excluded.origin_url,
                  launch_command = excluded.launch_command,
                  transport = excluded.transport,
                  last_seen_at = excluded.last_seen_at,
                  last_changed_at = coalesce(excluded.last_changed_at, artifact_inventory.last_changed_at),
                  last_approved_at = coalesce(excluded.last_approved_at, artifact_inventory.last_approved_at),
                  removed_at = null,
                  present = 1,
                  last_policy_action = excluded.last_policy_action,
                  artifact_hash = excluded.artifact_hash
                """,
                (
                    artifact.artifact_id,
                    artifact.harness,
                    artifact.name,
                    artifact.artifact_type,
                    artifact.source_scope,
                    artifact.config_path,
                    artifact.publisher,
                    artifact.url,
                    launch_command,
                    artifact.transport,
                    first_seen_at,
                    now,
                    last_changed_at,
                    last_approved_at,
                    None,
                    1,
                    policy_action,
                    artifact_hash,
                ),
            )

    def mark_inventory_removed(
        self,
        *,
        harness: str,
        artifact_id: str,
        policy_action: str,
        artifact_hash: str,
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update artifact_inventory
                set last_seen_at = ?, last_changed_at = ?, removed_at = ?, present = 0,
                    last_policy_action = ?, artifact_hash = ?
                where artifact_id = ? and harness = ?
                """,
                (now, now, now, policy_action, artifact_hash, artifact_id, harness),
            )

    def list_inventory(self, harness: str | None = None) -> list[dict[str, object]]:
        query = """
            select artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher,
                   origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at,
                   last_approved_at, removed_at, present, last_policy_action, artifact_hash
            from artifact_inventory
        """
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        query += " order by harness asc, artifact_name asc"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "artifact_id": str(row["artifact_id"]),
                "harness": str(row["harness"]),
                "artifact_name": str(row["artifact_name"]),
                "artifact_type": str(row["artifact_type"]),
                "source_scope": str(row["source_scope"]),
                "config_path": str(row["config_path"]),
                "publisher": row["publisher"],
                "origin_url": row["origin_url"],
                "launch_command": row["launch_command"],
                "transport": row["transport"],
                "first_seen_at": str(row["first_seen_at"]),
                "last_seen_at": str(row["last_seen_at"]),
                "last_changed_at": row["last_changed_at"],
                "last_approved_at": row["last_approved_at"],
                "removed_at": row["removed_at"],
                "present": bool(row["present"]),
                "last_policy_action": str(row["last_policy_action"]),
                "artifact_hash": str(row["artifact_hash"]),
            }
            for row in rows
        ]

    def find_inventory_item(self, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher,
                       origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at,
                       last_approved_at, removed_at, present, last_policy_action, artifact_hash
                from artifact_inventory
                where artifact_id = ?
                order by last_seen_at desc
                limit 1
                """,
                (artifact_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "artifact_id": str(row["artifact_id"]),
            "harness": str(row["harness"]),
            "artifact_name": str(row["artifact_name"]),
            "artifact_type": str(row["artifact_type"]),
            "source_scope": str(row["source_scope"]),
            "config_path": str(row["config_path"]),
            "publisher": row["publisher"],
            "origin_url": row["origin_url"],
            "launch_command": row["launch_command"],
            "transport": row["transport"],
            "first_seen_at": str(row["first_seen_at"]),
            "last_seen_at": str(row["last_seen_at"]),
            "last_changed_at": row["last_changed_at"],
            "last_approved_at": row["last_approved_at"],
            "removed_at": row["removed_at"],
            "present": bool(row["present"]),
            "last_policy_action": str(row["last_policy_action"]),
            "artifact_hash": str(row["artifact_hash"]),
        }

    def upsert_policy(self, decision: PolicyDecision, now: str) -> None:
        artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
        with self._connect() as connection:
            connection.execute(
                """
                delete from policy_decisions
                where harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '')
                  and coalesce(artifact_hash, '') = coalesce(?, '')
                  and coalesce(workspace, '') = coalesce(?, '')
                  and coalesce(publisher, '') = coalesce(?, '')
                """,
                (decision.harness, decision.scope, artifact_id, artifact_hash, workspace, publisher),
            )
            connection.execute(
                """
                insert into policy_decisions (
                  harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                  expires_at, updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    decision.expires_at,
                    now,
                ),
            )

    def replace_remote_policies(self, decisions: list[PolicyDecision], now: str) -> None:
        with self._connect() as connection:
            connection.execute("delete from policy_decisions where source in ('cloud-sync', 'team-policy')")
            for decision in decisions:
                artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
                connection.execute(
                    """
                    insert into policy_decisions (
                      harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                      expires_at, updated_at
                    )
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.harness,
                        decision.scope,
                        artifact_id,
                        artifact_hash,
                        workspace,
                        publisher,
                        decision.action,
                        decision.reason,
                        decision.owner,
                        decision.source,
                        decision.expires_at,
                        now,
                    ),
                )

    def resolve_policy(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
    ) -> str | None:
        current_time = now or _now()
        with self._connect() as connection:
            rows = connection.execute(
                """
                select scope, action, artifact_hash from policy_decisions
                where (harness = ? or harness = '*') and (
                  (
                    scope = 'artifact' and artifact_id = ? and (
                      artifact_hash is null or (? is not null and artifact_hash = ?)
                    )
                  )
                  or (scope = 'workspace' and workspace = ?)
                  or (scope = 'publisher' and publisher = ?)
                  or scope = 'harness'
                  or scope = 'global'
                )
                and (expires_at is null or expires_at > ?)
                order by case scope when 'artifact' then 0 when 'workspace' then 1 when 'publisher' then 2
                         when 'harness' then 3 else 4 end,
                         updated_at desc
                """,
                (harness, artifact_id, artifact_hash, artifact_hash, workspace, publisher, current_time),
            ).fetchall()
        return str(rows[0]["action"]) if rows else None

    @staticmethod
    def _normalized_policy_keys(decision: PolicyDecision) -> tuple[str | None, str | None, str | None, str | None]:
        artifact_id = decision.artifact_id if decision.scope == "artifact" else None
        artifact_hash = decision.artifact_hash if decision.scope == "artifact" else None
        workspace = decision.workspace if decision.scope == "workspace" else None
        publisher = decision.publisher if decision.scope == "publisher" else None
        return artifact_id, artifact_hash, workspace, publisher

    def add_receipt(self, receipt: GuardReceipt) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into runtime_receipts (
                  receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                  changed_capabilities_json,
                  provenance_summary, user_override, artifact_name, source_scope, timestamp
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.harness,
                    receipt.artifact_id,
                    receipt.artifact_hash,
                    receipt.policy_decision,
                    receipt.capabilities_summary,
                    json.dumps(list(receipt.changed_capabilities)),
                    receipt.provenance_summary,
                    receipt.user_override,
                    receipt.artifact_name,
                    receipt.source_scope,
                    receipt.timestamp,
                ),
            )

    def list_receipts(self, limit: int = 50) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                       changed_capabilities_json,
                       provenance_summary, user_override, artifact_name, source_scope, timestamp
                from runtime_receipts
                order by timestamp desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "receipt_id": str(row["receipt_id"]),
                "harness": str(row["harness"]),
                "artifact_id": str(row["artifact_id"]),
                "artifact_hash": str(row["artifact_hash"]),
                "policy_decision": str(row["policy_decision"]),
                "capabilities_summary": str(row["capabilities_summary"]),
                "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
                "provenance_summary": str(row["provenance_summary"]),
                "user_override": row["user_override"],
                "artifact_name": row["artifact_name"],
                "source_scope": row["source_scope"],
                "timestamp": str(row["timestamp"]),
            }
            for row in rows
        ]

    def get_receipt(self, receipt_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                       changed_capabilities_json,
                       provenance_summary, user_override, artifact_name, source_scope, timestamp
                from runtime_receipts
                where receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "receipt_id": str(row["receipt_id"]),
            "harness": str(row["harness"]),
            "artifact_id": str(row["artifact_id"]),
            "artifact_hash": str(row["artifact_hash"]),
            "policy_decision": str(row["policy_decision"]),
            "capabilities_summary": str(row["capabilities_summary"]),
            "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
            "provenance_summary": str(row["provenance_summary"]),
            "user_override": row["user_override"],
            "artifact_name": row["artifact_name"],
            "source_scope": row["source_scope"],
            "timestamp": str(row["timestamp"]),
        }

    def get_latest_receipt(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select receipt_id, harness, artifact_id, artifact_hash, policy_decision, capabilities_summary,
                       changed_capabilities_json,
                       provenance_summary, user_override, artifact_name, source_scope, timestamp
                from runtime_receipts
                where harness = ? and artifact_id = ?
                order by timestamp desc
                limit 1
                """,
                (harness, artifact_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "receipt_id": str(row["receipt_id"]),
            "harness": str(row["harness"]),
            "artifact_id": str(row["artifact_id"]),
            "artifact_hash": str(row["artifact_hash"]),
            "policy_decision": str(row["policy_decision"]),
            "capabilities_summary": str(row["capabilities_summary"]),
            "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
            "provenance_summary": str(row["provenance_summary"]),
            "user_override": row["user_override"],
            "artifact_name": row["artifact_name"],
            "source_scope": row["source_scope"],
            "timestamp": str(row["timestamp"]),
        }

    def count_receipts(self, harness: str | None = None) -> int:
        query = "select count(*) as total from runtime_receipts"
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row["total"]) if row is not None else 0

    def upsert_runtime_state(
        self,
        *,
        session_id: str,
        daemon_host: str,
        daemon_port: int,
        started_at: str,
        last_heartbeat_at: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_runtime_state (
                  state_key, session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                )
                values ('runtime', ?, ?, ?, ?, ?)
                on conflict(state_key) do update set
                  session_id = excluded.session_id,
                  daemon_host = excluded.daemon_host,
                  daemon_port = excluded.daemon_port,
                  started_at = excluded.started_at,
                  last_heartbeat_at = excluded.last_heartbeat_at
                """,
                (session_id, daemon_host, daemon_port, started_at, last_heartbeat_at),
            )

    def touch_runtime_state(self, *, session_id: str, last_heartbeat_at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update guard_runtime_state
                set last_heartbeat_at = ?
                where state_key = 'runtime'
                  and session_id = ?
                """,
                (last_heartbeat_at, session_id),
            )

    def get_runtime_state(self) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                from guard_runtime_state
                where state_key = 'runtime'
                """
            ).fetchone()
        if row is None:
            return None
        return GuardRuntimeState(
            session_id=str(row["session_id"]),
            daemon_host=str(row["daemon_host"]),
            daemon_port=int(row["daemon_port"]),
            started_at=str(row["started_at"]),
            last_heartbeat_at=str(row["last_heartbeat_at"]),
        ).to_dict()

    def clear_runtime_state(self, *, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                delete from guard_runtime_state
                where state_key = 'runtime'
                  and session_id = ?
                """,
                (session_id,),
            )

    def add_approval_request(self, request: GuardApprovalRequest, now: str) -> str:
        with self._connect() as connection:
            return persist_approval_request(connection, request, now)

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
    ) -> list[dict[str, object]]:
        with self._connect() as connection:
            return load_approval_requests(connection, status=status, harness=harness, limit=limit)

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_approval_request(connection, request_id)

    def resolve_approval_request(
        self,
        request_id: str,
        *,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
    ) -> None:
        with self._connect() as connection:
            persist_approval_resolution(
                connection,
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )

    def resolve_matching_approval_requests(
        self,
        *,
        harness: str,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
        resolution_action: str,
        resolution_scope: str,
        reason: str | None,
        resolved_at: str,
    ) -> list[str]:
        pending = self.list_approval_requests(status="pending", harness=harness, limit=None)
        resolved_ids: list[str] = []
        for item in pending:
            if not self._matches_scope(
                item,
                scope=scope,
                artifact_id=artifact_id,
                workspace=workspace,
                publisher=publisher,
            ):
                continue
            request_id = str(item["request_id"])
            self.resolve_approval_request(
                request_id,
                resolution_action=resolution_action,
                resolution_scope=resolution_scope,
                reason=reason,
                resolved_at=resolved_at,
            )
            resolved_ids.append(request_id)
        return resolved_ids

    @staticmethod
    def _matches_scope(
        item: dict[str, object],
        *,
        scope: str,
        artifact_id: str | None,
        workspace: str | None,
        publisher: str | None,
    ) -> bool:
        if scope == "global":
            return True
        if scope == "harness":
            return True
        if scope == "artifact":
            return str(item["artifact_id"]) == artifact_id
        if scope == "publisher":
            return isinstance(item.get("publisher"), str) and item.get("publisher") == publisher
        if scope == "workspace" and isinstance(workspace, str):
            config_path = str(item.get("config_path") or "")
            return _path_within_workspace(config_path, workspace)
        return False

    def count_approval_requests(self, *, status: str | None = "pending") -> int:
        with self._connect() as connection:
            return count_pending_approval_requests(connection, status=status)

    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]:
        query = """
            select harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
                   expires_at, updated_at
            from policy_decisions
        """
        params: tuple[object, ...] = ()
        if harness is not None:
            query += " where harness = ?"
            params = (harness,)
        query += " order by updated_at desc"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "harness": str(row["harness"]),
                "scope": str(row["scope"]),
                "artifact_id": row["artifact_id"],
                "artifact_hash": row["artifact_hash"],
                "workspace": row["workspace"],
                "publisher": row["publisher"],
                "action": str(row["action"]),
                "reason": row["reason"],
                "owner": row["owner"],
                "source": str(row["source"]),
                "expires_at": row["expires_at"],
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def get_latest_diff(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at
                from artifact_diffs
                where harness = ? and artifact_id = ?
                order by diff_id desc
                limit 1
                """,
                (harness, artifact_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "artifact_id": str(row["artifact_id"]),
            "harness": str(row["harness"]),
            "changed_fields": json.loads(str(row["changed_fields_json"])),
            "previous_hash": row["previous_hash"],
            "current_hash": str(row["current_hash"]),
            "recorded_at": str(row["recorded_at"]),
        }

    def set_managed_install(
        self,
        harness: str,
        active: bool,
        workspace: str | None,
        manifest: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into managed_installs (harness, active, workspace, manifest_json, updated_at)
                values (?, ?, ?, ?, ?)
                on conflict(harness) do update set
                  active = excluded.active,
                  workspace = excluded.workspace,
                  manifest_json = excluded.manifest_json,
                  updated_at = excluded.updated_at
                """,
                (harness, 1 if active else 0, workspace, json.dumps(manifest), now),
            )

    def get_managed_install(self, harness: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select harness, active, workspace, manifest_json, updated_at from managed_installs where harness = ?",
                (harness,),
            ).fetchone()
        if row is None:
            return None
        return {
            "harness": str(row["harness"]),
            "active": bool(row["active"]),
            "workspace": row["workspace"],
            "manifest": json.loads(str(row["manifest_json"])),
            "updated_at": str(row["updated_at"]),
        }

    def list_managed_installs(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select harness, active, workspace, manifest_json, updated_at
                from managed_installs
                order by harness asc
                """
            ).fetchall()
        return [
            {
                "harness": str(row["harness"]),
                "active": bool(row["active"]),
                "workspace": row["workspace"],
                "manifest": json.loads(str(row["manifest_json"])),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def cache_advisories(self, advisories: list[dict[str, object]], now: str) -> int:
        stored = 0
        with self._connect() as connection:
            for advisory in advisories:
                cache_key = self._advisory_cache_key(advisory)
                connection.execute(
                    """
                    insert into publisher_cache (publisher_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(publisher_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (cache_key, json.dumps(advisory), now),
                )
                stored += 1
        return stored

    def list_cached_advisories(self, limit: int | None = 100) -> list[dict[str, object]]:
        with self._connect() as connection:
            if limit is None:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    select publisher_key, payload_json, updated_at
                    from publisher_cache
                    order by updated_at desc
                    limit ?
                    """,
                    (limit,),
                ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                continue
            items.append(
                {
                    "cache_key": str(row["publisher_key"]),
                    "updated_at": str(row["updated_at"]),
                    **payload,
                }
            )
        return items

    def set_sync_credentials(self, sync_url: str, token: str, now: str) -> None:
        payload = {"sync_url": sync_url, "token": token}
        with self._connect() as connection:
            previous_row = connection.execute(
                "select payload_json from sync_state where state_key = 'credentials'"
            ).fetchone()
            credentials_changed = False
            if previous_row is None:
                credentials_changed = True
            else:
                previous_payload = json.loads(str(previous_row["payload_json"]))
                credentials_changed = previous_payload != payload
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values ('credentials', ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (json.dumps(payload), now),
            )
            if credentials_changed:
                connection.execute("delete from sync_state where state_key != 'credentials'")
                connection.execute("delete from publisher_cache")
                connection.execute("delete from policy_decisions where source in ('cloud-sync', 'team-policy')")

    def set_sync_payload(self, state_key: str, payload: dict[str, object] | list[object], now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (state_key, json.dumps(payload), now),
            )

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
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

    def add_event(self, event_name: str, payload: dict[str, object], now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_events (event_name, payload_json, occurred_at)
                values (?, ?, ?)
                """,
                (event_name, json.dumps(payload), now),
            )

    def list_events(self, limit: int = 100, event_name: str | None = None) -> list[dict[str, object]]:
        query = """
            select event_id, event_name, payload_json, occurred_at
            from guard_events
        """
        params: tuple[object, ...] = ()
        if event_name is not None:
            query += " where event_name = ?"
            params = (event_name,)
        query += " order by occurred_at desc, event_id desc limit ?"
        params = (*params, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            items.append(
                {
                    "event_id": int(row["event_id"]),
                    "event_name": str(row["event_name"]),
                    "occurred_at": str(row["occurred_at"]),
                    "payload": payload,
                }
            )
        return items

    def list_events_after(
        self,
        event_id: int,
        *,
        limit: int = 100,
        event_names: tuple[str, ...] | None = None,
    ) -> list[dict[str, object]]:
        query = """
            select event_id, event_name, payload_json, occurred_at
            from guard_events
            where event_id > ?
        """
        params: list[object] = [event_id]
        if event_names:
            placeholders = ", ".join("?" for _ in event_names)
            query += f" and event_name in ({placeholders})"
            params.extend(event_names)
        query += " order by event_id asc limit ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                payload = {}
            items.append(
                {
                    "event_id": int(row["event_id"]),
                    "event_name": str(row["event_name"]),
                    "occurred_at": str(row["occurred_at"]),
                    "payload": payload,
                }
            )
        return items

    def get_sync_credentials(self) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute("select payload_json from sync_state where state_key = 'credentials'").fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        if not isinstance(payload, dict):
            return None
        sync_url = payload.get("sync_url")
        token = payload.get("token")
        if not isinstance(sync_url, str) or not isinstance(token, str):
            return None
        return {"sync_url": sync_url, "token": token}

    @staticmethod
    def _advisory_cache_key(advisory: dict[str, object]) -> str:
        advisory_id = advisory.get("id")
        if isinstance(advisory_id, str) and advisory_id.strip():
            return advisory_id.strip()
        advisory_digest = sha256(
            json.dumps(advisory, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        return f"anonymous:{advisory_digest}"


def _path_within_workspace(config_path: str, workspace: str) -> bool:
    config_path_obj = Path(config_path)
    workspace_path_obj = Path(workspace)
    return config_path_obj == workspace_path_obj or workspace_path_obj in config_path_obj.parents


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
