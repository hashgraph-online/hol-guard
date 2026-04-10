"""SQLite-backed local Guard persistence."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .models import GuardReceipt, PolicyDecision


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
            create table if not exists policy_decisions (
              decision_id integer primary key autoincrement,
              harness text not null,
              scope text not null,
              artifact_id text,
              workspace text,
              action text not null,
              reason text,
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
            create table if not exists managed_installs (
              harness text primary key,
              active integer not null,
              workspace text,
              manifest_json text not null,
              updated_at text not null
            )
            """,
        )
        with self._connect() as connection:
            for statement in statements:
                connection.execute(statement)

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

    def upsert_policy(self, decision: PolicyDecision, now: str) -> None:
        artifact_id, workspace = self._normalized_policy_keys(decision)
        with self._connect() as connection:
            connection.execute(
                """
                delete from policy_decisions
                where harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '')
                  and coalesce(workspace, '') = coalesce(?, '')
                """,
                (decision.harness, decision.scope, artifact_id, workspace),
            )
            connection.execute(
                """
                insert into policy_decisions (harness, scope, artifact_id, workspace, action, reason, updated_at)
                values (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    workspace,
                    decision.action,
                    decision.reason,
                    now,
                ),
            )

    def resolve_policy(self, harness: str, artifact_id: str | None, workspace: str | None) -> str | None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select scope, action from policy_decisions
                where harness = ? and (
                  (scope = 'artifact' and artifact_id = ?)
                  or (scope = 'workspace' and workspace = ?)
                  or scope = 'harness'
                  or scope = 'global'
                )
                order by case scope when 'artifact' then 0 when 'workspace' then 1 when 'harness' then 2 else 3 end,
                         updated_at desc
                """,
                (harness, artifact_id, workspace),
            ).fetchall()
        return str(rows[0]["action"]) if rows else None

    @staticmethod
    def _normalized_policy_keys(decision: PolicyDecision) -> tuple[str | None, str | None]:
        artifact_id = decision.artifact_id if decision.scope == "artifact" else None
        workspace = decision.workspace if decision.scope == "workspace" else None
        return artifact_id, workspace

    def add_receipt(self, receipt: GuardReceipt) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into runtime_receipts (
                  receipt_id, harness, artifact_id, artifact_hash, policy_decision, changed_capabilities_json,
                  provenance_summary, user_override, artifact_name, source_scope, timestamp
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.harness,
                    receipt.artifact_id,
                    receipt.artifact_hash,
                    receipt.policy_decision,
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
                select receipt_id, harness, artifact_id, artifact_hash, policy_decision, changed_capabilities_json,
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
                "changed_capabilities": json.loads(str(row["changed_capabilities_json"])),
                "provenance_summary": str(row["provenance_summary"]),
                "user_override": row["user_override"],
                "artifact_name": row["artifact_name"],
                "source_scope": row["source_scope"],
                "timestamp": str(row["timestamp"]),
            }
            for row in rows
        ]

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

    def set_sync_credentials(self, sync_url: str, token: str, now: str) -> None:
        payload = {"sync_url": sync_url, "token": token}
        with self._connect() as connection:
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
