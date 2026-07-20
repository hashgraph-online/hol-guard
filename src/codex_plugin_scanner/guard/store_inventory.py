"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from .action_lattice import normalize_guard_action_result
from .models import GuardAction
from .runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT

# ruff: noqa: F403,F405
from .store_base import *


def _canonical_inventory_action(value: object, *, reject_unknown: bool) -> tuple[GuardAction, str | None]:
    normalization = normalize_guard_action_result(value, unknown_action="require-reapproval")
    if reject_unknown and not normalization.recognized:
        raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
    return (
        normalization.action,
        None if normalization.recognized else AUTHORITATIVE_DECISION_INCONSISTENT,
    )


def _inventory_payload_from_row(row: sqlite3.Row) -> dict[str, object]:
    action, contract_error = _canonical_inventory_action(row["last_policy_action"], reject_unknown=False)
    payload: dict[str, object] = {
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
        "last_approved_at": row["last_approved_at"] if action in {"allow", "warn"} else None,
        "removed_at": row["removed_at"],
        "present": bool(row["present"]),
        "last_policy_action": action,
        "artifact_hash": str(row["artifact_hash"]),
    }
    if contract_error is not None:
        payload["decision_contract_error"] = contract_error
    return payload


class StoreInventoryMixin:
    def save_scanner_cache(
        self,
        *,
        scanner_name: str,
        target_id: str,
        input_content_hash: str,
        scanner_version: str,
        payload: dict[str, object],
        now: str,
    ) -> None:
        cache_key = scanner_cache_key(
            scanner_name=scanner_name,
            input_content_hash=input_content_hash,
            scanner_version=scanner_version,
        )
        with self._connect() as connection:
            connection.execute(
                """
                insert into scanner_cache (
                  scanner_name, target_id, cache_key, input_content_hash, scanner_version, payload_json, updated_at
                )
                values (?, ?, ?, ?, ?, ?, ?)
                on conflict(scanner_name, target_id) do update set
                  cache_key = excluded.cache_key,
                  input_content_hash = excluded.input_content_hash,
                  scanner_version = excluded.scanner_version,
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (
                    scanner_name,
                    target_id,
                    cache_key,
                    input_content_hash,
                    scanner_version,
                    json.dumps(payload, sort_keys=True),
                    now,
                ),
            )

    def get_scanner_cache(
        self,
        *,
        scanner_name: str,
        target_id: str,
        input_content_hash: str,
        scanner_version: str,
    ) -> dict[str, object] | None:
        cache_key = scanner_cache_key(
            scanner_name=scanner_name,
            input_content_hash=input_content_hash,
            scanner_version=scanner_version,
        )
        with self._connect() as connection:
            row = connection.execute(
                """
                select payload_json from scanner_cache
                where scanner_name = ? and target_id = ? and cache_key = ?
                """,
                (scanner_name, target_id, cache_key),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        return payload if isinstance(payload, dict) else None

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
        policy_action: GuardAction,
        changed: bool,
        now: str,
        approved: bool,
    ) -> None:
        canonical_action, _contract_error = _canonical_inventory_action(policy_action, reject_unknown=True)
        if approved and canonical_action not in {"allow", "warn"}:
            raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
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
                  last_approved_at = excluded.last_approved_at,
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
                    canonical_action,
                    artifact_hash,
                ),
            )

    def mark_inventory_removed(
        self,
        *,
        harness: str,
        artifact_id: str,
        policy_action: GuardAction,
        artifact_hash: str,
        now: str,
    ) -> None:
        canonical_action, _contract_error = _canonical_inventory_action(policy_action, reject_unknown=True)
        with self._connect() as connection:
            connection.execute(
                """
                update artifact_inventory
                set last_seen_at = ?, last_changed_at = ?, removed_at = ?, present = 0,
                    last_approved_at = case when ? in ('allow', 'warn') then last_approved_at else null end,
                    last_policy_action = ?, artifact_hash = ?
                where artifact_id = ? and harness = ?
                """,
                (now, now, now, canonical_action, canonical_action, artifact_hash, artifact_id, harness),
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
        return [_inventory_payload_from_row(row) for row in rows]

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
        return _inventory_payload_from_row(row)

    def save_artifact_capability(
        self,
        *,
        harness: str,
        artifact_id: str,
        capability_snapshot: dict[str, object],
        now: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into artifact_capabilities (artifact_id, harness, capability_json, updated_at)
                values (?, ?, ?, ?)
                on conflict(artifact_id, harness) do update set
                  capability_json = excluded.capability_json,
                  updated_at = excluded.updated_at
                """,
                (artifact_id, harness, json.dumps(capability_snapshot), now),
            )

    def get_artifact_capability(self, harness: str, artifact_id: str) -> CapabilitySet | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select capability_json
                from artifact_capabilities
                where artifact_id = ? and harness = ?
                """,
                (artifact_id, harness),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["capability_json"]))
        if not isinstance(payload, dict):
            return None
        return CapabilitySet(
            network_hosts=tuple(_string_list(payload.get("network_hosts"))),
            network_schemes=tuple(_string_list(payload.get("network_schemes"))),
            filesystem_paths=tuple(_string_list(payload.get("filesystem_paths"))),
            secret_classes=tuple(_string_list(payload.get("secret_classes"))),
            subprocess_invocation=bool(payload.get("subprocess_invocation")),
            interpreters=tuple(_string_list(payload.get("interpreters"))),
            shell_wrappers=tuple(_string_list(payload.get("shell_wrappers"))),
            publisher=payload.get("publisher") if isinstance(payload.get("publisher"), str) else None,
            transport=_transport_value(payload.get("transport")),
        )

    def upsert_provenance_cache(self, *, artifact_hash: str, payload: dict[str, object], now: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into provenance_cache (artifact_hash, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(artifact_hash) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (artifact_hash, json.dumps(payload), now),
            )

    def get_provenance_cache(self, artifact_hash: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select payload_json from provenance_cache where artifact_hash = ?",
                (artifact_hash,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["payload_json"]))
        return payload if isinstance(payload, dict) else None

    def get_or_create_installation_id(self) -> str:
        with self._connect() as connection:
            self._ensure_local_device(connection)
            row = connection.execute(
                "select installation_id from guard_devices where device_key = ?",
                (_DEVICE_ROW_KEY,),
            ).fetchone()
        if row is None:
            raise RuntimeError("Guard local device row was not initialized.")
        return str(row["installation_id"])

    def set_device_label(self, label: str, now: str) -> dict[str, str]:
        normalized_label = label.strip() or "Local machine"
        with self._connect() as connection:
            self._ensure_local_device(connection)
            connection.execute(
                """
                update guard_devices
                set device_label = ?, updated_at = ?
                where device_key = ?
                """,
                (normalized_label, now, _DEVICE_ROW_KEY),
            )
        return self.get_device_metadata()

    def rotate_installation_id(self, now: str) -> dict[str, str]:
        new_installation_id = uuid4().hex
        with self._connect() as connection:
            self._ensure_local_device(connection)
            connection.execute(
                """
                update guard_devices
                set installation_id = ?, updated_at = ?
                where device_key = ?
                """,
                (new_installation_id, now, _DEVICE_ROW_KEY),
            )
        return self.get_device_metadata()

    def get_device_metadata(self) -> dict[str, str]:
        with self._connect() as connection:
            self._ensure_local_device(connection)
            row = connection.execute(
                "select installation_id, device_label from guard_devices where device_key = ?",
                (_DEVICE_ROW_KEY,),
            ).fetchone()
        if row is None:
            raise RuntimeError("Guard local device metadata is unavailable.")
        return {
            "installation_id": str(row["installation_id"]),
            "device_label": str(row["device_label"]),
        }

    def get_cloud_workspace_id(self) -> str | None:
        with self._connect() as connection:
            return self._cloud_workspace_id_from_connection(connection)

    def next_aibom_trust_attestation_sequence(self, now: str) -> int:
        state_key = "aibom_trust_attestation_sequence"
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (state_key,),
            ).fetchone()
            current_sequence = 0
            if row is not None:
                try:
                    payload = json.loads(str(row["payload_json"]))
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict):
                    raw_sequence = payload.get("sequence")
                    if isinstance(raw_sequence, int) and raw_sequence >= 0:
                        current_sequence = raw_sequence
                    elif isinstance(raw_sequence, str) and raw_sequence.isdigit():
                        current_sequence = int(raw_sequence)
            next_sequence = current_sequence + 1
            connection.execute(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                (state_key, json.dumps({"sequence": next_sequence}), now),
            )
        return next_sequence
