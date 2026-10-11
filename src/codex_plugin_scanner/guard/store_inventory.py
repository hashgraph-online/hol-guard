"""GuardStore domain mixin extracted from store.py.

Artifact snapshots, diffs, inventory, capabilities, provenance cache and the
attestation sequence run in the native resident (``guard_store`` op), which owns
the SQL and the decision-contract canonicalization. Python serializes the
inputs and shapes the decoded rows; it never recomputes what the resident
persists. Local device metadata stays here.
"""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from .models import GuardAction

# ruff: noqa: F403,F405
from .store_base import *


class StoreInventoryMixin:
    def save_snapshot(
        self,
        harness: str,
        artifact_id: str,
        snapshot: dict[str, object],
        artifact_hash: str,
        now: str,
    ) -> None:
        self._native_store_call(
            "save_artifact_snapshot",
            {
                "harness": harness,
                "artifact_id": artifact_id,
                "snapshot_json": json.dumps(snapshot),
                "artifact_hash": artifact_hash,
                "now": now,
            },
        )

    def get_snapshot(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        row = self._native_store_call("get_artifact_snapshot", {"harness": harness, "artifact_id": artifact_id})
        if row is None:
            return None
        return json.loads(str(row["snapshot_json"]))

    def list_snapshots(self, harness: str) -> dict[str, dict[str, object]]:
        rows = self._resident_inventory_rows("list_artifact_snapshots", {"harness": harness})
        return {str(row["artifact_id"]): json.loads(str(row["snapshot_json"])) for row in rows}

    def delete_snapshot(self, harness: str, artifact_id: str) -> None:
        self._native_store_call("delete_artifact_snapshot", {"harness": harness, "artifact_id": artifact_id})

    def record_diff(
        self,
        harness: str,
        artifact_id: str,
        changed_fields: list[str],
        previous_hash: str | None,
        current_hash: str,
        now: str,
    ) -> None:
        self._native_store_call(
            "record_artifact_diff",
            {
                "harness": harness,
                "artifact_id": artifact_id,
                "changed_fields_json": json.dumps(changed_fields),
                "previous_hash": previous_hash,
                "current_hash": current_hash,
                "now": now,
            },
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
        launch_command = None
        if artifact.command:
            launch_command = " ".join([artifact.command, *artifact.args]).strip()
        self._native_store_call(
            "record_inventory_artifact",
            {
                "artifact_id": artifact.artifact_id,
                "harness": artifact.harness,
                "artifact_name": artifact.name,
                "artifact_type": artifact.artifact_type,
                "source_scope": artifact.source_scope,
                "config_path": artifact.config_path,
                "publisher": artifact.publisher,
                "origin_url": artifact.url,
                "launch_command": launch_command,
                "transport": artifact.transport,
                "artifact_hash": artifact_hash,
                "policy_action": policy_action,
                "changed": changed,
                "approved": approved,
                "now": now,
            },
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
        self._native_store_call(
            "mark_inventory_removed",
            {
                "harness": harness,
                "artifact_id": artifact_id,
                "policy_action": policy_action,
                "artifact_hash": artifact_hash,
                "now": now,
            },
        )

    def list_inventory(self, harness: str | None = None) -> list[dict[str, object]]:
        return self._resident_inventory_rows("list_artifact_inventory", {"harness": harness})

    def _resident_inventory_rows(self, method: str, args: dict[str, object]) -> list[dict[str, object]]:
        """Follow resident pages until the ordered result is exhausted.

        Each reply stays under the resident response cap. A resident failure or a
        cursor that does not advance raises, and the rows already collected are
        not returned as a complete inventory.
        """

        rows: list[dict[str, object]] = []
        cursor: dict[str, object] | None = None
        while True:
            page_args = dict(args)
            if cursor is not None:
                page_args["after"] = cursor
            page = self._native_store_call(method, page_args)
            if not isinstance(page, dict):
                raise ValueError("native_inventory_page_invalid")
            batch = page.get("rows")
            if not isinstance(batch, list) or not all(isinstance(row, dict) for row in batch):
                raise ValueError("native_inventory_page_invalid")
            rows.extend(dict(row) for row in batch)
            following = page.get("next")
            if following is None:
                return rows
            if not isinstance(following, dict) or following == cursor:
                raise ValueError("native_inventory_page_stalled")
            cursor = dict(following)

    def find_inventory_item(self, artifact_id: str) -> dict[str, object] | None:
        return self._native_store_call("find_artifact_inventory_item", {"artifact_id": artifact_id})

    def save_artifact_capability(
        self,
        *,
        harness: str,
        artifact_id: str,
        capability_snapshot: dict[str, object],
        now: str,
    ) -> None:
        self._native_store_call(
            "save_artifact_capability",
            {
                "harness": harness,
                "artifact_id": artifact_id,
                "capability_json": json.dumps(capability_snapshot),
                "now": now,
            },
        )

    def get_artifact_capability(self, harness: str, artifact_id: str) -> CapabilitySet | None:
        row = self._native_store_call("get_artifact_capability", {"harness": harness, "artifact_id": artifact_id})
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
        self._native_store_call(
            "upsert_provenance_cache",
            {"artifact_hash": artifact_hash, "payload_json": json.dumps(payload), "now": now},
        )

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
        return int(self._native_store_call("next_aibom_trust_attestation_sequence", {"now": now}))
