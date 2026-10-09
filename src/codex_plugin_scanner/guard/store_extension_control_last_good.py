"""Durable last-good export of the local extension-control authority.

The authenticated snapshot normally lives only in ``guard.db``. When that file
is quarantined and re-created, the key and anchor survive in the credential
vault but the controls would be lost. This module keeps an owner-only copy of
the latest committed snapshot beside the database. The copy is the same
authenticated record the database holds, so it is trusted only after it
verifies under the authority key and matches the vault anchor exactly.
"""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from uuid import uuid4

from .runtime.extension_control_authority import (
    SNAPSHOT_PURPOSE,
    TRANSITION_PURPOSE,
    AuthorityAnchor,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    authenticated_record,
    layers_from_json,
    verify_authenticated_record,
)
from .store_extension_control_authority_support import _now, _private_hash

_LOGGER = logging.getLogger(__name__)
LAST_GOOD_FILE_NAME = "extension-control-last-good.json"
LAST_GOOD_SCHEMA = "guard.extension-control-last-good.v1"
RESTORED_BASELINE_FIELD = "restored_baseline"
_MAX_EXPORT_BYTES = 1024 * 1024
_EXPORT_FIELDS = ("revision", "catalog_digest", "layers_json", "previous_digest", "committed_at")


def _count_controls(layers_json: str) -> int:
    try:
        return sum(len(layer.controls) for layer in layers_from_json(layers_json))
    except ExtensionControlAuthorityError:
        return 0


class ExtensionControlLastGoodMixin:
    """GuardStore mixin that exports and restores the committed authority snapshot."""

    # Human-readable notes for the most recent explicit recovery. CLI callers
    # surface these so a lossy reset is never silent.
    extension_control_recovery_warnings: tuple[str, ...] = ()

    def _last_good_path(self) -> Path:
        return cast(Path, self.guard_home) / LAST_GOOD_FILE_NAME

    def _export_last_good_authority(self, anchor: AuthorityAnchor) -> None:
        """Best-effort export of the committed snapshot the anchor just pinned."""

        if anchor.phase is not AuthorityPhase.COMMITTED:
            return
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "select * from extension_control_authority_snapshot where singleton = 1"
                ).fetchone()
            if row is None or str(row["snapshot_digest"]) != anchor.snapshot_digest:
                return
            if int(row["revision"]) != anchor.revision:
                return
            payload: dict[str, object] = {
                "schema": LAST_GOOD_SCHEMA,
                "snapshot_json": str(row["snapshot_json"]),
                "snapshot_digest": str(row["snapshot_digest"]),
                "snapshot_mac": str(row["snapshot_mac"]),
                **{name: row[name] for name in _EXPORT_FIELDS},
            }
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > _MAX_EXPORT_BYTES:
                return
            self._write_owner_only(self._last_good_path(), encoded)
        except Exception as error:
            detail = str(error) if isinstance(error, OSError | sqlite3.Error) else ""
            _LOGGER.warning(
                "Guard could not refresh the extension-control last-good export: %s %s",
                type(error).__name__,
                detail,
            )

    @staticmethod
    def _write_owner_only(path: Path, text: str) -> None:
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
                _ = handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()

    def _verified_last_good_export(self, *, key: bytes) -> dict[str, object] | None:
        path = self._last_good_path()
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_EXPORT_BYTES:
                return None
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(raw, dict) or raw.get("schema") != LAST_GOOD_SCHEMA:
            return None
        try:
            payload = verify_authenticated_record(
                str(raw["snapshot_json"]),
                expected_digest=str(raw["snapshot_digest"]),
                expected_mac=str(raw["snapshot_mac"]),
                key=key,
                purpose=SNAPSHOT_PURPOSE,
            )
        except (KeyError, ExtensionControlAuthorityError):
            return None
        if any(payload.get(name) != raw.get(name) for name in _EXPORT_FIELDS):
            return None
        revision = payload.get("revision")
        if type(revision) is not int or revision < 0:
            return None
        if not all(isinstance(payload.get(name), str) for name in ("catalog_digest", "layers_json", "committed_at")):
            return None
        return {
            **payload,
            "snapshot_json": str(raw["snapshot_json"]),
            "snapshot_digest": str(raw["snapshot_digest"]),
            "snapshot_mac": str(raw["snapshot_mac"]),
        }

    def _quarantine_unusable_last_good_export(self) -> bool:
        """Move an export that cannot be applied aside; report whether it moved."""

        path = self._last_good_path()
        if not path.is_file() or path.is_symlink():
            return False
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        try:
            os.replace(path, path.with_name(f"extension-control-last-good.unapplied-{stamp}.json"))
        except OSError:
            return False
        return True

    def _restore_last_good_authority(self, anchor: AuthorityAnchor, *, key: bytes) -> bool:
        """Re-create the snapshot row from the export when it matches the vault anchor."""

        if anchor.phase is not AuthorityPhase.COMMITTED:
            return False
        exported = self._verified_last_good_export(key=key)
        if exported is None:
            return False
        revision = cast(int, exported["revision"])
        snapshot_digest = str(exported["snapshot_digest"])
        if revision != anchor.revision or snapshot_digest != anchor.snapshot_digest:
            return False
        restored_at = _now()
        layers_json = str(exported["layers_json"])
        catalog_digest = str(exported["catalog_digest"])
        previous_digest = exported.get("previous_digest")
        with self._connect() as connection:
            existing = connection.execute(
                "select 1 from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
            if existing is not None:
                return False
            connection.execute(
                """
                insert into extension_control_authority_snapshot (
                    singleton, revision, catalog_digest, layers_json, previous_digest,
                    snapshot_json, snapshot_digest, snapshot_mac, committed_at
                ) values (1, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    revision,
                    catalog_digest,
                    layers_json,
                    previous_digest,
                    exported["snapshot_json"],
                    snapshot_digest,
                    exported["snapshot_mac"],
                    exported["committed_at"],
                ),
            )
            baseline_exists = (
                connection.execute(
                    "select 1 from extension_control_authority_transition where revision = ?", (revision,)
                ).fetchone()
                is not None
            )
            if revision > 0 and not baseline_exists:
                self._insert_restored_baseline_transition(
                    connection,
                    revision=revision,
                    catalog_digest=catalog_digest,
                    layers_json=layers_json,
                    previous_digest=str(previous_digest),
                    snapshot_json=str(exported["snapshot_json"]),
                    snapshot_digest=snapshot_digest,
                    snapshot_mac=str(exported["snapshot_mac"]),
                    restored_at=restored_at,
                    key=key,
                )
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                (
                    "extension_control_authority_restored",
                    json.dumps(
                        {
                            "revision": revision,
                            "control_count": _count_controls(layers_json),
                            "source": "last-good-export",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    restored_at,
                ),
            )
        _LOGGER.warning(
            "Guard restored %d extension control(s) at revision %d from its last-good export.",
            _count_controls(layers_json),
            revision,
        )
        return True

    def _insert_restored_baseline_transition(
        self,
        connection: sqlite3.Connection,
        *,
        revision: int,
        catalog_digest: str,
        layers_json: str,
        previous_digest: str,
        snapshot_json: str,
        snapshot_digest: str,
        snapshot_mac: str,
        restored_at: str,
        key: bytes,
    ) -> None:
        # The transition's created_at must equal the restored snapshot's
        # committed_at for chain validation to accept the pair.
        created_at = str(json.loads(snapshot_json)["committed_at"])
        ref = f"restored-baseline:{revision}:{snapshot_digest}"
        actor_hash = _private_hash("trusted-store-restore", key=key, purpose="actor")
        idempotency_hash = _private_hash(ref, key=key, purpose="idempotency")
        nonce_hash = _private_hash(ref, key=key, purpose="nonce")
        transition_json, transition_digest, transition_mac = authenticated_record(
            {
                "revision": revision,
                "previous_revision": revision - 1,
                "previous_digest": previous_digest,
                "snapshot_digest": snapshot_digest,
                "catalog_digest": catalog_digest,
                "actor_id_hash": actor_hash,
                "idempotency_key_hash": idempotency_hash,
                "nonce_hash": nonce_hash,
                "created_at": created_at,
                "phase": AuthorityPhase.PREPARED.value,
                RESTORED_BASELINE_FIELD: True,
            },
            key=key,
            purpose=TRANSITION_PURPOSE,
        )
        connection.execute(
            """
            insert into extension_control_authority_transition (
                revision, previous_revision, phase, actor_id_hash, idempotency_key_hash,
                nonce_hash, catalog_digest, layers_json, snapshot_json, snapshot_digest,
                snapshot_mac, transition_json, transition_digest, transition_mac,
                created_at, committed_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                revision,
                revision - 1,
                AuthorityPhase.COMMITTED.value,
                actor_hash,
                idempotency_hash,
                nonce_hash,
                catalog_digest,
                layers_json,
                snapshot_json,
                snapshot_digest,
                snapshot_mac,
                transition_json,
                transition_digest,
                transition_mac,
                created_at,
                restored_at,
            ),
        )
