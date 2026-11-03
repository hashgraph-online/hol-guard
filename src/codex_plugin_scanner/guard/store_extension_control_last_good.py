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
    AuthorityAnchor,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    layers_from_json,
)
from .store_extension_control_authority_support import _now, _plan_int, _plan_map, _plan_record

_LOGGER = logging.getLogger(__name__)
LAST_GOOD_FILE_NAME = "extension-control-last-good.json"
LAST_GOOD_SCHEMA = "guard.extension-control-last-good.v1"
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

    def _restore_last_good_authority(self, *, key: bytes) -> bool:
        """Re-create the snapshot row from the export when it matches the vault anchor.

        The resident reads and verifies the export and seals any baseline
        transition; this method only applies its plan.
        """

        anchor_json = self._read_anchor_json()
        if anchor_json is None:
            return False
        plan = _plan_map(
            self._extension_control_authority_op("restore_plan", key=key, anchor_json=anchor_json, now=_now()),
            "plan",
        )
        if plan.get("outcome") != "restore":
            return False
        revision = _plan_int(plan, "revision")
        control_count = _plan_int(plan, "control_count")
        catalog_digest, layers_json = str(plan["catalog_digest"]), str(plan["layers_json"])
        committed_at, restored_at = str(plan["committed_at"]), str(plan["restored_at"])
        previous_digest = plan.get("previous_digest")
        snapshot_json, snapshot_digest, snapshot_mac = _plan_record(plan, "snapshot")
        baseline = plan.get("baseline")
        with self._connect() as connection:
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
                    None if previous_digest is None else str(previous_digest),
                    snapshot_json,
                    snapshot_digest,
                    snapshot_mac,
                    committed_at,
                ),
            )
            if baseline is not None:
                hashes = _plan_map(_plan_map(plan, "baseline"), "hashes")
                transition_json, transition_digest, transition_mac = _plan_record(
                    _plan_map(plan, "baseline"), "transition"
                )
                # The baseline's created_at equals the snapshot's committed_at,
                # which chain validation requires of the pair.
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
                        str(hashes["actor"]),
                        str(hashes["idempotency"]),
                        str(hashes["nonce"]),
                        catalog_digest,
                        layers_json,
                        snapshot_json,
                        snapshot_digest,
                        snapshot_mac,
                        transition_json,
                        transition_digest,
                        transition_mac,
                        committed_at,
                        restored_at,
                    ),
                )
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                (
                    "extension_control_authority_restored",
                    json.dumps(
                        {"revision": revision, "control_count": control_count, "source": "last-good-export"},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    restored_at,
                ),
            )
        _LOGGER.warning(
            "Guard restored %d extension control(s) at revision %d from its last-good export.",
            control_count,
            revision,
        )
        return True
