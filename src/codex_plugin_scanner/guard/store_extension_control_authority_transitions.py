"""Authenticated extension-control transition validation and recovery helpers."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import sqlite3
from typing import cast

from .runtime.extension_control_authority import (
    SNAPSHOT_PURPOSE,
    TRANSITION_PURPOSE,
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    layers_from_json,
    verify_authenticated_record,
)
from .store_extension_control_authority_support import (
    _ExtensionControlAuthoritySupportMixin,
    _now,
    _row_int,
    _row_optional_str,
    _row_str,
)


class _ExtensionControlAuthorityTransitionMixin(_ExtensionControlAuthoritySupportMixin):
    def _resume_idempotent_transition(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        current: ExtensionControlAuthorityView,
        catalog_digest: str,
        layers_json: str,
        actor_hash: str,
        idempotency_hash: str,
        nonce_hash: str,
        expected_revision: int,
        key: bytes,
    ) -> ExtensionControlAuthorityView | None:
        self._validate_serialized_layers(layers_json)
        if (
            _row_int(row, "previous_revision") != expected_revision
            or _row_str(row, "catalog_digest") != catalog_digest
            or _row_str(row, "layers_json") != layers_json
            or _row_str(row, "actor_id_hash") != actor_hash
            or _row_str(row, "idempotency_key_hash") != idempotency_hash
            or _row_str(row, "nonce_hash") != nonce_hash
        ):
            raise ExtensionControlAuthorityError("idempotency key request mismatch")
        snapshot = connection.execute(
            "select * from extension_control_authority_snapshot where singleton = 1"
        ).fetchone()
        if snapshot is None:
            raise ExtensionControlAuthorityError("extension control authority snapshot missing")
        previous_revision = _row_int(row, "previous_revision")
        revision = _row_int(row, "revision")
        snapshot_revision = _row_int(snapshot, "revision")
        if snapshot_revision == previous_revision:
            previous_digest = _row_str(snapshot, "snapshot_digest")
        elif snapshot_revision == revision:
            previous_digest = _row_optional_str(snapshot, "previous_digest")
            if previous_digest is None:
                raise ExtensionControlAuthorityError("idempotent transition chain mismatch")
        else:
            raise ExtensionControlAuthorityError("idempotent transition revision mismatch")
        transition_payload = verify_authenticated_record(
            _row_str(row, "transition_json"),
            expected_digest=_row_str(row, "transition_digest"),
            expected_mac=_row_str(row, "transition_mac"),
            key=key,
            purpose=TRANSITION_PURPOSE,
        )
        transition_expected: dict[str, object] = {
            "revision": revision,
            "previous_revision": previous_revision,
            "previous_digest": previous_digest,
            "snapshot_digest": _row_str(row, "snapshot_digest"),
            "catalog_digest": catalog_digest,
            "actor_id_hash": actor_hash,
            "idempotency_key_hash": idempotency_hash,
            "nonce_hash": nonce_hash,
            "created_at": _row_str(row, "created_at"),
            "phase": AuthorityPhase.PREPARED.value,
        }
        if any(transition_payload.get(name) != value for name, value in transition_expected.items()):
            raise ExtensionControlAuthorityError("idempotent transition authentication mismatch")
        snapshot_payload = verify_authenticated_record(
            _row_str(row, "snapshot_json"),
            expected_digest=_row_str(row, "snapshot_digest"),
            expected_mac=_row_str(row, "snapshot_mac"),
            key=key,
            purpose=SNAPSHOT_PURPOSE,
        )
        snapshot_expected: dict[str, object] = {
            "revision": revision,
            "catalog_digest": catalog_digest,
            "layers_json": layers_json,
            "previous_digest": previous_digest,
            "committed_at": _row_str(row, "created_at"),
        }
        if any(snapshot_payload.get(name) != value for name, value in snapshot_expected.items()):
            raise ExtensionControlAuthorityError("idempotent snapshot authentication mismatch")
        anchor = self._read_anchor(key=key)
        if anchor is None:
            raise ExtensionControlAuthorityError("extension control authority anchor missing")
        if (
            snapshot_revision == previous_revision
            and anchor.revision == previous_revision
            and anchor.snapshot_digest == previous_digest
            and anchor.phase is AuthorityPhase.COMMITTED
            and _row_str(row, "phase") == AuthorityPhase.PREPARED.value
        ):
            _ = connection.execute(
                "delete from extension_control_authority_transition where revision = ?",
                (revision,),
            )
            return None
        if (
            anchor.revision == revision
            and anchor.snapshot_digest == _row_str(row, "snapshot_digest")
            and anchor.phase in {AuthorityPhase.ANCHORED, AuthorityPhase.COMMITTED}
        ):
            if snapshot_revision == previous_revision:
                self._commit_pending_transition(connection, row)
            elif _row_str(row, "phase") != AuthorityPhase.COMMITTED.value:
                _ = connection.execute(
                    "update extension_control_authority_transition set phase = ?, committed_at = ? where revision = ?",
                    (AuthorityPhase.COMMITTED.value, _now(), revision),
                )
            self._queue_extension_control_change_event(
                connection,
                revision=revision,
                previous_revision=previous_revision,
                catalog_digest=catalog_digest,
                snapshot_digest=_row_str(row, "snapshot_digest"),
                layers_json=layers_json,
                occurred_at=_row_str(row, "created_at"),
            )
            connection.commit()
            self._write_and_verify_anchor(
                AuthorityAnchor(revision, _row_str(row, "snapshot_digest"), AuthorityPhase.COMMITTED),
                key=key,
            )
            resumed = self._read_extension_control_authority_locked(catalog_digest)
            if resumed.health is not AuthorityHealth.PROTECTED or resumed.revision != revision:
                raise ExtensionControlAuthorityError("idempotent transition recovery failed")
            return resumed
        if current.health is AuthorityHealth.PROTECTED and current.revision == revision:
            return current
        raise ExtensionControlAuthorityError("idempotent transition state mismatch")

    def _validate_transition_chain(
        self,
        revision: int,
        *,
        current_snapshot_digest: str,
        key: bytes,
    ) -> None:
        with self._connect() as connection:
            rows = cast(
                list[sqlite3.Row],
                connection.execute("select * from extension_control_authority_transition order by revision").fetchall(),
            )
        committed = [row for row in rows if _row_str(row, "phase") == AuthorityPhase.COMMITTED.value]
        if [_row_int(row, "revision") for row in committed] != list(range(1, revision + 1)):
            raise ExtensionControlAuthorityError("extension control transition gap")
        prior_snapshot_digest: str | None = None
        for row in committed:
            row_revision = _row_int(row, "revision")
            previous_revision = _row_int(row, "previous_revision")
            if previous_revision != row_revision - 1:
                raise ExtensionControlAuthorityError("extension control transition chain mismatch")
            layers_json = _row_str(row, "layers_json")
            self._validate_serialized_layers(layers_json)
            snapshot_payload = verify_authenticated_record(
                _row_str(row, "snapshot_json"),
                expected_digest=_row_str(row, "snapshot_digest"),
                expected_mac=_row_str(row, "snapshot_mac"),
                key=key,
                purpose=SNAPSHOT_PURPOSE,
            )
            previous_digest = snapshot_payload.get("previous_digest")
            if not isinstance(previous_digest, str):
                raise ExtensionControlAuthorityError("extension control transition chain mismatch")
            if prior_snapshot_digest is not None and previous_digest != prior_snapshot_digest:
                raise ExtensionControlAuthorityError("extension control transition chain mismatch")
            snapshot_expected: dict[str, object] = {
                "revision": row_revision,
                "catalog_digest": _row_str(row, "catalog_digest"),
                "layers_json": layers_json,
                "previous_digest": previous_digest,
                "committed_at": _row_str(row, "created_at"),
            }
            if any(snapshot_payload.get(name) != value for name, value in snapshot_expected.items()):
                raise ExtensionControlAuthorityError("extension control transition snapshot mismatch")
            self._validate_layers(layers_from_json(layers_json), _row_str(row, "catalog_digest"))
            transition_payload = verify_authenticated_record(
                _row_str(row, "transition_json"),
                expected_digest=_row_str(row, "transition_digest"),
                expected_mac=_row_str(row, "transition_mac"),
                key=key,
                purpose=TRANSITION_PURPOSE,
            )
            transition_expected: dict[str, object] = {
                "revision": row_revision,
                "previous_revision": previous_revision,
                "previous_digest": previous_digest,
                "snapshot_digest": _row_str(row, "snapshot_digest"),
                "catalog_digest": _row_str(row, "catalog_digest"),
                "actor_id_hash": _row_str(row, "actor_id_hash"),
                "idempotency_key_hash": _row_str(row, "idempotency_key_hash"),
                "nonce_hash": _row_str(row, "nonce_hash"),
                "created_at": _row_str(row, "created_at"),
                "phase": AuthorityPhase.PREPARED.value,
            }
            if any(transition_payload.get(name) != value for name, value in transition_expected.items()):
                raise ExtensionControlAuthorityError("extension control transition field mismatch")
            prior_snapshot_digest = _row_str(row, "snapshot_digest")
        if prior_snapshot_digest is not None and prior_snapshot_digest != current_snapshot_digest:
            raise ExtensionControlAuthorityError("extension control transition head mismatch")

    def _commit_pending_transition(self, connection: sqlite3.Connection, row: sqlite3.Row) -> None:
        self._validate_serialized_layers(_row_str(row, "layers_json"))
        _ = connection.execute(
            """
            update extension_control_authority_snapshot
            set revision = ?, catalog_digest = ?, layers_json = ?, previous_digest = snapshot_digest,
                snapshot_json = ?, snapshot_digest = ?, snapshot_mac = ?, committed_at = ?
            where singleton = 1 and revision = ?
            """,
            (
                _row_int(row, "revision"),
                _row_str(row, "catalog_digest"),
                _row_str(row, "layers_json"),
                _row_str(row, "snapshot_json"),
                _row_str(row, "snapshot_digest"),
                _row_str(row, "snapshot_mac"),
                _row_str(row, "created_at"),
                _row_int(row, "previous_revision"),
            ),
        )
        _ = connection.execute(
            "update extension_control_authority_transition set phase = ?, committed_at = ? where revision = ?",
            (AuthorityPhase.COMMITTED.value, _now(), _row_int(row, "revision")),
        )

    def _pending_transition(self, revision: int) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                "select * from extension_control_authority_transition where revision = ?",
                (revision,),
            ).fetchone()
