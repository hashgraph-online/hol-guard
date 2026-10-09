"""Authenticated extension-control transition validation and recovery helpers."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
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
    layers_to_json,
    verify_authenticated_record,
)
from .store_extension_control_authority_support import (
    _ExtensionControlAuthoritySupportMixin,
    _now,
    _row_int,
    _row_optional_str,
    _row_str,
)

# A request that failed after preparing its transition may be retried with the
# same single-use proof, which needs the prepared row and proof reservation to
# survive. Only transitions older than this are treated as abandoned.
ABANDONED_TRANSITION_GRACE_SECONDS = 300.0


def _prepared_row_is_stale(row: sqlite3.Row) -> bool:
    try:
        created = datetime.fromisoformat(_row_str(row, "created_at"))
    except ValueError:
        return False
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - created).total_seconds() >= ABANDONED_TRANSITION_GRACE_SECONDS


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
        self._invalidate_native_extension_control_policy()
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
            connection.commit()
            self._write_and_verify_anchor(
                AuthorityAnchor(revision, _row_str(row, "snapshot_digest"), AuthorityPhase.COMMITTED),
                key=key,
            )
            self._queue_extension_control_change_event(
                connection,
                revision=revision,
                previous_revision=previous_revision,
                layers_json=layers_json,
                occurred_at=_row_str(row, "created_at"),
            )
            connection.commit()
            resumed = self._read_extension_control_authority_locked(catalog_digest)
            if resumed.health is not AuthorityHealth.PROTECTED or resumed.revision != revision:
                raise ExtensionControlAuthorityError("idempotent transition recovery failed")
            return resumed
        if current.health is AuthorityHealth.PROTECTED and current.revision == revision:
            self._queue_extension_control_change_event(
                connection,
                revision=revision,
                previous_revision=previous_revision,
                layers_json=layers_json,
                occurred_at=_row_str(row, "created_at"),
            )
            connection.commit()
            return current
        raise ExtensionControlAuthorityError("idempotent transition state mismatch")

    def _roll_back_abandoned_transition(
        self,
        revision: int,
        *,
        snapshot_digest: str,
        anchor: AuthorityAnchor,
        key: bytes,
    ) -> bool:
        """Discard a prepared transition the vault anchor never moved past.

        A request that dies before its anchor write leaves a prepared row at
        revision + 1 while the committed anchor still pins the current
        snapshot. That row never took effect, so removing it restores the
        previous authority without applying anything. The row is authenticated
        first, and anchored or committed transitions are left for explicit
        recovery. Rows younger than the grace window are kept so the original
        request can retry with its single-use proof. Returns whether the
        abandoned row was removed.
        """

        if (
            anchor.revision != revision
            or anchor.snapshot_digest != snapshot_digest
            or anchor.phase is not AuthorityPhase.COMMITTED
        ):
            return False
        pending = self._pending_transition(revision + 1)
        if pending is None or _row_str(pending, "phase") != AuthorityPhase.PREPARED.value:
            return False
        if not _prepared_row_is_stale(pending):
            return False
        from .native_policy_snapshot_constants import NativePolicySnapshotError

        try:
            with self._connect() as connection:
                resumed = self._resume_idempotent_transition(
                    connection,
                    pending,
                    current=ExtensionControlAuthorityView(
                        AuthorityHealth.RECOVERY_REQUIRED, revision, _row_str(pending, "catalog_digest"), ()
                    ),
                    catalog_digest=_row_str(pending, "catalog_digest"),
                    layers_json=_row_str(pending, "layers_json"),
                    actor_hash=_row_str(pending, "actor_id_hash"),
                    idempotency_hash=_row_str(pending, "idempotency_key_hash"),
                    nonce_hash=_row_str(pending, "nonce_hash"),
                    expected_revision=_row_int(pending, "previous_revision"),
                    key=key,
                )
                if resumed is not None:
                    return False
                _ = connection.execute(
                    "delete from extension_control_authority_proof "
                    "where transition_revision = ? and consumed_at is null",
                    (revision + 1,),
                )
        except (ExtensionControlAuthorityError, NativePolicySnapshotError):
            # Readers holding only a shared lease cannot mutate; explicit
            # recovery remains available.
            return False
        return True

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
        committed_revisions = [_row_int(row, "revision") for row in committed]
        first_revision = committed_revisions[0] if committed_revisions else revision + 1
        if committed_revisions != list(range(first_revision, revision + 1)) or (
            revision > 0 and not committed_revisions
        ):
            raise ExtensionControlAuthorityError("extension control transition gap")
        if first_revision > 1 and not self._is_restored_baseline(committed[0], key=key):
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

    @staticmethod
    def _is_restored_baseline(row: sqlite3.Row, *, key: bytes) -> bool:
        """True when a row is the authenticated head restored from the last-good export."""

        payload = verify_authenticated_record(
            _row_str(row, "transition_json"),
            expected_digest=_row_str(row, "transition_digest"),
            expected_mac=_row_str(row, "transition_mac"),
            key=key,
            purpose=TRANSITION_PURPOSE,
        )
        return payload.get("restored_baseline") is True

    def list_extension_control_authority_history(
        self,
        *,
        catalog_digest: str,
        limit: int = 20,
    ) -> list[dict[str, object]]:
        """Return authenticated, privacy-safe prior snapshots for the current catalog."""

        if type(limit) is not int or limit < 1 or limit > 50:
            raise ExtensionControlAuthorityError("invalid extension control history limit")
        with self._extension_control_authority_lock():
            current = self._read_extension_control_authority_locked(catalog_digest)
            if current.health is not AuthorityHealth.PROTECTED:
                raise ExtensionControlAuthorityError("extension control history unavailable")
            if current.revision <= 0:
                return []
            key = self._authority_key(required=True)
            assert key is not None
            anchor = self._read_anchor(key=key)
            if anchor is None or anchor.phase is not AuthorityPhase.COMMITTED or anchor.revision != current.revision:
                raise ExtensionControlAuthorityError("extension control history anchor mismatch")
            self._validate_transition_chain(
                current.revision,
                current_snapshot_digest=anchor.snapshot_digest,
                key=key,
            )
            with self._connect() as connection:
                rows = cast(
                    list[sqlite3.Row],
                    connection.execute(
                        """
                        select * from extension_control_authority_transition
                        where phase = ? and catalog_digest = ? and revision < ?
                        order by revision desc limit ?
                        """,
                        (AuthorityPhase.COMMITTED.value, catalog_digest, current.revision, limit),
                    ).fetchall(),
                )
            history: list[dict[str, object]] = []
            for row in rows:
                layers_json = _row_str(row, "layers_json")
                self._validate_serialized_layers(layers_json)
                layers = layers_from_json(layers_json)
                self._validate_layers(layers, catalog_digest)
                occurred_at = _row_optional_str(row, "committed_at") or _row_str(row, "created_at")
                history.append(
                    {
                        "revision": _row_int(row, "revision"),
                        "previous_revision": _row_int(row, "previous_revision"),
                        "occurred_at": occurred_at,
                        "catalog_digest": catalog_digest,
                        "layers": json.loads(layers_to_json(layers)),
                    }
                )
            return history

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
