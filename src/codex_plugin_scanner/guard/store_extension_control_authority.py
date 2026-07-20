"""Crash-safe, externally anchored extension-control authority persistence."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .runtime.extension_control_authority import (
    SNAPSHOT_PURPOSE,
    TRANSITION_PURPOSE,
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    anchor_from_json,
    anchor_to_json,
    authenticated_record,
    layers_from_json,
    layers_to_json,
    verify_authenticated_record,
)
from .runtime.extension_control_contract import (
    ControlLayerKind,
    ExtensionControlLayer,
)
from .runtime.extension_control_resolver import compose_control_layers
from .store_base import SecretStore, SystemKeyringSecretStore
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema

_KEY_REF_SUFFIX = ":authentication-key"
_ANCHOR_REF_SUFFIX = ":anchor"


class StoreExtensionControlAuthorityMixin:
    """GuardStore mixin for the local extension-control authority."""

    _extension_control_authority_secret_store: SecretStore | None = None
    _extension_control_degraded_acknowledged: bool = False
    _extension_control_last_catalog_digest: str = "0" * 64

    def read_extension_control_authority(self, *, catalog_digest: str) -> ExtensionControlAuthorityView:
        self._extension_control_last_catalog_digest = catalog_digest
        try:
            with self._extension_control_authority_lock():
                return self._read_extension_control_authority_locked(catalog_digest, bootstrap=True)
        except ExtensionControlAuthorityError:
            raise
        except Exception:
            return self._degraded_view(catalog_digest)

    def commit_extension_control_layers(
        self,
        layers: tuple[ExtensionControlLayer, ...],
        *,
        catalog_digest: str,
        actor_id: str,
        expected_revision: int,
        idempotency_key: str,
        nonce: str,
    ) -> ExtensionControlAuthorityView:
        self._validate_commit_input(
            layers,
            catalog_digest=catalog_digest,
            actor_id=actor_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            nonce=nonce,
        )
        with self._extension_control_authority_lock():
            current = self._read_extension_control_authority_locked(catalog_digest, bootstrap=True)
            if current.health is not AuthorityHealth.PROTECTED:
                raise ExtensionControlAuthorityError("extension control authority unavailable")
            key = self._authority_key(required=True)
            assert key is not None
            idempotency_hash = _private_hash(idempotency_key)
            nonce_hash = _private_hash(nonce)
            with self._connect() as connection:
                replay = connection.execute(
                    "select revision from extension_control_authority_transition where idempotency_key_hash = ?",
                    (idempotency_hash,),
                ).fetchone()
                if replay is not None:
                    return current
                if current.revision != expected_revision:
                    raise ExtensionControlAuthorityError("extension control authority revision conflict")
                if (
                    connection.execute(
                        "select 1 from extension_control_authority_transition where nonce_hash = ?",
                        (nonce_hash,),
                    ).fetchone()
                    is not None
                ):
                    raise ExtensionControlAuthorityError("extension control authority nonce replay")
                snapshot_row = connection.execute(
                    "select snapshot_digest from extension_control_authority_snapshot where singleton = 1"
                ).fetchone()
                if snapshot_row is None:
                    raise ExtensionControlAuthorityError("extension control authority snapshot missing")
                previous_digest = str(snapshot_row["snapshot_digest"])

            revision = current.revision + 1
            created_at = _now()
            layers_json = layers_to_json(layers)
            snapshot_json, snapshot_digest, snapshot_mac = authenticated_record(
                {
                    "revision": revision,
                    "catalog_digest": catalog_digest,
                    "layers_json": layers_json,
                    "previous_digest": previous_digest,
                    "committed_at": created_at,
                },
                key=key,
                purpose=SNAPSHOT_PURPOSE,
            )
            transition_json, transition_digest, transition_mac = authenticated_record(
                {
                    "revision": revision,
                    "previous_revision": current.revision,
                    "previous_digest": previous_digest,
                    "snapshot_digest": snapshot_digest,
                    "catalog_digest": catalog_digest,
                    "actor_id_hash": _private_hash(actor_id),
                    "idempotency_key_hash": idempotency_hash,
                    "nonce_hash": nonce_hash,
                    "created_at": created_at,
                    "phase": AuthorityPhase.PREPARED.value,
                },
                key=key,
                purpose=TRANSITION_PURPOSE,
            )
            with self._connect() as connection:
                ensure_extension_control_authority_schema(connection)
                connection.execute(
                    """
                    insert into extension_control_authority_transition (
                        revision, previous_revision, phase, actor_id_hash, idempotency_key_hash,
                        nonce_hash, catalog_digest, layers_json, snapshot_json, snapshot_digest,
                        snapshot_mac, transition_json, transition_digest, transition_mac, created_at
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        revision,
                        current.revision,
                        AuthorityPhase.PREPARED.value,
                        _private_hash(actor_id),
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
                    ),
                )
            anchored = AuthorityAnchor(revision, snapshot_digest, AuthorityPhase.ANCHORED)
            try:
                self._write_and_verify_anchor(anchored, key=key)
            except Exception as exc:
                raise ExtensionControlAuthorityError("extension control authority anchor unavailable") from exc
            with self._connect() as connection:
                connection.execute(
                    "update extension_control_authority_transition set phase = ? where revision = ?",
                    (AuthorityPhase.ANCHORED.value, revision),
                )
                connection.execute(
                    """
                    update extension_control_authority_snapshot
                    set revision = ?, catalog_digest = ?, layers_json = ?, previous_digest = ?,
                        snapshot_json = ?, snapshot_digest = ?, snapshot_mac = ?, committed_at = ?
                    where singleton = 1 and revision = ? and snapshot_digest = ?
                    """,
                    (
                        revision,
                        catalog_digest,
                        layers_json,
                        previous_digest,
                        snapshot_json,
                        snapshot_digest,
                        snapshot_mac,
                        created_at,
                        current.revision,
                        previous_digest,
                    ),
                )
                if connection.execute("select changes()").fetchone()[0] != 1:
                    raise ExtensionControlAuthorityError("extension control authority concurrent update")
                connection.execute(
                    "update extension_control_authority_transition set phase = ?, committed_at = ? where revision = ?",
                    (AuthorityPhase.COMMITTED.value, created_at, revision),
                )
            try:
                self._write_and_verify_anchor(
                    AuthorityAnchor(revision, snapshot_digest, AuthorityPhase.COMMITTED),
                    key=key,
                )
            except Exception as exc:
                raise ExtensionControlAuthorityError("extension control authority final anchor unavailable") from exc
            return self._read_extension_control_authority_locked(catalog_digest, bootstrap=False)

    def recover_extension_control_authority(self, *, catalog_digest: str) -> ExtensionControlAuthorityView:
        with self._extension_control_authority_lock():
            key = self._authority_key(required=True)
            if key is None:
                return self._degraded_view(catalog_digest)
            anchor = self._read_anchor(key=key)
            with self._connect() as connection:
                ensure_extension_control_authority_schema(connection)
                snapshot = connection.execute(
                    "select revision, snapshot_digest from extension_control_authority_snapshot where singleton = 1"
                ).fetchone()
                if snapshot is None or anchor is None:
                    return self._tampered_view(catalog_digest)
                current_revision = int(snapshot["revision"])
                current_digest = str(snapshot["snapshot_digest"])
                pending = connection.execute(
                    "select * from extension_control_authority_transition where revision = ?",
                    (current_revision + 1,),
                ).fetchone()
                if anchor.revision == current_revision and anchor.snapshot_digest == current_digest:
                    if pending is not None and str(pending["phase"]) == AuthorityPhase.PREPARED.value:
                        connection.execute(
                            "delete from extension_control_authority_transition where revision = ?",
                            (current_revision + 1,),
                        )
                    if anchor.phase is not AuthorityPhase.COMMITTED:
                        self._write_and_verify_anchor(
                            AuthorityAnchor(current_revision, current_digest, AuthorityPhase.COMMITTED),
                            key=key,
                        )
                    return self._read_extension_control_authority_locked(catalog_digest, bootstrap=False)
                if (
                    pending is not None
                    and anchor.phase is AuthorityPhase.ANCHORED
                    and anchor.revision == current_revision + 1
                    and anchor.snapshot_digest == str(pending["snapshot_digest"])
                ):
                    self._commit_pending_transition(connection, pending)
                    self._write_and_verify_anchor(
                        AuthorityAnchor(anchor.revision, anchor.snapshot_digest, AuthorityPhase.COMMITTED),
                        key=key,
                    )
                    return self._read_extension_control_authority_locked(catalog_digest, bootstrap=False)
            return self._tampered_view(catalog_digest)

    def acknowledge_extension_control_degraded_mode(self) -> ExtensionControlAuthorityView:
        self._extension_control_degraded_acknowledged = True
        return self._degraded_view(self._extension_control_last_catalog_digest)

    def _read_extension_control_authority_locked(
        self, catalog_digest: str, *, bootstrap: bool
    ) -> ExtensionControlAuthorityView:
        with self._connect() as connection:
            ensure_extension_control_authority_schema(connection)
            row = connection.execute(
                "select * from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
        try:
            key = self._authority_key(required=False)
            anchor = self._read_anchor(key=key) if key is not None else None
        except Exception:
            return self._degraded_view(catalog_digest)
        if row is None and anchor is None and bootstrap:
            return self._bootstrap_extension_control_authority(catalog_digest, key=key)
        if row is None or key is None or anchor is None:
            return self._tampered_view(catalog_digest)
        try:
            revision = int(row["revision"])
            if str(row["catalog_digest"]) != catalog_digest:
                raise ExtensionControlAuthorityError("extension control catalog digest mismatch")
            payload = verify_authenticated_record(
                str(row["snapshot_json"]),
                expected_digest=str(row["snapshot_digest"]),
                expected_mac=str(row["snapshot_mac"]),
                key=key,
                purpose=SNAPSHOT_PURPOSE,
            )
            expected = {
                "revision": revision,
                "catalog_digest": str(row["catalog_digest"]),
                "layers_json": str(row["layers_json"]),
                "previous_digest": row["previous_digest"],
                "committed_at": str(row["committed_at"]),
            }
            if any(payload.get(name) != value for name, value in expected.items()):
                raise ExtensionControlAuthorityError("extension control snapshot field mismatch")
            layers = layers_from_json(str(row["layers_json"]))
            self._validate_layers(layers, catalog_digest)
            if anchor.revision != revision or anchor.snapshot_digest != str(row["snapshot_digest"]):
                pending = self._pending_transition(revision + 1)
                if not (
                    pending is not None
                    and anchor.phase is AuthorityPhase.ANCHORED
                    and anchor.revision == revision + 1
                    and anchor.snapshot_digest == _row_str(pending, "snapshot_digest")
                ):
                    raise ExtensionControlAuthorityError("extension control authority rollback detected")
                return ExtensionControlAuthorityView(AuthorityHealth.RECOVERY_REQUIRED, revision, catalog_digest, ())
            if anchor.phase is not AuthorityPhase.COMMITTED:
                return ExtensionControlAuthorityView(AuthorityHealth.RECOVERY_REQUIRED, revision, catalog_digest, ())
            self._validate_transition_chain(revision, key=key)
            return ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, revision, catalog_digest, layers)
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)

    def _bootstrap_extension_control_authority(
        self, catalog_digest: str, *, key: bytes | None
    ) -> ExtensionControlAuthorityView:
        if key is None:
            key = secrets.token_bytes(32)
            self._secret_store().set_secret(self._key_ref(), base64.urlsafe_b64encode(key).decode())
        committed_at = _now()
        layers_json = layers_to_json(())
        snapshot_json, digest, mac = authenticated_record(
            {
                "revision": 0,
                "catalog_digest": catalog_digest,
                "layers_json": layers_json,
                "previous_digest": None,
                "committed_at": committed_at,
            },
            key=key,
            purpose=SNAPSHOT_PURPOSE,
        )
        with self._connect() as connection:
            existing = connection.execute(
                "select 1 from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
            if existing is not None:
                raise ExtensionControlAuthorityError("extension control authority already exists")
            connection.execute(
                """
                insert into extension_control_authority_snapshot (
                    singleton, revision, catalog_digest, layers_json, previous_digest,
                    snapshot_json, snapshot_digest, snapshot_mac, committed_at
                ) values (1, 0, ?, ?, null, ?, ?, ?, ?)
                """,
                (catalog_digest, layers_json, snapshot_json, digest, mac, committed_at),
            )
        self._write_and_verify_anchor(AuthorityAnchor(0, digest, AuthorityPhase.COMMITTED), key=key)
        return ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 0, catalog_digest, ())

    def _validate_transition_chain(self, revision: int, *, key: bytes) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                "select * from extension_control_authority_transition order by revision"
            ).fetchall()
        committed = [row for row in rows if str(row["phase"]) == AuthorityPhase.COMMITTED.value]
        if [int(row["revision"]) for row in committed] != list(range(1, revision + 1)):
            raise ExtensionControlAuthorityError("extension control transition gap")
        for row in committed:
            payload = verify_authenticated_record(
                str(row["transition_json"]),
                expected_digest=str(row["transition_digest"]),
                expected_mac=str(row["transition_mac"]),
                key=key,
                purpose=TRANSITION_PURPOSE,
            )
            expected = {
                "revision": int(row["revision"]),
                "previous_revision": int(row["previous_revision"]),
                "snapshot_digest": str(row["snapshot_digest"]),
                "catalog_digest": str(row["catalog_digest"]),
                "actor_id_hash": str(row["actor_id_hash"]),
                "idempotency_key_hash": str(row["idempotency_key_hash"]),
                "nonce_hash": str(row["nonce_hash"]),
                "created_at": str(row["created_at"]),
                "phase": AuthorityPhase.PREPARED.value,
            }
            if any(payload.get(name) != value for name, value in expected.items()):
                raise ExtensionControlAuthorityError("extension control transition field mismatch")

    def _commit_pending_transition(self, connection: sqlite3.Connection, row: sqlite3.Row) -> None:
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

    def _authority_key(self, *, required: bool) -> bytes | None:
        try:
            value = self._secret_store().get_secret(self._key_ref())
        except Exception as exc:
            if required:
                raise ExtensionControlAuthorityError("extension control credential store unavailable") from exc
            raise
        if value is None:
            if required:
                raise ExtensionControlAuthorityError("extension control authentication key missing")
            return None
        try:
            key = base64.urlsafe_b64decode(value.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ExtensionControlAuthorityError("invalid extension control authentication key") from exc
        if len(key) != 32:
            raise ExtensionControlAuthorityError("invalid extension control authentication key")
        return key

    def _read_anchor(self, *, key: bytes) -> AuthorityAnchor | None:
        value = self._secret_store().get_secret(self._anchor_ref())
        return None if value is None else anchor_from_json(value, key=key)

    def _write_and_verify_anchor(self, anchor: AuthorityAnchor, *, key: bytes) -> None:
        encoded = anchor_to_json(anchor, key=key)
        self._secret_store().set_secret(self._anchor_ref(), encoded)
        observed = self._secret_store().get_secret(self._anchor_ref())
        if observed != encoded:
            raise ExtensionControlAuthorityError("extension control anchor read-back mismatch")

    def _secret_store(self) -> SecretStore:
        current = self._extension_control_authority_secret_store
        if current is None:
            current = SystemKeyringSecretStore(service_name="hol-guard.extension-control-authority")
            self._extension_control_authority_secret_store = current
        if isinstance(current, SystemKeyringSecretStore) and not current._is_available():
            raise RuntimeError("extension control credential store unavailable")
        return current

    def _authority_ref_prefix(self) -> str:
        home = str(cast(Path, self.guard_home).resolve())
        return "extension-control:" + hashlib.sha256(home.encode("utf-8")).hexdigest()[:20]

    def _key_ref(self) -> str:
        return self._authority_ref_prefix() + _KEY_REF_SUFFIX

    def _anchor_ref(self) -> str:
        return self._authority_ref_prefix() + _ANCHOR_REF_SUFFIX

    @contextmanager
    def _extension_control_authority_lock(self) -> Generator[None, None, None]:
        with self._hold_advisory_file_lock(
            path=cast(Path, self.guard_home) / "extension-control-authority.lock",
            timeout_seconds=30.0,
            poll_seconds=0.05,
            timeout_message="Timed out waiting for the extension control authority lock.",
        ):
            yield

    @staticmethod
    def _validate_layers(layers: tuple[ExtensionControlLayer, ...], catalog_digest: str) -> None:
        if any(layer.catalog_digest != catalog_digest for layer in layers):
            raise ExtensionControlAuthorityError("extension control catalog digest mismatch")
        composed = compose_control_layers(layers)
        if composed.failures:
            raise ExtensionControlAuthorityError("invalid extension control layers")
        if len({layer.kind for layer in layers}) != len(layers):
            raise ExtensionControlAuthorityError("duplicate extension control layer")
        if any(layer.kind not in {ControlLayerKind.LOCAL_ADMIN, ControlLayerKind.SIGNED_CLOUD} for layer in layers):
            raise ExtensionControlAuthorityError("invalid extension control layer kind")

    @classmethod
    def _validate_commit_input(
        cls,
        layers: tuple[ExtensionControlLayer, ...],
        *,
        catalog_digest: str,
        actor_id: str,
        expected_revision: int,
        idempotency_key: str,
        nonce: str,
    ) -> None:
        cls._validate_layers(layers, catalog_digest)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ExtensionControlAuthorityError("invalid expected authority revision")
        if not actor_id.strip() or not idempotency_key.strip() or not nonce.strip():
            raise ExtensionControlAuthorityError("invalid extension control transition identity")

    def _degraded_view(self, catalog_digest: str) -> ExtensionControlAuthorityView:
        health = (
            AuthorityHealth.DEGRADED_ACKNOWLEDGED
            if self._extension_control_degraded_acknowledged
            else AuthorityHealth.DEGRADED_UNACKNOWLEDGED
        )
        return ExtensionControlAuthorityView(health, 0, catalog_digest, ())

    @staticmethod
    def _tampered_view(catalog_digest: str) -> ExtensionControlAuthorityView:
        return ExtensionControlAuthorityView(AuthorityHealth.TAMPERED, 0, catalog_digest, ())


def _row_str(row: sqlite3.Row, name: str) -> str:
    value = cast(object, row[name])
    if not isinstance(value, str):
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _row_int(row: sqlite3.Row, name: str) -> int:
    value = cast(object, row[name])
    if type(value) is not int:
        raise ExtensionControlAuthorityError("invalid extension control authority row")
    return value


def _private_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
