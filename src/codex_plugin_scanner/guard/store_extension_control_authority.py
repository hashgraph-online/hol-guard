"""Crash-safe, externally anchored extension-control authority persistence."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import base64
import secrets

from .runtime.extension_control_authority import (
    SNAPSHOT_PURPOSE,
    TRANSITION_PURPOSE,
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    authenticated_record,
    layers_from_json,
    layers_to_json,
    verify_authenticated_record,
)
from .runtime.extension_control_contract import ExtensionControlLayer
from .runtime.extension_control_proof import (
    ExtensionControlMutation,
    ExtensionControlProof,
    consume_extension_control_proof,
    validate_extension_control_proof,
)
from .store_base import SecretStore
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_extension_control_authority_support import (
    _now,
    _private_hash,
    _row_int,
    _row_str,
)
from .store_extension_control_authority_transitions import _ExtensionControlAuthorityTransitionMixin


class StoreExtensionControlAuthorityMixin(_ExtensionControlAuthorityTransitionMixin):
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
        proof: ExtensionControlProof,
    ) -> ExtensionControlAuthorityView:
        self._validate_commit_input(
            layers,
            catalog_digest=catalog_digest,
            actor_id=actor_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            nonce=nonce,
        )
        mutation = ExtensionControlMutation(
            previous_revision=expected_revision,
            catalog_digest=catalog_digest,
            layers=layers,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
        )
        validate_extension_control_proof(proof, mutation)
        layers_json = layers_to_json(layers)
        self._validate_serialized_layers(layers_json)
        with self._extension_control_authority_lock():
            current = self._read_extension_control_authority_locked(catalog_digest, bootstrap=True)
            key = self._authority_key(required=True)
            assert key is not None
            actor_hash = _private_hash(actor_id, key=key, purpose="actor")
            idempotency_hash = _private_hash(idempotency_key, key=key, purpose="idempotency")
            nonce_hash = _private_hash(nonce, key=key, purpose="nonce")
            proof_hash = _private_hash(proof.proof_id, key=key, purpose="proof")
            proof_already_consumed = False
            with self._connect() as connection:
                ensure_extension_control_authority_schema(connection)
                proof_record = connection.execute(
                    "select * from extension_control_authority_proof where proof_id_hash = ?",
                    (proof_hash,),
                ).fetchone()
                replay = connection.execute(
                    "select * from extension_control_authority_transition where idempotency_key_hash = ?",
                    (idempotency_hash,),
                ).fetchone()
                if proof_record is not None and (
                    replay is None or AuthorityPhase(str(replay["phase"])) is AuthorityPhase.COMMITTED
                ):
                    raise ExtensionControlAuthorityError("extension control authority proof replay")
                if (
                    proof_record is not None
                    and replay is not None
                    and (
                        str(proof_record["mutation_digest"]) != mutation.canonical_digest
                        or int(proof_record["transition_revision"]) != _row_int(replay, "revision")
                    )
                ):
                    raise ExtensionControlAuthorityError("extension control authority proof state conflict")
                if replay is not None:
                    resumed = self._resume_idempotent_transition(
                        connection,
                        replay,
                        current=current,
                        catalog_digest=catalog_digest,
                        layers_json=layers_json,
                        actor_hash=actor_hash,
                        idempotency_hash=idempotency_hash,
                        nonce_hash=nonce_hash,
                        expected_revision=expected_revision,
                        key=key,
                    )
                    if resumed is not None:
                        consumed_at = _now()
                        if proof_record is None:
                            consume_extension_control_proof(self.guard_home, proof, mutation)
                            connection.execute(
                                """
                                insert into extension_control_authority_proof (
                                    proof_id_hash, mutation_digest, transition_revision,
                                    reserved_at, consumed_at
                                ) values (?, ?, ?, ?, ?)
                                """,
                                (
                                    proof_hash,
                                    mutation.canonical_digest,
                                    _row_int(replay, "revision"),
                                    consumed_at,
                                    consumed_at,
                                ),
                            )
                        else:
                            connection.execute(
                                """
                                update extension_control_authority_proof
                                set consumed_at = coalesce(consumed_at, ?)
                                where proof_id_hash = ?
                                """,
                                (consumed_at, proof_hash),
                            )
                        return resumed
                    connection.commit()
                    if proof_record is not None:
                        connection.execute(
                            "delete from extension_control_authority_proof where proof_id_hash = ?",
                            (proof_hash,),
                        )
                        proof_already_consumed = True
                    current = self._read_extension_control_authority_locked(catalog_digest, bootstrap=False)
            if current.health is not AuthorityHealth.PROTECTED:
                raise ExtensionControlAuthorityError("extension control authority unavailable")
            with self._connect() as connection:
                ensure_extension_control_authority_schema(connection)
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
                if (
                    connection.execute(
                        "select 1 from extension_control_authority_proof where proof_id_hash = ?",
                        (proof_hash,),
                    ).fetchone()
                    is not None
                ):
                    raise ExtensionControlAuthorityError("extension control authority proof replay")
                snapshot_row = connection.execute(
                    "select snapshot_digest from extension_control_authority_snapshot where singleton = 1"
                ).fetchone()
                if snapshot_row is None:
                    raise ExtensionControlAuthorityError("extension control authority snapshot missing")
                previous_digest = str(snapshot_row["snapshot_digest"])

            revision = current.revision + 1
            created_at = _now()
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
                    "actor_id_hash": actor_hash,
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
                    insert into extension_control_authority_proof (
                        proof_id_hash, mutation_digest, transition_revision, reserved_at
                    ) values (?, ?, ?, ?)
                    """,
                    (proof_hash, mutation.canonical_digest, revision, created_at),
                )
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
                    ),
                )
            if not proof_already_consumed:
                consume_extension_control_proof(self.guard_home, proof, mutation)
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
                    """
                    update extension_control_authority_proof
                    set consumed_at = ?
                    where proof_id_hash = ? and transition_revision = ? and consumed_at is null
                    """,
                    (created_at, proof_hash, revision),
                )
                if connection.execute("select changes()").fetchone()[0] != 1:
                    raise ExtensionControlAuthorityError("extension control authority proof state conflict")
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
                current_revision = _row_int(snapshot, "revision")
                current_digest = _row_str(snapshot, "snapshot_digest")
                pending = connection.execute(
                    """
                    select * from extension_control_authority_transition
                    where (revision = ? and phase != ?) or revision = ?
                    order by revision
                    limit 1
                    """,
                    (
                        current_revision,
                        AuthorityPhase.COMMITTED.value,
                        current_revision + 1,
                    ),
                ).fetchone()
                if pending is not None:
                    resumed = self._resume_idempotent_transition(
                        connection,
                        pending,
                        current=ExtensionControlAuthorityView(
                            AuthorityHealth.RECOVERY_REQUIRED,
                            current_revision,
                            catalog_digest,
                            (),
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
                        return resumed
                    connection.commit()
                if anchor.revision == current_revision and anchor.snapshot_digest == current_digest:
                    if anchor.phase is not AuthorityPhase.COMMITTED:
                        self._write_and_verify_anchor(
                            AuthorityAnchor(
                                current_revision,
                                current_digest,
                                AuthorityPhase.COMMITTED,
                            ),
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
        if row is None and anchor is None and key is None and bootstrap:
            return self._bootstrap_extension_control_authority(catalog_digest, key=None)
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
            self._validate_serialized_layers(str(row["layers_json"]))
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
            if self._pending_transition(revision + 1) is not None:
                return ExtensionControlAuthorityView(
                    AuthorityHealth.RECOVERY_REQUIRED,
                    revision,
                    catalog_digest,
                    (),
                )
            if anchor.phase is not AuthorityPhase.COMMITTED:
                return ExtensionControlAuthorityView(AuthorityHealth.RECOVERY_REQUIRED, revision, catalog_digest, ())
            self._validate_transition_chain(
                revision,
                current_snapshot_digest=_row_str(row, "snapshot_digest"),
                key=key,
            )
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
