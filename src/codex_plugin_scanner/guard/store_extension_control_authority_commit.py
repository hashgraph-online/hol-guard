"""Enrollment and crash-safe commits of extension-control authority."""

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
    layers_to_json,
)
from .runtime.extension_control_contract import (
    ExtensionControlLayer,
)
from .runtime.extension_control_proof import (
    ExtensionControlEnrollment,
    ExtensionControlEnrollmentProof,
    ExtensionControlMutation,
    ExtensionControlProof,
    consume_extension_control_enrollment_proof,
    consume_extension_control_proof,
    validate_extension_control_enrollment_proof,
    validate_extension_control_proof,
)
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_extension_control_authority_support import (
    _now,
    _private_hash,
    _row_int,
)


def _canonical_contract_value(value: object) -> object:
    from .store_extension_control_authority import _canonical_contract_value as canonical

    return canonical(value)


class ExtensionControlAuthorityCommitMixin:
    def enroll_extension_control_authority(
        self,
        *,
        catalog_digest: str,
        actor_id: str,
        nonce: str,
        proof: ExtensionControlEnrollmentProof,
    ) -> ExtensionControlAuthorityView:
        enrollment = ExtensionControlEnrollment(
            catalog_digest=catalog_digest,
            actor_id=actor_id,
            nonce=nonce,
        )
        validate_extension_control_enrollment_proof(proof, enrollment)
        with self._extension_control_authority_lock():
            current = self._read_extension_control_authority_locked(catalog_digest)
            if current.health is not AuthorityHealth.UNENROLLED:
                raise ExtensionControlAuthorityError("extension control authority already enrolled")
            consume_extension_control_enrollment_proof(self.guard_home, proof, enrollment)
            return self._bootstrap_extension_control_authority(catalog_digest, key=None)

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
            self._invalidate_native_extension_control_policy()
            current = self._read_extension_control_authority_locked(catalog_digest)
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
                    current = self._read_extension_control_authority_locked(catalog_digest)
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
            with self._connect() as connection:
                self._queue_extension_control_change_event(
                    connection,
                    revision=revision,
                    previous_revision=current.revision,
                    layers_json=layers_json,
                    occurred_at=created_at,
                )
            return self._read_extension_control_authority_locked(catalog_digest)

    def _bootstrap_extension_control_authority(
        self, catalog_digest: str, *, key: bytes | None
    ) -> ExtensionControlAuthorityView:
        self._invalidate_native_extension_control_policy()
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
