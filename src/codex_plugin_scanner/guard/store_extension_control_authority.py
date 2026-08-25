"""Crash-safe, externally anchored extension-control authority persistence."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import is_dataclass, replace
from enum import Enum
from typing import cast

from .managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
    managed_controls_layers_from_activation_state,
    managed_controls_revision_from_state,
)
from .runtime.command_extensions import CommandSafetyExtensionRegistry
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
from .runtime.extension_control_contract import ControlLayerKind, ExtensionControl, ExtensionControlLayer
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
from .store_base import SecretStore
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_extension_control_authority_support import (
    _now,
    _private_hash,
    _row_int,
    _row_str,
    preserve_migrated_extension_control,
)
from .store_extension_control_authority_transitions import _ExtensionControlAuthorityTransitionMixin


def _canonical_contract_value(value: object) -> object:
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        dataclass_fields = cast(Mapping[str, object], value.__dataclass_fields__)
        return {
            "type": type(value).__qualname__,
            "fields": {
                field_name: _canonical_contract_value(getattr(value, field_name)) for field_name in dataclass_fields
            },
        }
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_contract_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        normalized = [_canonical_contract_value(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    if isinstance(value, (tuple, list)):
        return [_canonical_contract_value(item) for item in value]
    raise ExtensionControlAuthorityError(f"unsupported catalog contract value: {type(value).__qualname__}")


class StoreExtensionControlAuthorityMixin(_ExtensionControlAuthorityTransitionMixin):
    """GuardStore mixin for the local extension-control authority."""

    _extension_control_authority_secret_store: SecretStore | None = None
    _extension_control_degraded_acknowledged: bool = False
    _extension_control_last_catalog_digest: str = "0" * 64
    _catalog_manifest_purpose = "hol-guard.extension-control-catalog-manifest.v1"

    def read_extension_control_authority(self, *, catalog_digest: str) -> ExtensionControlAuthorityView:
        self._extension_control_last_catalog_digest = catalog_digest
        try:
            with self._extension_control_authority_lock():
                return self._read_extension_control_authority_locked(catalog_digest)
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)
        except Exception:
            return self._degraded_view(catalog_digest)

    def read_extension_control_authority_for_registry(
        self,
        registry: CommandSafetyExtensionRegistry,
    ) -> ExtensionControlAuthorityView:
        catalog_digest = registry.catalog_digest
        self._extension_control_last_catalog_digest = catalog_digest
        try:
            with self._extension_control_authority_lock():
                view = self._read_extension_control_authority_locked(
                    catalog_digest,
                    migration_registry=registry,
                )
                if view.health is AuthorityHealth.PROTECTED:
                    key = self._authority_key(required=True)
                    assert key is not None
                    self._record_catalog_manifest(registry, key=key)
                return self._with_managed_controls_activation(view)
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)
        except Exception:
            return self._degraded_view(catalog_digest)

    def _with_managed_controls_activation(
        self,
        view: ExtensionControlAuthorityView,
    ) -> ExtensionControlAuthorityView:
        with self._connect() as connection:
            rows = connection.execute(
                "select state_key, payload_json from sync_state where state_key in (?, ?)",
                (
                    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
                    MANAGED_CONTROLS_REVISION_STATE_KEY,
                ),
            ).fetchall()
        managed_state: dict[str, object] = {}
        for row in rows:
            try:
                managed_state[str(row["state_key"])] = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError as exc:
                raise ExtensionControlAuthorityError("invalid managed controls state") from exc
        active = managed_state.get(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
        revision_state = managed_state.get(MANAGED_CONTROLS_REVISION_STATE_KEY)
        if active is None or active == {}:
            if revision_state is None or revision_state == {}:
                return view
            key = self._authority_key(required=True)
            assert key is not None
            managed_revision = managed_controls_revision_from_state(
                revision_state,
                authority_key=key,
            )
            local_layers = tuple(layer for layer in view.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
            return ExtensionControlAuthorityView(
                view.health,
                view.revision,
                view.catalog_digest,
                local_layers,
                managed_revision,
            )
        if view.health is not AuthorityHealth.PROTECTED:
            raise ExtensionControlAuthorityError("managed controls require protected local authority")
        if revision_state is None or revision_state == {}:
            raise ExtensionControlAuthorityError("managed controls revision state is missing")
        key = self._authority_key(required=True)
        assert key is not None
        managed_layers, managed_revision = managed_controls_layers_from_activation_state(
            active,
            catalog_digest=view.catalog_digest,
            authority_key=key,
        )
        durable_revision = managed_controls_revision_from_state(
            revision_state,
            authority_key=key,
        )
        if managed_revision != durable_revision:
            raise ExtensionControlAuthorityError("managed controls activation revision mismatch")
        local_layers = tuple(layer for layer in view.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
        composed = ExtensionControlAuthorityView(
            view.health,
            view.revision,
            view.catalog_digest,
            (*local_layers, *managed_layers),
            managed_revision,
        )
        return composed

    def managed_controls_lkg_capabilities(
        self,
        policy_bundle: dict[str, object],
    ) -> frozenset[str]:
        """Return negotiation bound to the exact authenticated managed LKG."""

        state = self.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY)
        if not isinstance(state, dict):
            return frozenset()
        if state.get("bundleHash") != policy_bundle.get("bundleHash") or state.get(
            "bundleVersion"
        ) != policy_bundle.get("bundleVersion"):
            return frozenset()
        key = self._authority_key(required=False)
        if key is None:
            return frozenset()
        try:
            managed_controls_layers_from_activation_state(
                state,
                catalog_digest=str(state.get("catalogDigest", "")),
                authority_key=key,
            )
        except ExtensionControlAuthorityError:
            return frozenset()
        raw = state.get("negotiatedCapabilities")
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            return frozenset()
        return frozenset(cast(list[str], raw))

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

    def recover_extension_control_authority(
        self,
        *,
        catalog_digest: str,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
    ) -> ExtensionControlAuthorityView:
        with self._extension_control_authority_lock():
            key = self._authority_key(required=False)
            if key is None:
                return self._reset_extension_control_authority(
                    catalog_digest, key=None, reason="authentication-key-missing"
                )
            anchor = self._read_anchor(key=key)
            with self._connect() as connection:
                ensure_extension_control_authority_schema(connection)
                snapshot = connection.execute(
                    "select revision, snapshot_digest from extension_control_authority_snapshot where singleton = 1"
                ).fetchone()
                if snapshot is None or anchor is None:
                    return self._reset_extension_control_authority(
                        catalog_digest,
                        key=key,
                        reason="snapshot-or-anchor-missing",
                    )
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
                    if resumed is not None and resumed.health is AuthorityHealth.PROTECTED:
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
                    if current_revision > 0:
                        committed = connection.execute(
                            """select previous_revision, layers_json, created_at
                               from extension_control_authority_transition where revision = ? and phase = ?""",
                            (current_revision, AuthorityPhase.COMMITTED.value),
                        ).fetchone()
                        if committed is None:
                            return self._reset_extension_control_authority(
                                catalog_digest,
                                key=key,
                                reason="committed-transition-missing",
                            )
                        self._queue_extension_control_change_event(
                            connection,
                            revision=current_revision,
                            previous_revision=_row_int(committed, "previous_revision"),
                            layers_json=_row_str(committed, "layers_json"),
                            occurred_at=_row_str(committed, "created_at"),
                        )
                    recovered = self._read_extension_control_authority_locked(
                        catalog_digest,
                        migration_registry=migration_registry,
                    )
                    if recovered.health is AuthorityHealth.PROTECTED:
                        return recovered
            return self._reset_extension_control_authority(
                catalog_digest,
                key=key,
                reason="authenticated-recovery-unverifiable",
            )

    def _reset_extension_control_authority(
        self,
        catalog_digest: str,
        *,
        key: bytes | None,
        reason: str,
    ) -> ExtensionControlAuthorityView:
        # Authenticated recovery must not import rows whose chain cannot be
        # verified. Re-establish an empty, protected local authority instead.
        reset_at = _now()
        with self._connect() as connection:
            ensure_extension_control_authority_schema(connection)
            snapshot = connection.execute(
                "select * from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
            transitions = connection.execute(
                "select * from extension_control_authority_transition order by revision"
            ).fetchall()
            proofs = connection.execute(
                "select * from extension_control_authority_proof order by transition_revision, proof_id_hash"
            ).fetchall()
            snapshot_payload = dict(snapshot) if snapshot is not None else None
            transition_payload = [dict(row) for row in transitions]
            proof_payload = [dict(row) for row in proofs]
            previous_snapshot_digest = (
                str(snapshot_payload["snapshot_digest"]) if snapshot_payload is not None else "missing"
            )
            archive_id = hashlib.sha256(f"{reset_at}\0{reason}\0{previous_snapshot_digest}".encode()).hexdigest()
            provenance = {
                "reason": reason,
                "archive_id": archive_id,
                "previous_revision": int(snapshot_payload["revision"]) if snapshot_payload is not None else None,
                "previous_catalog_digest": (
                    str(snapshot_payload["catalog_digest"]) if snapshot_payload is not None else None
                ),
                "previous_snapshot_digest": (
                    str(snapshot_payload["snapshot_digest"]) if snapshot_payload is not None else None
                ),
                "previous_layers_bytes": (
                    len(str(snapshot_payload["layers_json"]).encode("utf-8")) if snapshot_payload is not None else 0
                ),
                "previous_transition_count": len(transition_payload),
                "catalog_digest": catalog_digest,
            }
            connection.execute(
                """
                insert into extension_control_authority_recovery_archive (
                    archive_id, reason, archived_at, previous_revision, previous_catalog_digest,
                    snapshot_row_json, transition_rows_json, proof_rows_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    archive_id,
                    reason,
                    reset_at,
                    provenance["previous_revision"],
                    provenance["previous_catalog_digest"],
                    json.dumps(snapshot_payload, sort_keys=True, separators=(",", ":")),
                    json.dumps(transition_payload, sort_keys=True, separators=(",", ":")),
                    json.dumps(proof_payload, sort_keys=True, separators=(",", ":")),
                ),
            )
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                (
                    "extension_control_authority_reset",
                    json.dumps(provenance, sort_keys=True, separators=(",", ":")),
                    reset_at,
                ),
            )
            connection.execute("delete from extension_control_authority_proof")
            connection.execute("delete from extension_control_authority_transition")
            connection.execute("delete from extension_control_authority_snapshot")
        return self._bootstrap_extension_control_authority(catalog_digest, key=key)

    def acknowledge_extension_control_degraded_mode(self) -> ExtensionControlAuthorityView:
        self._extension_control_degraded_acknowledged = True
        return self._degraded_view(self._extension_control_last_catalog_digest)

    def _read_extension_control_authority_locked(
        self,
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
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
        if row is None and anchor is None:
            return ExtensionControlAuthorityView(AuthorityHealth.UNENROLLED, 0, catalog_digest, ())
        if row is None or key is None or anchor is None:
            return self._tampered_view(catalog_digest)
        try:
            revision = int(row["revision"])
            stored_catalog_digest = str(row["catalog_digest"])
            if stored_catalog_digest != catalog_digest:
                if migration_registry is None or migration_registry.catalog_digest != catalog_digest:
                    raise ExtensionControlAuthorityError("extension control catalog digest changed")
                previous = self._read_extension_control_authority_locked(stored_catalog_digest)
                if previous.health is not AuthorityHealth.PROTECTED:
                    raise ExtensionControlAuthorityError("extension control catalog migration source unavailable")
                return self._migrate_extension_control_catalog(previous, registry=migration_registry, key=key)
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

    @staticmethod
    def _catalog_target_manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
        manifest: dict[str, str] = {}
        for extension in registry.extensions:
            rule_contracts = {
                rule.rule_id: {
                    "rule_version": rule.rule_version,
                    "severity": rule.severity,
                    "risk_classes": rule.risk_classes,
                    "action_classes": rule.action_classes,
                    "default_mode": rule.default_mode,
                    "matcher": _canonical_contract_value(rule.matcher),
                    "safe_variants": tuple(
                        (item.variant_id, _canonical_contract_value(item.matcher)) for item in rule.safe_variants
                    ),
                    "compatibility_fallback": rule.compatibility_fallback,
                    "family": rule.family,
                }
                for rule in extension.rules
            }
            extension_contract = {
                "extension_id": extension.extension_id,
                "required": extension.required,
                "source": extension.source,
                "aliases": extension.aliases,
                "dependencies": extension.dependencies,
                "conflicts": extension.conflicts,
                "delegated_protection": extension.delegated_protection,
                "ecosystem_ids": extension.ecosystem_ids,
                "executables": extension.executables,
                "project_markers": extension.project_markers,
                "action_classes": extension.action_classes,
                "risk_classes": extension.risk_classes,
                "rules": rule_contracts,
            }
            extension_fingerprint = hashlib.sha256(
                json.dumps(extension_contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ).hexdigest()
            manifest[f"extension:{extension.extension_id}"] = extension_fingerprint
            for permission in extension.permissions:
                permission_contract = {
                    "permission_id": permission.permission_id,
                    "extension_id": permission.extension_id,
                    "risk_tier": permission.risk_tier,
                    "baseline_floor": permission.baseline_floor,
                    "default_enabled": permission.default_enabled,
                    "configurable": permission.configurable,
                    "fixed_reason": permission.fixed_reason,
                    "typed_capabilities": permission.typed_capabilities,
                    "action_classes": permission.action_classes,
                    "rule_ids": permission.rule_ids,
                    "dependencies": permission.dependencies,
                    "conflicts": permission.conflicts,
                    "implied_permissions": permission.implied_permissions,
                    "family": permission.family,
                    "extension_required": extension.required,
                    "extension_dependencies": extension.dependencies,
                    "extension_conflicts": extension.conflicts,
                    "extension_delegated_protection": extension.delegated_protection,
                    "rules": {rule_id: rule_contracts[rule_id] for rule_id in permission.rule_ids},
                }
                manifest[f"permission:{permission.permission_id}"] = hashlib.sha256(
                    json.dumps(permission_contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
                ).hexdigest()
        return manifest

    def _record_catalog_manifest(self, registry: CommandSafetyExtensionRegistry, *, key: bytes) -> None:
        manifest_json = json.dumps(
            self._catalog_target_manifest(registry),
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._connect() as connection:
            existing = connection.execute(
                "select manifest_json from extension_control_catalog_manifest where catalog_digest = ?",
                (registry.catalog_digest,),
            ).fetchone()
            if existing is not None:
                persisted = self._load_catalog_manifest(registry.catalog_digest, key=key)
                if persisted is None or persisted != self._catalog_target_manifest(registry):
                    raise ExtensionControlAuthorityError("extension control catalog manifest conflict")
                return
            recorded_at = _now()
            record_json, record_digest, record_mac = authenticated_record(
                {
                    "catalog_digest": registry.catalog_digest,
                    "manifest_json": manifest_json,
                    "recorded_at": recorded_at,
                },
                key=key,
                purpose=self._catalog_manifest_purpose,
            )
            connection.execute(
                """
                insert into extension_control_catalog_manifest (
                    catalog_digest, manifest_json, record_json, record_digest, record_mac, recorded_at
                ) values (?, ?, ?, ?, ?, ?)
                """,
                (registry.catalog_digest, manifest_json, record_json, record_digest, record_mac, recorded_at),
            )

    def _load_catalog_manifest(self, catalog_digest: str, *, key: bytes) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select * from extension_control_catalog_manifest where catalog_digest = ?",
                (catalog_digest,),
            ).fetchone()
        if row is None:
            return None
        payload = verify_authenticated_record(
            str(row["record_json"]),
            expected_digest=str(row["record_digest"]),
            expected_mac=str(row["record_mac"]),
            key=key,
            purpose=self._catalog_manifest_purpose,
        )
        expected = {
            "catalog_digest": catalog_digest,
            "manifest_json": str(row["manifest_json"]),
            "recorded_at": str(row["recorded_at"]),
        }
        if any(payload.get(name) != expected_value for name, expected_value in expected.items()):
            raise ExtensionControlAuthorityError("extension control catalog manifest field mismatch")
        value = json.loads(str(row["manifest_json"]))
        if not isinstance(value, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()
        ):
            raise ExtensionControlAuthorityError("invalid extension control catalog manifest")
        return value

    def _migrate_extension_control_catalog(
        self,
        previous: ExtensionControlAuthorityView,
        *,
        registry: CommandSafetyExtensionRegistry,
        key: bytes,
    ) -> ExtensionControlAuthorityView:
        """Rebind authenticated controls to a trusted built-in catalog update."""

        catalog_digest = registry.catalog_digest
        previous_manifest = self._load_catalog_manifest(previous.catalog_digest, key=key) or {}
        current_manifest = self._catalog_target_manifest(registry)

        def keep(control: ExtensionControl) -> bool:
            return preserve_migrated_extension_control(
                control, previous_manifest=previous_manifest, current_manifest=current_manifest
            )

        retired_targets = tuple(
            sorted(
                control.target.target_id for layer in previous.layers for control in layer.controls if not keep(control)
            )
        )
        layers = tuple(
            replace(
                layer,
                catalog_digest=catalog_digest,
                controls=tuple(control for control in layer.controls if keep(control)),
            )
            for layer in previous.layers
        )
        self._validate_layers(layers, catalog_digest)
        layers_json = layers_to_json(layers)
        self._validate_serialized_layers(layers_json)
        with self._connect() as connection:
            snapshot = connection.execute(
                "select snapshot_digest, catalog_digest from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
        if snapshot is None or str(snapshot["catalog_digest"]) != previous.catalog_digest:
            raise ExtensionControlAuthorityError("extension control catalog migration source changed")
        previous_digest = str(snapshot["snapshot_digest"])
        revision = previous.revision + 1
        created_at = _now()
        migration_ref = f"catalog-migration:{previous.catalog_digest}:{catalog_digest}:{previous.revision}"
        actor_hash = _private_hash("trusted-catalog-migration", key=key, purpose="actor")
        idempotency_hash = _private_hash(migration_ref, key=key, purpose="idempotency")
        nonce_hash = _private_hash(migration_ref, key=key, purpose="nonce")
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
                "previous_revision": previous.revision,
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
                    previous.revision,
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
        self._write_and_verify_anchor(AuthorityAnchor(revision, snapshot_digest, AuthorityPhase.ANCHORED), key=key)
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
                    previous.revision,
                    previous_digest,
                ),
            )
            if connection.execute("select changes()").fetchone()[0] != 1:
                raise ExtensionControlAuthorityError("extension control catalog migration conflict")
            connection.execute(
                "update extension_control_authority_transition set phase = ?, committed_at = ? where revision = ?",
                (AuthorityPhase.COMMITTED.value, created_at, revision),
            )
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                (
                    "extension_control_authority_catalog_migrated",
                    json.dumps(
                        {
                            "previous_revision": previous.revision,
                            "revision": revision,
                            "previous_catalog_digest": previous.catalog_digest,
                            "catalog_digest": catalog_digest,
                            "layer_count": len(layers),
                            "control_count": sum(len(layer.controls) for layer in layers),
                            "retired_target_count": len(retired_targets),
                            "retired_target_ids": retired_targets,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    created_at,
                ),
            )
        self._write_and_verify_anchor(AuthorityAnchor(revision, snapshot_digest, AuthorityPhase.COMMITTED), key=key)
        return self._read_extension_control_authority_locked(catalog_digest)

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
