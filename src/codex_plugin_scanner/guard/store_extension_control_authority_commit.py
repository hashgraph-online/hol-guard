"""Enrollment and crash-safe commits of extension-control authority."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import base64
import secrets

from .native_extension_control_authority import view_to_wire
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    layers_to_json,
)
from .runtime.extension_control_contract import (
    ControlLayerKind,
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
from .store_extension_control_authority_support import _now, _plan_int, _plan_map, _plan_pack_digest, _plan_record

# A commit re-reads at most once to roll back another request's abandoned
# transition and once after abandoning its own; the resident decides each round.
_MAX_COMMIT_ROUNDS = 4


class ExtensionControlAuthorityCommitMixin:
    def migrate_installed_command_pack_authority(self):
        """Authenticate legacy controls before admitting the installed release.

        Called at daemon installation/startup, never by preview or recovery.
        Neither controls, managed state nor saved command decisions are mutated.
        """
        from .catalog_delivery import lifecycle_store
        from .catalog_delivery.preparation_authority import load_installed_bundle

        installed = load_installed_bundle()
        if installed is None:
            # `None` means this install advertises no bundle at all (a legacy
            # or source install); a bundle that is advertised but fails
            # verification raises instead. There is nothing to admit, but the
            # floor then stays absent and every later pack-lifecycle read
            # fails, so record the absence; a silent return left no trace.
            from .daemon.background_diagnostics import record_background_event

            record_background_event("installed_authority_release_absent", "detail=installed bundle not advertised")
            return
        with self._extension_control_authority_lock(shared=True):
            retained = lifecycle_store.migration_retained(self)
        if not retained:
            with self._extension_control_authority_lock():
                with self._connect() as connection:
                    ensure_extension_control_authority_schema(connection)
                lifecycle_store.migrate_installed(self, installed)
        from .catalog_delivery.installed_upgrade import migrate_active

        migrate_active(self, installed)

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
            guard_home=self.guard_home,
        )
        validate_extension_control_enrollment_proof(proof, enrollment)
        with self._extension_control_authority_lock():
            current = self._read_extension_control_authority_locked(catalog_digest)
            if current.health is not AuthorityHealth.UNENROLLED:
                raise ExtensionControlAuthorityError("extension control authority already enrolled")
            consume_extension_control_enrollment_proof(self.guard_home, proof, enrollment)
            from .catalog_delivery import lifecycle_store
            from .catalog_delivery.preparation_authority import load_installed_bundle

            installed = load_installed_bundle()
            if installed is not None and not lifecycle_store.floor_enrolled(self):
                # Startup migration now enrolls the floor on an install that
                # carries no legacy controls, so by the time an operator
                # enrolls the authority the floor is usually already there.
                # Enrolling it a second time is refused, and that refusal
                # would fail the enrollment the operator is waiting on. A
                # floor without its stamp still goes through the refusal.
                lifecycle_store.enroll_installed(self, installed)
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
        migration_registry: CommandSafetyExtensionRegistry | None = None,
        pack_activation=None,
        expected_managed_revision: int | None = None,
        expected_managed_layers: tuple[ExtensionControlLayer, ...] | None = None,
        managed_registry: CommandSafetyExtensionRegistry | None = None,
    ) -> ExtensionControlAuthorityView:
        if pack_activation is not None:
            if migration_registry is None or migration_registry.catalog_digest != catalog_digest:
                raise ExtensionControlAuthorityError("pack activation requires its verified registry")
            self._catalog_target_manifest(migration_registry)
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
        managed_manifest = None
        if expected_managed_revision is not None:
            if managed_registry is None or expected_managed_layers is None:
                raise ExtensionControlAuthorityError("managed policy binding missing")
            managed_manifest = self._catalog_target_manifest(managed_registry)
        with self._extension_control_authority_lock():
            if pack_activation is not None:
                from .catalog_delivery import lifecycle_store

                lifecycle_store.check(self, pack_activation.lifecycle_before, pack_activation.lifecycle_after)
                from .catalog_delivery.active_security import check_scope

                check_scope(self, pack_activation.security_digest)
            if expected_managed_revision is not None:
                assert managed_registry is not None
                managed_view = self._read_extension_control_authority_locked(
                    managed_registry.catalog_digest,
                    migration_registry=managed_registry,
                    allow_migration=False,
                )
                managed_view = self._with_managed_controls_activation(managed_view, current_manifest=managed_manifest)
                if (
                    managed_view.health is not AuthorityHealth.PROTECTED
                    or managed_view.managed_revision != expected_managed_revision
                    or tuple(layer for layer in managed_view.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
                    != expected_managed_layers
                ):
                    raise ExtensionControlAuthorityError("managed policy changed before commit")
            self._invalidate_native_extension_control_policy()
            # Do not roll back an abandoned transition yet: a retry of the same
            # request must still find and resume its prepared row below.
            #
            # Pass the registry: when another install has bound this authority
            # to its own catalog, a write under ours has to be able to rebind
            # the stored controls. Without it the read below rejects the
            # digest, every apply answers 409, and the only way out of the
            # conflict is to stop running one of the two installs.
            current = self._read_extension_control_authority_locked(
                catalog_digest,
                migration_registry=migration_registry,
                roll_back_abandoned=False,
                allow_migration=pack_activation is None,
            )
            key = self._authority_key(required=True)
            assert key is not None
            # An unknown schema version must refuse the write by name rather
            # than surface as a generic unavailable authority.
            with self._connect() as connection:
                ensure_extension_control_authority_schema(connection)
            commit = {
                "actor_id": actor_id,
                "idempotency_key": idempotency_key,
                "nonce": nonce,
                "proof_id": proof.proof_id,
                "mutation_digest": mutation.canonical_digest,
                "layers_json": layers_json,
                "expected_revision": expected_revision,
                # The resident binds its reply to the request it re-serializes,
                # which omits an absent digest rather than sending null.
                **({"pack_record_digest": pack_activation.digest} if pack_activation is not None else {}),
            }
            proof_already_consumed = False
            rollback_attempted = False
            for _ in range(_MAX_COMMIT_ROUNDS):
                plan = self._authority_plan(
                    "commit_plan",
                    key=key,
                    catalog_digest=catalog_digest,
                    view=view_to_wire(current),
                    commit=commit,
                    now=_now(),
                    rollback_attempted=rollback_attempted,
                )
                outcome = str(plan["outcome"])
                if outcome == "prepare":
                    break
                if outcome == "reread":
                    # A different request abandoned its prepared transition
                    # before anchoring it; a read rolls that back so this
                    # request can proceed.
                    current = self._read_extension_control_authority_locked(
                        catalog_digest, migration_registry=migration_registry, allow_migration=pack_activation is None
                    )
                    rollback_attempted = True
                    continue
                # A retry of this request found its own prepared transition.
                revision = _plan_int(plan, "revision")
                proof_hash = str(_plan_map(plan, "hashes")["proof"])
                with self._connect() as connection:
                    resumed = self._apply_resumed_transition(
                        connection,
                        outcome,
                        revision,
                        current=current,
                        key=key,
                        pack_record_digest=_plan_pack_digest(plan),
                    )
                    if resumed is not None:
                        consumed_at = _now()
                        if plan.get("proof_recorded") is not True:
                            consume_extension_control_proof(self.guard_home, proof, mutation)
                            connection.execute(
                                """
                                insert into extension_control_authority_proof (
                                    proof_id_hash, mutation_digest, transition_revision,
                                    reserved_at, consumed_at
                                ) values (?, ?, ?, ?, ?)
                                """,
                                (proof_hash, mutation.canonical_digest, revision, consumed_at, consumed_at),
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
                    if plan.get("proof_recorded") is True:
                        connection.execute(
                            "delete from extension_control_authority_proof where proof_id_hash = ?",
                            (proof_hash,),
                        )
                        proof_already_consumed = True
                current = self._read_extension_control_authority_locked(
                    catalog_digest, migration_registry=migration_registry, allow_migration=pack_activation is None
                )
            else:
                raise ExtensionControlAuthorityError("extension control authority unavailable")

            revision = _plan_int(plan, "revision")
            previous_revision = _plan_int(plan, "previous_revision")
            previous_digest = str(plan["previous_digest"])
            created_at = str(plan["created_at"])
            hashes = _plan_map(plan, "hashes")
            actor_hash, idempotency_hash = str(hashes["actor"]), str(hashes["idempotency"])
            nonce_hash, proof_hash = str(hashes["nonce"]), str(hashes["proof"])
            snapshot, transition = _plan_map(plan, "snapshot"), _plan_map(plan, "transition")
            snapshot_json, snapshot_digest, snapshot_mac = (
                str(snapshot["json"]),
                str(snapshot["digest"]),
                str(snapshot["mac"]),
            )
            transition_json, transition_digest, transition_mac = (
                str(transition["json"]),
                str(transition["digest"]),
                str(transition["mac"]),
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
                        previous_revision,
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
                if pack_activation is not None:
                    from .catalog_delivery.activation_journal import reserve

                    reserve(
                        self,
                        connection,
                        pack_activation,
                        control_revision=revision,
                        snapshot_digest=snapshot_digest,
                        catalog_digest=catalog_digest,
                        recorded_at=created_at,
                    )
            if not proof_already_consumed:
                consume_extension_control_proof(self.guard_home, proof, mutation)
            anchored = AuthorityAnchor(revision, snapshot_digest, AuthorityPhase.ANCHORED)
            try:
                self._write_and_verify_anchor(anchored, key=key)
            except Exception as exc:
                raise ExtensionControlAuthorityError("extension control authority anchor unavailable") from exc
            with self._connect() as connection:
                from .catalog_delivery.activation_journal import finish

                pending = connection.execute(
                    "select * from extension_control_authority_transition where revision=?", (revision,)
                ).fetchone()
                finish(
                    self,
                    connection,
                    pending,
                    expected_pack=pack_activation.digest if pack_activation is not None else None,
                )
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
                        previous_revision,
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
                    previous_revision=previous_revision,
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
        plan = _plan_map(
            self._extension_control_authority_op("bootstrap_plan", key=key, catalog_digest=catalog_digest, now=_now()),
            "plan",
        )
        snapshot_json, digest, mac = _plan_record(plan, "snapshot")
        layers_json, committed_at = str(plan["layers_json"]), str(plan["committed_at"])
        with self._connect() as connection:
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
