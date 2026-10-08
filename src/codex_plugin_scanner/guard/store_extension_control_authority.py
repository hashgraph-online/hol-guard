"""Crash-safe, externally anchored extension-control authority persistence."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import cast

from .managed_controls_policy_bundle import (
    managed_controls_layers_from_activation_state as managed_controls_layers_from_activation_state,
)
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.command_matcher_contracts import MatcherContractError, canonical_contract_value
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from .store_base import SecretStore
from .store_extension_control_authority_catalog import ExtensionControlAuthorityCatalogMixin
from .store_extension_control_authority_commit import ExtensionControlAuthorityCommitMixin
from .store_extension_control_authority_reads import ExtensionControlAuthorityReadsMixin
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_extension_control_authority_support import (
    _now,
    _row_int,
    _row_str,
)
from .store_extension_control_authority_transitions import _ExtensionControlAuthorityTransitionMixin


def _canonical_contract_value(value: object) -> object:
    try:
        return canonical_contract_value(value)
    except MatcherContractError as exc:
        raise ExtensionControlAuthorityError(str(exc)) from exc


class StoreExtensionControlAuthorityMixin(
    ExtensionControlAuthorityReadsMixin,
    ExtensionControlAuthorityCommitMixin,
    ExtensionControlAuthorityCatalogMixin,
    _ExtensionControlAuthorityTransitionMixin,
):
    """GuardStore mixin for the local extension-control authority."""

    _extension_control_authority_secret_store: SecretStore | None = None
    _extension_control_degraded_acknowledged: bool = False
    _extension_control_last_catalog_digest: str = "0" * 64
    _catalog_manifest_purpose = "hol-guard.extension-control-catalog-manifest.v1"

    def recover_extension_control_authority(
        self,
        *,
        catalog_digest: str,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
    ) -> ExtensionControlAuthorityView:
        with self._extension_control_authority_lock():
            self._invalidate_native_extension_control_policy(explicit_recovery=True)
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
                    committed = None
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
                    # Catalog migration below uses its own transaction. Release
                    # the writer lock before re-reading the authority;
                    # the authority lock still excludes competing mutations.
                    connection.commit()
                    recovered = self._read_extension_control_authority_locked(
                        catalog_digest,
                        migration_registry=migration_registry,
                    )
                    if recovered.health is AuthorityHealth.PROTECTED:
                        if committed is not None:
                            self._queue_extension_control_change_event(
                                connection,
                                revision=current_revision,
                                previous_revision=_row_int(committed, "previous_revision"),
                                layers_json=_row_str(committed, "layers_json"),
                                occurred_at=_row_str(committed, "created_at"),
                            )
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
        # Never import rows with an unverifiable chain; re-establish an empty protected authority.
        from .native_command_control_authority_store import begin_native_command_control_recovery
        from .store import GuardStore

        recovered_key = key if key is not None else secrets.token_bytes(32)
        begin_native_command_control_recovery(cast(GuardStore, self), new_authority_key=recovered_key)
        if key is None:
            self._secret_store().set_secret(self._key_ref(), base64.urlsafe_b64encode(recovered_key).decode())
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
            if key is None:
                # These rows authenticate with the lost key. They cannot be
                # reused under the explicit new-key recovery epoch. Managed
                # activation remains independently authenticated and fail-closed.
                connection.execute("delete from extension_control_catalog_manifest")
        return self._bootstrap_extension_control_authority(catalog_digest, key=recovered_key)

    def acknowledge_extension_control_degraded_mode(self) -> ExtensionControlAuthorityView:
        with self._extension_control_authority_lock():
            self._invalidate_native_extension_control_policy()
            self._extension_control_degraded_acknowledged = True
            return self._degraded_view(self._extension_control_last_catalog_digest)
