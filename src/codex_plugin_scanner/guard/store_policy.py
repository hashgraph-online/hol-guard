"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal, cast

from .managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
    MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
    build_managed_controls_activation_state,
    build_managed_controls_revision_state,
    managed_controls_layers_from_activation_state,
    managed_controls_revision_from_state,
)
from .native_policy_bundle import PolicyBundleNativeError, PolicyBundleNativeUnavailableError
from .policy_bundle_activation import (
    PolicyBundleActivationRejectionError,
    PrecomputedVerdicts,
    ResidentVerdictRequiredError,
    composed_managed_authority,
    encoded_delivery_acknowledgement,
    managed_delivery_matches_base,
    published_managed_authority,
)
from .runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from .runtime.extension_control_contract import ControlLayerKind
from .store_custom_extension_continuity import CustomExtensionContinuityMutation
from .store_policy_activation_preflight import (
    apply_continuity_rejection,
    continuity_activation_rejection,
    encoded_policy_activation_payloads,
    policy_checkpoint_rejection,
)

if TYPE_CHECKING:
    from .managed_controls_policy_fields import ParsedManagedControlsPolicy

# ruff: noqa: F403,F405
from .action_lattice import guard_action_severity
from .memory_pattern_fingerprint import (
    build_exact_command_memory_artifact_id,
    build_exact_shell_command_memory_artifact_id,
    build_memory_pattern_fingerprint,
)
from .native_approval_proof import approval_reuse_claim_disposition as native_claim_disposition
from .native_execution import _resident_request
from .native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME, NativePolicySnapshotError
from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key
from .native_policy_snapshot_windows_support import _runtime_state_directory
from .native_store_policy import (
    ApprovalReuseDiagnosticUnavailableError,
    claim_evidence_binding,
    encode_key,
    native_approval_reuse_diagnostic,
    native_claim_approval_reuse_decisions,
)
from .store_base import *

_LOGGER = logging.getLogger(__name__)
# Reported when the resident cannot diagnose a saved-allow miss. Every caller
# already treats a reason as "the saved allow was rejected", so this fails closed
# into re-approval instead of letting a missing diagnosis read as authority.
APPROVAL_REUSE_DIAGNOSTIC_UNAVAILABLE_REASON = "approval_reuse_integrity_failure"

POLICY_DECISION_LOOKUP_FEATURE = "policy-decision-lookup-v1"
_RESIDENT_VERDICT_ATTEMPTS = 6


def _memory_artifact_is_shell_command(
    artifact_type: str | None,
    artifact_name: str | None,
) -> bool:
    normalized_type = artifact_type.strip().casefold() if isinstance(artifact_type, str) else ""
    if normalized_type in {"bash", "shell", "shell_command"}:
        return True
    if normalized_type != "tool_action_request" or not isinstance(artifact_name, str):
        return False
    normalized_name = artifact_name.strip().casefold()
    return normalized_name in {"bash", "shell"} or normalized_name.startswith(("bash ", "shell "))


def _distinct_non_null(values: Sequence[str | None]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value is not None))


def _most_restrictive_policy_lookup(
    lookups: Sequence[PolicyDecisionLookupResult],
) -> PolicyDecisionLookupResult:
    """Compose non-consuming direct, exact-command, and memory matches."""

    if not lookups:
        raise ValueError("at least one policy lookup is required")
    selected_lookup = lookups[0]
    selected_decision = selected_lookup["decision"]
    ignored_integrity = selected_lookup.get("ignored_local_integrity")
    revisions = {lookup["authority_revision"] for lookup in lookups}
    authority_revision = next(iter(revisions)) if len(revisions) == 1 else -1
    for lookup in lookups[1:]:
        decision = lookup["decision"]
        if ignored_integrity is None and lookup.get("ignored_local_integrity") is not None:
            ignored_integrity = lookup["ignored_local_integrity"]
        if decision is None:
            continue
        if selected_decision is None or guard_action_severity(
            decision.get("action"),
            unknown_action="block",
        ) > guard_action_severity(selected_decision.get("action"), unknown_action="block"):
            selected_lookup = lookup
            selected_decision = decision
    if selected_decision is not None:
        selected_decision = {
            **selected_decision,
            "_approval_authority_revision": authority_revision,
        }
    return {
        "decision": selected_decision,
        "ignored_local_integrity": ignored_integrity,
        "trust_status": selected_lookup["trust_status"],
        "authority_revision": authority_revision,
    }


def _approval_authority_revision(connection: sqlite3.Connection) -> int:
    row = connection.execute("select revision from guard_approval_authority_revision where singleton = 1").fetchone()
    if row is None:
        return -1
    revision = row["revision"]
    return revision if isinstance(revision, int) and not isinstance(revision, bool) else -1


class StorePolicyMixin:
    def reconcile_managed_policy_bundle_keyring_state(
        self,
        *,
        managed_keyring: Mapping[str, object] | None,
        quarantined_local_keyring: Mapping[str, object] | None,
        provenance: Mapping[str, object] | None,
        now: str,
        force_clear: bool = False,
    ) -> bool:
        """Atomically reconcile the user-side mirror of machine key authority.

        A configured managed domain writes its diagnostic mirror, empty local
        anchor slot, and provenance marker in one transaction. Cleanup may be
        forced by an authorized managed repair/deactivation so deleting the
        user-writable marker cannot preserve a replacement local anchor.
        """

        state_keys = (
            "managed_policy_bundle_keyring_provenance",
            "managed_policy_bundle_keyring_mirror",
            "policy_bundle_keyring",
        )
        normalized_now = _canonical_utc_timestamp(now)
        configured = managed_keyring is not None and quarantined_local_keyring is not None and provenance is not None
        if (
            any(item is not None for item in (managed_keyring, quarantined_local_keyring, provenance))
            and not configured
        ):
            raise ValueError("managed_policy_bundle_keyring_reconcile_incomplete")
        with self._connect() as connection:
            connection.execute("begin immediate")
            if not configured:
                marker = connection.execute(
                    "select 1 from sync_state where state_key = ?",
                    (state_keys[0],),
                ).fetchone()
                if marker is None and not force_clear:
                    connection.rollback()
                    return False
                placeholders = ",".join("?" for _ in state_keys)
                connection.execute(
                    f"delete from sync_state where state_key in ({placeholders})",
                    state_keys,
                )
                return True
            assert managed_keyring is not None
            assert quarantined_local_keyring is not None
            assert provenance is not None
            payloads = {
                state_keys[0]: dict(provenance),
                state_keys[1]: dict(managed_keyring),
                state_keys[2]: dict(quarantined_local_keyring),
            }
            encoded = {state_key: json.dumps(payload, allow_nan=False) for state_key, payload in payloads.items()}
            for state_key, payload_json in encoded.items():
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (state_key, payload_json, normalized_now),
                )
        return True

    def _cached_policy_bundle_decision_identities(
        self,
        *,
        now: float | None = None,
    ) -> frozenset[tuple[object, ...]]:
        """Return only rows derivable from the currently authorized signed bundle."""

        from .policy_bundle_decisions import build_policy_bundle_decisions
        from .synced_policy import SyncPayloadReader, cached_policy_bundle_validation

        policy_bundle = self.get_sync_payload("policy_bundle")
        if not isinstance(policy_bundle, dict) or not policy_bundle:
            return frozenset()
        validated_bundle, _reason = cached_policy_bundle_validation(
            cast(SyncPayloadReader, cast(object, self)),
            policy_bundle,
            now=now,
        )
        if validated_bundle is None:
            return frozenset()
        try:
            device_metadata = self.get_device_metadata()
            decisions = build_policy_bundle_decisions(
                validated_bundle,
                device_id=str(device_metadata["installation_id"]),
                device_name=str(device_metadata["device_label"]),
            )
        except (KeyError, OSError, RuntimeError, TypeError, ValueError):
            return frozenset()
        identities: set[tuple[object, ...]] = set()
        for decision in decisions:
            artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
            identities.add(
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    (_canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None),
                )
            )
        return frozenset(identities)

    def upsert_policy(
        self,
        decision: PolicyDecision,
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
    ) -> None:
        now = _canonical_utc_timestamp(now)
        validate_policy_write_authority(
            decision,
            remote_write_authorized=remote_write_authorized,
        )
        require_policy_write(
            self.guard_home,
            decision=decision,
            approval_gate_grant=approval_gate_grant,
            now=now,
        )
        _validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
        next_control_state: dict[str, object] | None = None
        with self._connect() as connection:
            secret_material = (None, None)
            if not is_remote_policy_source(decision.source):
                secret_material = self._policy_integrity_secret_material(create=True)
            next_control_state = self._upsert_policy_locked(
                connection,
                decision=decision,
                now=now,
                secret_material=secret_material,
            )
        if next_control_state is not None:
            self._finalize_policy_integrity_control_state(next_control_state)

    def _upsert_policy_locked(
        self,
        connection: sqlite3.Connection,
        *,
        decision: PolicyDecision,
        now: str,
        secret_material: tuple[bytes | None, str | None],
    ) -> dict[str, object] | None:
        expires_at = _canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None
        artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
        state = self._refresh_policy_integrity_state(
            connection,
            now=now,
            create_key=not is_remote_policy_source(decision.source),
            secret_material=secret_material,
            allow_cutover_resign=False,
        )
        connection.execute(
            """
            delete from policy_decisions
            where harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '')
              and coalesce(artifact_hash, '') = coalesce(?, '')
              and coalesce(workspace, '') = coalesce(?, '')
              and coalesce(publisher, '') = coalesce(?, '')
            """,
            (decision.harness, decision.scope, artifact_id, artifact_hash, workspace, publisher),
        )
        cursor = connection.execute(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
              expires_at, updated_at, integrity_version, integrity_generation, payload_hash, payload_mac,
              integrity_key_id, signed_at
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.harness,
                decision.scope,
                artifact_id,
                artifact_hash,
                workspace,
                publisher,
                decision.action,
                decision.reason,
                decision.owner,
                decision.source,
                expires_at,
                now,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        )
        if is_remote_policy_source(decision.source) or state.get("mode") != "protected":
            return None
        key, key_id = secret_material
        if key is None or key_id is None:
            return None
        trusted_state = self._load_policy_integrity_control_state(create=True)
        if trusted_state is None:
            return None
        lastrowid = cursor.lastrowid
        if lastrowid is None:
            raise RuntimeError("Guard policy decision row was not inserted.")
        return self._advance_policy_integrity_generation(
            connection,
            now=now,
            key=key,
            key_id=key_id,
            trusted_state=trusted_state,
            force_sign_decision_ids={lastrowid},
        )

    def replace_remote_policies(
        self,
        decisions: list[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
    ) -> None:
        now, rows = self._prepared_remote_policy_rows(
            decisions,
            now,
            approval_gate_grant=approval_gate_grant,
            remote_write_authorized=remote_write_authorized,
        )
        with self._connect() as connection:
            self._replace_remote_policy_rows_locked(connection, rows)

    def apply_policy_bundle_authority(self, *args: Any, **kwargs: Any) -> dict[str, object] | None:
        """Activate one authenticated policy bundle atomically.

        The resident computes the delivery acknowledgement and the anti-downgrade
        verdict, which can take seconds. They must never run while the authority
        lock and the SQLite write transaction are held, so they are computed
        between attempts. Each attempt re-reads the state those verdicts depend
        on under the lock and only uses a precomputed result that was derived
        from exactly that state.
        """

        verdicts = PrecomputedVerdicts()
        for _attempt in range(_RESIDENT_VERDICT_ATTEMPTS):
            try:
                return self._apply_policy_bundle_authority_attempt(*args, verdicts=verdicts, **kwargs)
            except ResidentVerdictRequiredError as required:
                try:
                    verdicts.fill(required)
                except PolicyBundleNativeUnavailableError:
                    raise
                except (json.JSONDecodeError, TypeError, ValueError, PolicyBundleNativeError):
                    return self._reject_policy_bundle_activation(required.invalid_reason, kwargs)
        return self._reject_policy_bundle_activation("policy_bundle_activation_contended", kwargs)

    @staticmethod
    def _reject_policy_bundle_activation(reason: str, kwargs: Mapping[str, Any]) -> None:
        if kwargs.get("raise_on_rejection"):
            raise PolicyBundleActivationRejectionError(reason)
        return None

    def _apply_policy_bundle_authority_attempt(
        self,
        decisions: list[PolicyDecision],
        now: str,
        *,
        policy_bundle: Mapping[str, object],
        policy_bundle_keyring: Mapping[str, object],
        cloud_exceptions: Sequence[Mapping[str, object]],
        policy_bundle_ack: Mapping[str, object],
        policy_bundle_checkpoint: Mapping[str, object],
        update_last_good: bool,
        policy_bundle_last_error: Mapping[str, object] | None = None,
        managed_controls_policy: ParsedManagedControlsPolicy | None = None,
        managed_controls_negotiated_capabilities: frozenset[str] = frozenset(),
        managed_controls_delivery: Mapping[str, object] | None = None,
        managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
        custom_extension_continuity: CustomExtensionContinuityMutation | None = None,
        raise_on_rejection: bool = False,
        approval_gate_grant: ApprovalGateGrant | None = None,
        remote_write_authorized: bool = False,
        verdicts: PrecomputedVerdicts | None = None,
    ) -> dict[str, object] | None:
        """Atomically activate one authenticated policy bundle and its rows.

        The cached bundle is itself enforcement authority because policy
        defaults are read directly from it.  It must therefore become current
        in one transaction with every materialized decision, exception, acknowledgement, and trust checkpoint.
        Preparing and JSON-encoding all inputs before the write transaction
        also guarantees malformed rule expiry or payload data cannot leave a
        partially activated bundle behind.
        """

        def reject(
            reason: str,
            connection: sqlite3.Connection | None = None,
        ) -> None:
            if connection is not None:
                connection.rollback()
            if raise_on_rejection:
                raise PolicyBundleActivationRejectionError(reason)
            return None

        normalized_now, rows = self._prepared_remote_policy_rows(
            decisions,
            now,
            approval_gate_grant=approval_gate_grant,
            remote_write_authorized=remote_write_authorized,
        )
        payload_rejection, encoded_payloads = encoded_policy_activation_payloads(
            policy_bundle,
            policy_bundle_keyring,
            cloud_exceptions,
            policy_bundle_ack,
            policy_bundle_checkpoint,
            policy_bundle_last_error,
            update_last_good=update_last_good,
        )
        if payload_rejection is not None:
            return reject(payload_rejection)
        from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

        with self._extension_control_authority_lock(), self._connect() as connection:
            self._invalidate_native_extension_control_policy()
            connection.execute("begin immediate")
            managed_base_authority = self._read_extension_control_authority_locked(
                BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            )
            continuity_rejection = continuity_activation_rejection(
                custom_extension_continuity,
                protected_authority=managed_base_authority.health is AuthorityHealth.PROTECTED,
                negotiated_capabilities=managed_controls_negotiated_capabilities,
            )
            if continuity_rejection is not None:
                return reject(continuity_rejection, connection)
            authority_row = connection.execute(
                "select revision, snapshot_digest from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
            managed_base_snapshot = (
                None
                if authority_row is None
                else (
                    int(authority_row["revision"]),
                    str(authority_row["snapshot_digest"]),
                )
            )
            managed_authority_key: bytes | None = None
            managed_revision = 0
            if managed_controls_policy is not None:
                if managed_base_authority.health is not AuthorityHealth.PROTECTED:
                    return reject("managed_controls_authority_unprotected", connection)
                if managed_base_snapshot is None:
                    return reject("managed_controls_authority_snapshot_missing", connection)
                managed_authority_key = self._authority_key(required=True)
                if managed_authority_key is None:
                    return reject("managed_controls_authority_key_unavailable", connection)
            try:
                checkpoint_rejection = policy_checkpoint_rejection(connection, policy_bundle, verdicts)
            except ResidentVerdictRequiredError:
                connection.rollback()
                raise
            if checkpoint_rejection is not None:
                return reject(checkpoint_rejection, connection)
            active_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (MANAGED_CONTROLS_ACTIVE_STATE_KEY,),
            ).fetchone()
            revision_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (MANAGED_CONTROLS_REVISION_STATE_KEY,),
            ).fetchone()
            if (active_row is not None or revision_row is not None) and managed_authority_key is None:
                managed_authority_key = self._authority_key(required=True)
                if managed_authority_key is None:
                    return reject("managed_controls_authority_key_unavailable", connection)
            previous_revision = 0
            previous_bundle_hash: object = None
            active_managed_layers = ()
            if revision_row is not None:
                assert managed_authority_key is not None
                try:
                    revision_state = json.loads(str(revision_row["payload_json"]))
                    previous_revision = managed_controls_revision_from_state(
                        revision_state,
                        authority_key=managed_authority_key,
                    )
                except (json.JSONDecodeError, ExtensionControlAuthorityError):
                    return reject("managed_controls_revision_state_invalid", connection)
            if active_row is not None:
                assert managed_base_authority is not None
                assert managed_authority_key is not None
                try:
                    previous_active = json.loads(str(active_row["payload_json"]))
                    active_managed_layers, active_revision = managed_controls_layers_from_activation_state(
                        previous_active,
                        catalog_digest=managed_base_authority.catalog_digest,
                        authority_key=managed_authority_key,
                    )
                except (json.JSONDecodeError, ExtensionControlAuthorityError):
                    return reject("managed_controls_activation_state_invalid", connection)
                if revision_row is not None and active_revision != previous_revision:
                    return reject("managed_controls_revision_state_mismatch", connection)
                previous_revision = active_revision
                previous_bundle_hash = previous_active.get("bundleHash")
            if managed_controls_delivery is not None:
                if managed_controls_policy is None or managed_base_authority is None:
                    return reject("managed_controls_delivery_policy_missing", connection)
                current_authority = composed_managed_authority(
                    managed_base_authority,
                    managed_layers=active_managed_layers,
                    managed_revision=previous_revision,
                )
                if not managed_delivery_matches_base(
                    managed_controls_delivery,
                    policy_bundle=policy_bundle,
                    policy=managed_controls_policy,
                    base_authority=current_authority,
                ):
                    return reject("managed_controls_delivery_mismatch", connection)
            if managed_controls_policy is not None:
                assert managed_base_authority is not None
                assert managed_base_snapshot is not None
                assert managed_authority_key is not None
                managed_revision = (
                    previous_revision
                    if previous_bundle_hash == policy_bundle.get("bundleHash") and previous_revision > 0
                    else previous_revision + 1
                )
                managed_state = build_managed_controls_activation_state(
                    dict(policy_bundle),
                    managed_controls_policy,
                    base_authority=managed_base_authority,
                    managed_revision=managed_revision,
                    negotiated_capabilities=managed_controls_negotiated_capabilities,
                    authority_key=managed_authority_key,
                    base_snapshot_digest=managed_base_snapshot[1],
                )
                encoded_payloads[MANAGED_CONTROLS_ACTIVE_STATE_KEY] = json.dumps(
                    managed_state,
                    allow_nan=False,
                )
                encoded_payloads[MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY] = json.dumps(
                    sorted(managed_controls_negotiated_capabilities),
                    allow_nan=False,
                )
                encoded_payloads[MANAGED_CONTROLS_REVISION_STATE_KEY] = json.dumps(
                    build_managed_controls_revision_state(
                        managed_revision,
                        authority_key=managed_authority_key,
                    ),
                    allow_nan=False,
                )
                if update_last_good:
                    encoded_payloads[MANAGED_CONTROLS_LAST_GOOD_STATE_KEY] = json.dumps(
                        managed_state,
                        allow_nan=False,
                    )
            else:
                managed_revision = previous_revision + 1 if active_row is not None else previous_revision
                if managed_revision > 0:
                    assert managed_authority_key is not None
                    encoded_payloads[MANAGED_CONTROLS_REVISION_STATE_KEY] = json.dumps(
                        build_managed_controls_revision_state(
                            managed_revision,
                            authority_key=managed_authority_key,
                        ),
                        allow_nan=False,
                    )
                connection.execute(
                    "delete from sync_state where state_key in (?, ?)",
                    (MANAGED_CONTROLS_ACTIVE_STATE_KEY, MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY),
                )
            published_authority = None
            if managed_controls_policy is not None or managed_controls_publish is not None:
                assert managed_base_authority is not None
                published_authority = published_managed_authority(
                    managed_base_authority,
                    policy=managed_controls_policy,
                    managed_revision=managed_revision,
                )
            if managed_controls_delivery is not None:
                if published_authority is None:
                    return reject("managed_controls_delivery_authority_missing", connection)
                try:
                    encoded_payloads["policy_bundle_ack"] = encoded_delivery_acknowledgement(
                        connection,
                        delivery=managed_controls_delivery,
                        policy_bundle=policy_bundle,
                        published_authority=published_authority,
                        observed_at=normalized_now,
                        verdicts=verdicts,
                    )
                except ResidentVerdictRequiredError:
                    connection.rollback()
                    raise
                except (json.JSONDecodeError, TypeError, ValueError):
                    return reject("managed_controls_delivery_ack_invalid", connection)
            continuity_rejection = apply_continuity_rejection(
                connection,
                custom_extension_continuity,
                boundary=self._custom_extension_continuity_transaction_boundary,
            )
            if continuity_rejection is not None:
                return reject(continuity_rejection, connection)
            self._replace_remote_policy_rows_locked(connection, rows)
            for state_key, payload_json in encoded_payloads.items():
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (state_key, payload_json, normalized_now),
                )
            if managed_controls_publish is not None:
                assert published_authority is not None
                managed_controls_publish(
                    published_authority,
                    connection.commit,
                )
        persisted_acknowledgement = json.loads(encoded_payloads["policy_bundle_ack"])
        return persisted_acknowledgement if isinstance(persisted_acknowledgement, dict) else None

    def clear_policy_bundle_authority(
        self,
        now: str,
        *,
        policy_bundle_last_error: Mapping[str, object],
        managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
    ) -> None:
        """Atomically remove all cached and materialized remote authority."""

        normalized_now = _canonical_utc_timestamp(now)
        state_payloads: dict[str, object] = {
            "cloud_exceptions": [],
            "policy": {},
            "policy_bundle_last_error": dict(policy_bundle_last_error),
            "team_policy_pack": {},
        }
        encoded_payloads = {
            state_key: json.dumps(payload, allow_nan=False) for state_key, payload in state_payloads.items()
        }
        managed_base_snapshot: tuple[int, str] | None = None
        managed_base_snapshot_captured = False
        managed_base_authority = self.read_persisted_extension_control_authority()
        with self._connect() as authority_connection:
            authority_row = authority_connection.execute(
                "select revision, snapshot_digest from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
        managed_base_snapshot_captured = True
        if authority_row is not None:
            managed_base_snapshot = (
                int(authority_row["revision"]),
                str(authority_row["snapshot_digest"]),
            )
        with self._extension_control_authority_lock(), self._connect() as connection:
            self._invalidate_native_extension_control_policy()
            connection.execute("begin immediate")
            if managed_base_snapshot_captured:
                authority_row = connection.execute(
                    "select revision, snapshot_digest from extension_control_authority_snapshot where singleton = 1"
                ).fetchone()
                observed_base_snapshot = (
                    None
                    if authority_row is None
                    else (
                        int(authority_row["revision"]),
                        str(authority_row["snapshot_digest"]),
                    )
                )
                if observed_base_snapshot != managed_base_snapshot:
                    connection.rollback()
                    raise ExtensionControlAuthorityError("extension control authority changed during clear")
            active_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (MANAGED_CONTROLS_ACTIVE_STATE_KEY,),
            ).fetchone()
            revision_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (MANAGED_CONTROLS_REVISION_STATE_KEY,),
            ).fetchone()
            managed_revision = 0
            managed_authority_key = None
            if active_row is not None or revision_row is not None:
                managed_authority_key = self._authority_key(required=True)
                if managed_authority_key is None:
                    raise ExtensionControlAuthorityError("managed controls authority key is unavailable")
            if revision_row is not None:
                assert managed_authority_key is not None
                try:
                    revision_state = json.loads(str(revision_row["payload_json"]))
                    managed_revision = managed_controls_revision_from_state(
                        revision_state,
                        authority_key=managed_authority_key,
                    )
                except (json.JSONDecodeError, ExtensionControlAuthorityError) as exc:
                    connection.rollback()
                    raise ExtensionControlAuthorityError("invalid managed controls revision") from exc
            if active_row is not None:
                assert managed_authority_key is not None
                try:
                    previous_active = json.loads(str(active_row["payload_json"]))
                    active_catalog_digest = (
                        previous_active.get("catalogDigest") if isinstance(previous_active, dict) else None
                    )
                    if not isinstance(active_catalog_digest, str) or not active_catalog_digest:
                        raise ExtensionControlAuthorityError("invalid managed controls activation catalog")
                    _, active_revision = managed_controls_layers_from_activation_state(
                        previous_active,
                        catalog_digest=active_catalog_digest,
                        authority_key=managed_authority_key,
                    )
                except (json.JSONDecodeError, ExtensionControlAuthorityError) as exc:
                    connection.rollback()
                    raise ExtensionControlAuthorityError("invalid managed controls activation") from exc
                if revision_row is not None and active_revision != managed_revision:
                    connection.rollback()
                    raise ExtensionControlAuthorityError("managed controls revision mismatch")
                managed_revision = active_revision + 1
            if managed_revision > 0:
                assert managed_authority_key is not None
                encoded_payloads[MANAGED_CONTROLS_REVISION_STATE_KEY] = json.dumps(
                    build_managed_controls_revision_state(
                        managed_revision,
                        authority_key=managed_authority_key,
                    ),
                    allow_nan=False,
                )
            self._replace_remote_policy_rows_locked(connection, ())
            connection.execute(
                "delete from sync_state where state_key in (?, ?, ?, ?)",
                (
                    "policy_bundle",
                    "policy_bundle_ack",
                    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
                    MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY,
                ),
            )
            for state_key, payload_json in encoded_payloads.items():
                connection.execute(
                    """
                    insert into sync_state (state_key, payload_json, updated_at)
                    values (?, ?, ?)
                    on conflict(state_key) do update set
                      payload_json = excluded.payload_json,
                      updated_at = excluded.updated_at
                    """,
                    (state_key, payload_json, normalized_now),
                )
            if managed_controls_publish is not None:
                assert managed_base_authority is not None
                local_layers = tuple(
                    layer for layer in managed_base_authority.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN
                )
                managed_controls_publish(
                    ExtensionControlAuthorityView(
                        managed_base_authority.health,
                        managed_base_authority.revision,
                        managed_base_authority.catalog_digest,
                        local_layers,
                        managed_revision,
                    ),
                    connection.commit,
                )

    def _prepared_remote_policy_rows(
        self,
        decisions: Sequence[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None,
        remote_write_authorized: bool,
    ) -> tuple[str, list[tuple[object, ...]]]:
        normalized_now = _canonical_utc_timestamp(now)
        rows: list[tuple[object, ...]] = []
        for decision in decisions:
            validate_policy_write_authority(
                decision,
                remote_write_authorized=remote_write_authorized,
            )
            require_policy_write(
                self.guard_home,
                decision=decision,
                approval_gate_grant=approval_gate_grant,
                now=normalized_now,
            )
            expires_at = _canonical_utc_timestamp(decision.expires_at) if decision.expires_at is not None else None
            _validate_scoped_policy_artifact_target(decision.scope, decision.artifact_id)
            artifact_id, artifact_hash, workspace, publisher = self._normalized_policy_keys(decision)
            rows.append(
                (
                    decision.harness,
                    decision.scope,
                    artifact_id,
                    artifact_hash,
                    workspace,
                    publisher,
                    decision.action,
                    decision.reason,
                    decision.owner,
                    decision.source,
                    expires_at,
                    normalized_now,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            )
        return normalized_now, rows

    @staticmethod
    def _replace_remote_policy_rows_locked(
        connection: sqlite3.Connection,
        rows: Sequence[tuple[object, ...]],
    ) -> None:
        connection.execute(
            f"delete from policy_decisions where source in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS}",
            _REMOTE_POLICY_SOURCE_PARAMS,
        )
        connection.executemany(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
              expires_at, updated_at, integrity_version, integrity_generation, payload_hash, payload_mac,
              integrity_key_id, signed_at
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    def resolve_policy(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        *,
        memory_command: str | None = None,
        memory_artifact_type: str | None = None,
        memory_artifact_name: str | None = None,
        consume_one_shot: bool = True,
    ) -> str | None:
        lookup = self.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            memory_command=memory_command,
            memory_artifact_type=memory_artifact_type,
            memory_artifact_name=memory_artifact_name,
            consume_one_shot=consume_one_shot,
        )
        decision = lookup["decision"]
        return str(decision["action"]) if decision is not None else None

    def resolve_policy_decision_lookup_with_memory_pattern(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        *,
        memory_command: str | None = None,
        memory_artifact_type: str | None = None,
        memory_artifact_name: str | None = None,
        consume_one_shot: bool = True,
    ) -> PolicyDecisionLookupResult:
        direct_lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
        )
        candidate_lookups = [direct_lookup]
        if consume_one_shot and (
            direct_lookup["decision"] is not None or direct_lookup.get("ignored_local_integrity") is not None
        ):
            return direct_lookup
        if _memory_artifact_is_shell_command(memory_artifact_type, memory_artifact_name):
            exact_command_artifact_ids = (
                build_exact_shell_command_memory_artifact_id(memory_command),
                build_exact_command_memory_artifact_id(memory_command),
            )
            for exact_command_artifact_id in _distinct_non_null(exact_command_artifact_ids):
                if exact_command_artifact_id == artifact_id:
                    continue
                exact_command_lookup = self.resolve_policy_decision_lookup(
                    harness,
                    exact_command_artifact_id,
                    artifact_hash=artifact_hash,
                    workspace=workspace,
                    publisher=publisher,
                    now=now,
                    runtime_exact_match_context=runtime_exact_match_context,
                    consume_one_shot=consume_one_shot,
                )
                candidate_lookups.append(exact_command_lookup)
                if consume_one_shot and (
                    exact_command_lookup["decision"] is not None
                    or exact_command_lookup.get("ignored_local_integrity") is not None
                ):
                    return exact_command_lookup
        memory_pattern = build_memory_pattern_fingerprint(
            command=memory_command,
            artifact_type=memory_artifact_type,
            artifact_id=artifact_id,
            artifact_name=memory_artifact_name,
            harness=harness,
        )
        if memory_pattern is None:
            return _most_restrictive_policy_lookup(candidate_lookups)
        memory_artifact_id = f"memory:{harness}:{memory_pattern.kind}:{memory_pattern.fingerprint}"
        if memory_artifact_id == artifact_id:
            return _most_restrictive_policy_lookup(candidate_lookups)
        memory_lookup = self.resolve_policy_decision_lookup(
            harness,
            memory_artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
        )
        candidate_lookups.append(memory_lookup)
        if consume_one_shot:
            return (
                memory_lookup
                if (memory_lookup["decision"] is not None or memory_lookup.get("ignored_local_integrity") is not None)
                else direct_lookup
            )
        return _most_restrictive_policy_lookup(candidate_lookups)

    def resolve_policy_decision_lookup(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
    ) -> PolicyDecisionLookupResult:
        """Resolve the effective policy decision via the native resident op.

        Rust owns the digest/decision authority: it opens ``store_path``, runs
        the bounded non-consuming or consuming multi-scope probe, applies the
        scoped exact-match + eligibility rules, verifies row integrity against
        caller-shipped material, claims one-shot local-once approvals, emits
        ``guard_events``, and returns the ``lookup_result`` payload. Python only
        procures the OS-keyring-facing integrity material and the post-refresh
        integrity state, ships them as evidence DTO fields, and decodes the
        result. Native failure is terminal — there is no Python fallback.
        """
        current_time = _canonical_utc_timestamp(now or _now())

        # Procure the integrity evidence *before* dispatch. `_refresh_policy_integrity_state`
        # mutates `sync_state` and may mint a key (generation advance), so it stays
        # on the Python side; the resulting snapshot is shipped to Rust.
        with self._connect() as connection:
            has_local_policy = (
                connection.execute(
                    f"select 1 from policy_decisions where source not in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS} limit 1",
                    _REMOTE_POLICY_SOURCE_PARAMS,
                ).fetchone()
                is not None
            )
            has_remote_policy = (
                connection.execute(
                    f"select 1 from policy_decisions where source in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS} limit 1",
                    _REMOTE_POLICY_SOURCE_PARAMS,
                ).fetchone()
                is not None
            )
            has_local_once_approvals = (
                connection.execute("select 1 from guard_local_once_approvals limit 1").fetchone() is not None
            )
            integrity_state = (
                self._refresh_policy_integrity_state(
                    connection,
                    now=current_time,
                    create_key=True,
                )
                or {}
                if has_local_policy
                else {}
            )

        # The resident refuses to serve until the owner-private verifier key
        # exists under this guard home (consume_for_spawn gate). Publishers
        # provision it at start(); standalone decision lookups must establish
        # the same prerequisite or every request fails closed on
        # native_policy_verifier_key_missing. Provisioning is O_EXCL +
        # never-replace, so it is idempotent and safe to run per lookup.
        try:
            verifier_path = _runtime_state_directory(Path(self.guard_home)) / NATIVE_POLICY_VERIFIER_KEY_NAME
        except (NativePolicySnapshotError, OSError, RuntimeError, TypeError, ValueError):
            # Untrusted/inaccessible guard home (e.g. symlinked) cannot persist a
            # verifier key; treat as none so the degraded-lookup guard below applies.
            verifier_path = None
        verifier_exists = verifier_path.is_file() if verifier_path is not None else False

        # Resident startup needs the same verifier authority even when only
        # remote policy rows (or only local-once approvals) exist. Read the
        # keyring non-creatively first; minting is reserved for stores that
        # carry resident evidence (verifier file, remote policy rows, or a
        # local-once row whose signature was issued under the keyring) so a
        # lookup against a never-provisioned store does not mint an unused key.
        resident_key, resident_key_id = self._policy_integrity_secret_material(create=False)
        if resident_key is None and (verifier_exists or has_remote_policy or has_local_once_approvals):
            resident_key, resident_key_id = self._policy_integrity_secret_material(create=True)
        if has_local_policy:
            integrity_key, integrity_key_id = resident_key, resident_key_id
        else:
            integrity_key, integrity_key_id = None, None
        # Local-once approvals live in a separate table from policy_decisions.
        # Their integrity evidence must not depend on has_local_policy.
        local_once_key, local_once_key_id = resident_key, resident_key_id

        if resident_key is not None:
            try:
                provision_native_policy_verifier_key(Path(self.guard_home), resident_key)
            except NativePolicySnapshotError as error:
                if str(error) in {
                    "native_policy_verifier_key_invalid",
                    "native_policy_verifier_key_mismatch",
                    "native_policy_verifier_key_not_private",
                }:
                    # A persisted verifier that is malformed, foreign-owned,
                    # or bytes-mismatched is active tampering evidence. Never
                    # silently degrade past it — the resident must not serve
                    # under an unverifiable authority.
                    raise
                # Cannot persist the verifier under an untrusted home; keep only
                # the on-disk evidence flag, which is False when provisioning
                # failed on the same home.
                verifier_exists = verifier_path.is_file() if verifier_path is not None else False
                if not verifier_exists:
                    return {
                        "decision": None,
                        "ignored_local_integrity": None,
                        "trust_status": TrustStatus.from_policy_integrity_state(integrity_state).to_dict(),
                        "authority_revision": -1,
                    }
            except (OSError, RuntimeError, TypeError, ValueError):
                verifier_exists = verifier_path.is_file() if verifier_path is not None else False
                if not verifier_exists:
                    return {
                        "decision": None,
                        "ignored_local_integrity": None,
                        "trust_status": TrustStatus.from_policy_integrity_state(integrity_state).to_dict(),
                        "authority_revision": -1,
                    }
        elif verifier_path is None or (not verifier_exists and not has_local_once_approvals):
            # An untrusted guard home (verifier_path is None) can never persist
            # a verifier key, and a store with no integrity keyring, no
            # persisted verifier, and no local-once approvals has no authority
            # to serve. Return an empty degraded lookup rather than raising
            # native_policy_decision_lookup_unavailable on a store that cannot
            # be provisioned. When local-once rows exist (even unsigned legacy
            # ones) the resident still needs the request to emit
            # ignored_local_integrity evidence.
            return {
                "decision": None,
                "ignored_local_integrity": None,
                "trust_status": TrustStatus.from_policy_integrity_state(integrity_state).to_dict(),
                "authority_revision": -1,
            }

        request: dict[str, object] = {
            "schema": "guard-policy-decision-lookup-request.v1",
            "request_id": f"policy-decision-lookup-{uuid4().hex}",
            "store_path": str(self.path),
            "guard_home": str(self.guard_home),
            "harness": harness,
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "workspace": workspace,
            "publisher": publisher,
            "now": current_time,
            "runtime_exact_match_context": runtime_exact_match_context,
            "consume_one_shot": bool(consume_one_shot),
            "integrity_state": integrity_state,
            "integrity_key_b64": (
                base64.urlsafe_b64encode(integrity_key).rstrip(b"=").decode("ascii")
                if integrity_key is not None
                else None
            ),
            "integrity_key_id": integrity_key_id,
            "local_once_integrity_key_b64": (
                base64.urlsafe_b64encode(local_once_key).rstrip(b"=").decode("ascii")
                if local_once_key is not None
                else None
            ),
            "local_once_integrity_key_id": local_once_key_id,
        }
        bundle_identities = self._cached_policy_bundle_decision_identities(
            now=_parse_utc_timestamp(current_time).timestamp(),
        )
        if bundle_identities:
            request["policy_bundle_decision_identities"] = [
                [field for field in identity] for identity in bundle_identities
            ]

        response = _resident_request(
            operation="policy_decision_lookup",
            request=request,
            guard_home=self.guard_home,
            timeout_seconds=10.0,
            required_feature=POLICY_DECISION_LOOKUP_FEATURE,
            response_schema="guard-policy-decision-lookup-result.v1",
        )
        if response is None:
            raise ValueError("native_policy_decision_lookup_unavailable")
        if response.get("status") != "ok" or not isinstance(response.get("payload"), dict):
            # The native op encodes failures as status="error" + payload=<code>;
            # surface that code so callers can distinguish transport vs. store
            # errors, and never re-prefix an already-namespaced code.
            raw = response.get("code", response.get("payload"))
            code = raw if isinstance(raw, str) and raw else "failed"
            raise ValueError(
                code if code.startswith("native_policy_decision_lookup_") else f"native_policy_decision_lookup_{code}"
            )
        return cast("PolicyDecisionLookupResult", response["payload"])

    def resolve_policy_decision(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
    ) -> dict[str, object] | None:
        lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
        )
        return lookup["decision"]

    def claim_approval_reuse_decision(
        self,
        decision: Mapping[str, object],
        *,
        now: str | None = None,
    ) -> bool:
        """Atomically validate and claim an accepted saved ``allow`` decision.

        Returning ``False`` means the decision expired, changed, was consumed
        by another evaluator, or was not an approval ``allow``. Callers must
        then enforce the recomputed current action without saved evidence.
        """

        return self.claim_approval_reuse_decisions((decision,), now=now)

    def approval_reuse_claim_disposition(
        self,
        decision: Mapping[str, object],
    ) -> Literal["consumed", "retained"] | None:
        """Describe what a successful claim does to this selected allow.

        The resident decides; ``None`` means the row is not a claimable allow or
        the resident gave no authoritative answer, and callers must not claim.
        """

        return native_claim_disposition(decision, guard_home=getattr(self, "guard_home", None))

    def claim_approval_reuse_decisions(
        self,
        decisions: Sequence[Mapping[str, object]],
        *,
        now: str | None = None,
    ) -> bool:
        """Validate and claim a group of saved allows in one transaction.

        A compound launch (for example, an MCP tool call that also installs a
        package) may depend on more than one one-shot approval.  The launch is
        authorized only when every selected row still matches the authority
        revision observed during evaluation.  Any failed member rolls the
        entire group back so a denied launch cannot consume a sibling grant.

        The resident owns the whole decision: batch validation, the revision
        check, per-member integrity and identity checks, and the claim itself.
        This wrapper only procures the keyring-facing integrity evidence. No
        resident answer means no claim.
        """

        current_time = _canonical_utc_timestamp(now or _now())
        if not decisions:
            return True
        return native_claim_approval_reuse_decisions(
            store_path=self.path,
            guard_home=Path(self.guard_home),
            decisions=decisions,
            now=current_time,
            evidence=self._claim_integrity_evidence(decisions, current_time),
        )

    def _claim_integrity_evidence(
        self,
        decisions: Sequence[Mapping[str, object]],
        current_time: str,
    ) -> dict[str, object]:
        """Procure the integrity evidence the resident needs to claim ``decisions``."""

        evidence: dict[str, object] = {}
        needs_bundle = any(decision.get("source") == "policy-bundle" for decision in decisions)
        if any(isinstance(decision.get("approval_id"), str) and decision.get("approval_id") for decision in decisions):
            local_key, local_key_id = self._policy_integrity_secret_material(create=False)
            evidence["local_once_integrity_key_b64"] = encode_key(local_key)
            evidence["local_once_integrity_key_id"] = local_key_id
        if any(
            not (isinstance(decision.get("approval_id"), str) and decision.get("approval_id"))
            and isinstance(decision.get("source"), str)
            and not is_remote_policy_source(str(decision["source"]))
            for decision in decisions
        ):
            with self._connect() as connection:
                evidence["integrity_state"] = (
                    self._refresh_policy_integrity_state(connection, now=current_time, create_key=True) or {}
                )
            key, key_id = self._policy_integrity_secret_material(create=True)
            evidence["integrity_key_b64"] = encode_key(key)
            evidence["integrity_key_id"] = key_id
        # The evidence above is derived outside the claim's write lock. Name the
        # store-resident sources it depends on *before* deriving the bundle
        # identities, so anything that moves afterwards makes the resident refuse
        # the claim when it re-reads them under the lock.
        with self._connect() as connection:
            evidence["evidence_binding"] = claim_evidence_binding(
                connection,
                bundle=needs_bundle,
                cloud_workspace_id=self._cloud_workspace_id_from_connection(connection) if needs_bundle else None,
            )
        if needs_bundle:
            identities = self._cached_policy_bundle_decision_identities(
                now=_parse_utc_timestamp(current_time).timestamp(),
            )
            if identities:
                evidence["policy_bundle_decision_identities"] = [list(identity) for identity in identities]
        return evidence

    def approval_reuse_validation_reason(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        now: str | None = None,
    ) -> str | None:
        """Explain why otherwise relevant saved allow evidence did not match.

        The normal resolver intentionally returns only usable authority.  This
        read-only diagnostic pass is used after a miss so receipts can explain
        stale content/context without treating a near match as permission.
        """

        reason, _stored_hash = self.approval_reuse_diagnostic(
            harness,
            artifact_id,
            artifact_hash,
            workspace,
            publisher,
            now=now,
        )
        return reason

    def approval_reuse_diagnostic(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None,
        workspace: str | None,
        publisher: str | None,
        now: str | None = None,
    ) -> tuple[str | None, str | None]:
        """Diagnose a saved-allow miss and expose the matched row's hash.

        Returns ``(reason, stored_artifact_hash)``.  The stored hash is needed
        by emit layers that must distinguish a rejected approval bound to the
        current context-token contract from stale pre-token (legacy) evidence.

        The resident runs the bounded probes and picks the reason. This wrapper
        only procures integrity evidence when the resident asks for it. A store
        with no saved rows at all has nothing to diagnose and never needs the
        resident. When saved rows exist and the resident gives no authoritative
        answer (unprovisioned home, resident down, malformed reply) the miss
        fails closed: the saved allow is reported as rejected for an integrity
        failure and a typed warning is logged. Nothing is recomputed in Python
        and no exception reaches the caller.
        """

        if artifact_id is None:
            return None, None
        current_time = _canonical_utc_timestamp(now or _now())
        with self._connect() as connection:
            has_rows = (
                connection.execute(
                    "select 1 where exists (select 1 from policy_decisions) "
                    "or exists (select 1 from guard_local_once_approvals)"
                ).fetchone()
                is not None
            )
        if not has_rows:
            return None, None
        self._provision_resident_verifier()

        def evidence_provider(policy: bool, local_once: bool) -> dict[str, object]:
            evidence: dict[str, object] = {}
            if policy:
                with self._connect() as connection:
                    evidence["integrity_state"] = (
                        self._refresh_policy_integrity_state(connection, now=current_time, create_key=False) or {}
                    )
            if policy or local_once:
                key, key_id = self._policy_integrity_secret_material(create=False)
                prefix = "integrity" if policy else "local_once_integrity"
                evidence[f"{prefix}_key_b64"] = encode_key(key)
                evidence[f"{prefix}_key_id"] = key_id
                if policy and local_once:
                    evidence["local_once_integrity_key_b64"] = encode_key(key)
                    evidence["local_once_integrity_key_id"] = key_id
            return evidence

        try:
            return native_approval_reuse_diagnostic(
                store_path=self.path,
                guard_home=Path(self.guard_home),
                harness=harness,
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=current_time,
                evidence_provider=evidence_provider,
            )
        except ApprovalReuseDiagnosticUnavailableError as error:
            _LOGGER.warning(
                "%s: saved approvals exist but the native resident gave no authoritative diagnosis; "
                "treating the saved allow as rejected (%s)",
                error,
                APPROVAL_REUSE_DIAGNOSTIC_UNAVAILABLE_REASON,
            )
            return APPROVAL_REUSE_DIAGNOSTIC_UNAVAILABLE_REASON, None

    def _provision_resident_verifier(self) -> None:
        """Establish the verifier key the resident requires before it serves.

        Provisioning is O_EXCL and never replaces, so it is idempotent. A
        verifier that is malformed, foreign-owned, or mismatched is tampering
        evidence and is never silently degraded past.
        """

        key, _key_id = self._policy_integrity_secret_material(create=False)
        if key is None:
            return
        try:
            provision_native_policy_verifier_key(Path(self.guard_home), key)
        except NativePolicySnapshotError as error:
            if str(error) in {
                "native_policy_verifier_key_invalid",
                "native_policy_verifier_key_mismatch",
                "native_policy_verifier_key_not_private",
            }:
                raise
        except (OSError, RuntimeError, TypeError, ValueError):
            return

    @staticmethod
    def _normalized_policy_keys(decision: PolicyDecision) -> tuple[str | None, str | None, str | None, str | None]:
        if decision.scope in {"harness", "global"}:
            artifact_id = _artifact_family_key(decision.artifact_id)
        else:
            artifact_id = decision.artifact_id if decision.scope in {"artifact", "workspace"} else None
        artifact_hash = (
            decision.artifact_hash
            if decision.scope in {"artifact", "workspace"}
            or _is_runtime_scoped_exact_match_key(decision.artifact_hash)
            or _is_approval_context_token(decision.artifact_hash)
            else None
        )
        workspace = _workspace_policy_key(decision.workspace) if decision.scope == "workspace" else None
        publisher = decision.publisher if decision.scope == "publisher" else None
        return artifact_id, artifact_hash, workspace, publisher
