"""Atomic policy-bundle authority activation and clearing."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING

from .runtime.extension_control_authority import ExtensionControlAuthorityView
from .store_base import ApprovalGateGrant, PolicyDecision
from .store_custom_extension_continuity import CustomExtensionContinuityMutation

if TYPE_CHECKING:
    from .managed_controls_policy_fields import ParsedManagedControlsPolicy


class StorePolicyMixin:
    def apply_policy_bundle_authority(
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
        require_native_source_binding: bool = False,
    ) -> dict[str, object] | None:
        """Atomically activate one authenticated policy bundle and its rows.

        The cached bundle is itself enforcement authority because policy
        defaults are read directly from it.  It must therefore become current
        in one transaction with every materialized decision, exception, acknowledgement, and trust checkpoint.
        Preparing and JSON-encoding all inputs before the write transaction
        also guarantees malformed rule expiry or payload data cannot leave a
        partially activated bundle behind.
        """
        from . import store_policy as _policy

        def reject(
            reason: str,
            connection: _policy.sqlite3.Connection | None = None,
        ) -> None:
            if connection is not None:
                connection.rollback()
            if raise_on_rejection:
                raise _policy.PolicyBundleActivationRejectionError(reason)
            return None

        normalized_now, rows = self._prepared_remote_policy_rows(
            decisions,
            now,
            approval_gate_grant=approval_gate_grant,
            remote_write_authorized=remote_write_authorized,
        )
        payload_rejection, encoded_payloads = _policy.encoded_policy_activation_payloads(
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
            continuity_rejection = _policy.continuity_activation_rejection(
                custom_extension_continuity,
                protected_authority=managed_base_authority.health is _policy.AuthorityHealth.PROTECTED,
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
                if managed_base_authority.health is not _policy.AuthorityHealth.PROTECTED:
                    return reject("managed_controls_authority_unprotected", connection)
                if managed_base_snapshot is None:
                    return reject("managed_controls_authority_snapshot_missing", connection)
                managed_authority_key = self._authority_key(required=True)
                if managed_authority_key is None:
                    return reject("managed_controls_authority_key_unavailable", connection)
            checkpoint_rejection = _policy.policy_checkpoint_rejection(connection, policy_bundle)
            if checkpoint_rejection is not None:
                return reject(checkpoint_rejection, connection)
            active_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (_policy.MANAGED_CONTROLS_ACTIVE_STATE_KEY,),
            ).fetchone()
            revision_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (_policy.MANAGED_CONTROLS_REVISION_STATE_KEY,),
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
                    revision_state = _policy.json.loads(str(revision_row["payload_json"]))
                    previous_revision = _policy.managed_controls_revision_from_state(
                        revision_state,
                        authority_key=managed_authority_key,
                    )
                except (_policy.json.JSONDecodeError, _policy.ExtensionControlAuthorityError):
                    return reject("managed_controls_revision_state_invalid", connection)
            if active_row is not None:
                assert managed_base_authority is not None
                assert managed_authority_key is not None
                try:
                    previous_active = _policy.json.loads(str(active_row["payload_json"]))
                    active_managed_layers, active_revision = _policy.managed_controls_layers_from_activation_state(
                        previous_active,
                        catalog_digest=managed_base_authority.catalog_digest,
                        authority_key=managed_authority_key,
                    )
                except (_policy.json.JSONDecodeError, _policy.ExtensionControlAuthorityError):
                    return reject("managed_controls_activation_state_invalid", connection)
                if revision_row is not None and active_revision != previous_revision:
                    return reject("managed_controls_revision_state_mismatch", connection)
                previous_revision = active_revision
                previous_bundle_hash = previous_active.get("bundleHash")
            if managed_controls_delivery is not None:
                if managed_controls_policy is None or managed_base_authority is None:
                    return reject("managed_controls_delivery_policy_missing", connection)
                current_authority = _policy.composed_managed_authority(
                    managed_base_authority,
                    managed_layers=active_managed_layers,
                    managed_revision=previous_revision,
                )
                if not _policy.managed_delivery_matches_base(
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
                managed_state = _policy.build_managed_controls_activation_state(
                    dict(policy_bundle),
                    managed_controls_policy,
                    base_authority=managed_base_authority,
                    managed_revision=managed_revision,
                    negotiated_capabilities=managed_controls_negotiated_capabilities,
                    authority_key=managed_authority_key,
                    base_snapshot_digest=managed_base_snapshot[1],
                )
                encoded_payloads[_policy.MANAGED_CONTROLS_ACTIVE_STATE_KEY] = _policy.json.dumps(
                    managed_state,
                    allow_nan=False,
                )
                encoded_payloads[_policy.MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY] = _policy.json.dumps(
                    sorted(managed_controls_negotiated_capabilities),
                    allow_nan=False,
                )
                encoded_payloads[_policy.MANAGED_CONTROLS_REVISION_STATE_KEY] = _policy.json.dumps(
                    _policy.build_managed_controls_revision_state(
                        managed_revision,
                        authority_key=managed_authority_key,
                    ),
                    allow_nan=False,
                )
                if update_last_good:
                    encoded_payloads[_policy.MANAGED_CONTROLS_LAST_GOOD_STATE_KEY] = _policy.json.dumps(
                        managed_state,
                        allow_nan=False,
                    )
            else:
                managed_revision = previous_revision + 1 if active_row is not None else previous_revision
                if managed_revision > 0:
                    assert managed_authority_key is not None
                    encoded_payloads[_policy.MANAGED_CONTROLS_REVISION_STATE_KEY] = _policy.json.dumps(
                        _policy.build_managed_controls_revision_state(
                            managed_revision,
                            authority_key=managed_authority_key,
                        ),
                        allow_nan=False,
                    )
                connection.execute(
                    "delete from sync_state where state_key in (?, ?)",
                    (
                        _policy.MANAGED_CONTROLS_ACTIVE_STATE_KEY,
                        _policy.MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY,
                    ),
                )
            published_authority = None
            if managed_controls_policy is not None or managed_controls_publish is not None:
                assert managed_base_authority is not None
                published_authority = _policy.published_managed_authority(
                    managed_base_authority,
                    policy=managed_controls_policy,
                    managed_revision=managed_revision,
                )
            if managed_controls_delivery is not None:
                if published_authority is None:
                    return reject("managed_controls_delivery_authority_missing", connection)
                try:
                    encoded_payloads["policy_bundle_ack"] = _policy.encoded_delivery_acknowledgement(
                        connection,
                        delivery=managed_controls_delivery,
                        policy_bundle=policy_bundle,
                        published_authority=published_authority,
                        observed_at=normalized_now,
                    )
                except (_policy.json.JSONDecodeError, TypeError, ValueError):
                    return reject("managed_controls_delivery_ack_invalid", connection)
            continuity_rejection = _policy.apply_continuity_rejection(
                connection,
                custom_extension_continuity,
                boundary=self._custom_extension_continuity_transaction_boundary,
            )
            if continuity_rejection is not None:
                return reject(continuity_rejection, connection)
            from .policy_bundle_materialization import PolicyBundleMaterializationError, PolicyMaterializationStore
            from .policy_bundle_staging import bind_staged_policy_rows

            try:
                rows = bind_staged_policy_rows(
                    _policy.cast(PolicyMaterializationStore, _policy.cast(object, self)),
                    connection,
                    decisions=decisions,
                    rows=rows,
                    now=normalized_now,
                    encoded_payloads=encoded_payloads,
                    require_source_binding=require_native_source_binding,
                )
            except _policy.PolicyCompilationError:
                return reject("policy_bundle_staging_invalid", connection)
            except PolicyBundleMaterializationError:
                return reject("policy_bundle_materialization_unavailable", connection)
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
        _policy.notify_native_policy_mutation(self.guard_home, require_source_authority=True)
        persisted_acknowledgement = _policy.json.loads(encoded_payloads["policy_bundle_ack"])
        return persisted_acknowledgement if isinstance(persisted_acknowledgement, dict) else None

    def clear_policy_bundle_authority(
        self,
        now: str,
        *,
        policy_bundle_last_error: Mapping[str, object],
        managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
    ) -> None:
        """Atomically remove all cached and materialized remote authority."""
        from . import store_policy as _policy

        normalized_now = _policy._canonical_utc_timestamp(now)
        state_payloads: dict[str, object] = {
            "cloud_exceptions": [],
            "policy": {},
            "policy_bundle_last_error": dict(policy_bundle_last_error),
            "team_policy_pack": {},
        }
        encoded_payloads = {
            state_key: _policy.json.dumps(payload, allow_nan=False) for state_key, payload in state_payloads.items()
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
                    raise _policy.ExtensionControlAuthorityError("extension control authority changed during clear")
            active_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (_policy.MANAGED_CONTROLS_ACTIVE_STATE_KEY,),
            ).fetchone()
            revision_row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (_policy.MANAGED_CONTROLS_REVISION_STATE_KEY,),
            ).fetchone()
            managed_revision = 0
            managed_authority_key = None
            if active_row is not None or revision_row is not None:
                managed_authority_key = self._authority_key(required=True)
                if managed_authority_key is None:
                    raise _policy.ExtensionControlAuthorityError("managed controls authority key is unavailable")
            if revision_row is not None:
                assert managed_authority_key is not None
                try:
                    revision_state = _policy.json.loads(str(revision_row["payload_json"]))
                    managed_revision = _policy.managed_controls_revision_from_state(
                        revision_state,
                        authority_key=managed_authority_key,
                    )
                except (_policy.json.JSONDecodeError, _policy.ExtensionControlAuthorityError) as exc:
                    connection.rollback()
                    raise _policy.ExtensionControlAuthorityError("invalid managed controls revision") from exc
            if active_row is not None:
                assert managed_authority_key is not None
                try:
                    previous_active = _policy.json.loads(str(active_row["payload_json"]))
                    active_catalog_digest = (
                        previous_active.get("catalogDigest") if isinstance(previous_active, dict) else None
                    )
                    if not isinstance(active_catalog_digest, str) or not active_catalog_digest:
                        raise _policy.ExtensionControlAuthorityError("invalid managed controls activation catalog")
                    _, active_revision = _policy.managed_controls_layers_from_activation_state(
                        previous_active,
                        catalog_digest=active_catalog_digest,
                        authority_key=managed_authority_key,
                    )
                except (_policy.json.JSONDecodeError, _policy.ExtensionControlAuthorityError) as exc:
                    connection.rollback()
                    raise _policy.ExtensionControlAuthorityError("invalid managed controls activation") from exc
                if revision_row is not None and active_revision != managed_revision:
                    connection.rollback()
                    raise _policy.ExtensionControlAuthorityError("managed controls revision mismatch")
                managed_revision = active_revision + 1
            if managed_revision > 0:
                assert managed_authority_key is not None
                encoded_payloads[_policy.MANAGED_CONTROLS_REVISION_STATE_KEY] = _policy.json.dumps(
                    _policy.build_managed_controls_revision_state(
                        managed_revision,
                        authority_key=managed_authority_key,
                    ),
                    allow_nan=False,
                )
            self._replace_remote_policy_rows_locked(connection, ())
            connection.execute(
                "delete from sync_state where state_key in (?, ?, ?, ?, ?)",
                (
                    "policy_bundle",
                    "policy_bundle_ack",
                    "policy_bundle_materialization",
                    _policy.MANAGED_CONTROLS_ACTIVE_STATE_KEY,
                    _policy.MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY,
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
                    layer
                    for layer in managed_base_authority.layers
                    if layer.kind is _policy.ControlLayerKind.LOCAL_ADMIN
                )
                managed_controls_publish(
                    _policy.ExtensionControlAuthorityView(
                        managed_base_authority.health,
                        managed_base_authority.revision,
                        managed_base_authority.catalog_digest,
                        local_layers,
                        managed_revision,
                    ),
                    connection.commit,
                )

        _policy.notify_native_policy_mutation(self.guard_home, require_source_authority=True)
