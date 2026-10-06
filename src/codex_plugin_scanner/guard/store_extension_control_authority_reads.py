"""Authenticated authority reads and composition with managed controls."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from typing import cast

from .managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
    managed_controls_revision_from_state,
)
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    SNAPSHOT_PURPOSE,
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    layers_from_json,
    verify_authenticated_record,
)
from .runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
)
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_extension_control_authority_support import (
    _row_int,
    _row_str,
    preserve_managed_extension_control,
)


def _canonical_contract_value(value: object) -> object:
    from .store_extension_control_authority import _canonical_contract_value as canonical

    return canonical(value)


def _activation_layers(state, **kwargs):
    from .store_extension_control_authority import managed_controls_layers_from_activation_state

    return managed_controls_layers_from_activation_state(state, **kwargs)


class ExtensionControlAuthorityReadsMixin:
    _extension_control_last_catalog_digest: str = "0" * 64

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
        *,
        include_managed_controls: bool = True,
        read_only: bool = False,
    ) -> ExtensionControlAuthorityView:
        from .native_command_control_authority_io import NativeCommandControlMutationRequiredError

        catalog_digest = registry.catalog_digest
        self._extension_control_last_catalog_digest = catalog_digest
        try:
            self._catalog_target_manifest(registry)
            with self._extension_control_authority_lock(shared=read_only):
                self._require_compatible_extension_control_schema()
                view = self._read_extension_control_authority_locked(catalog_digest, migration_registry=registry)
                stale_manifest: dict[str, str] | None = None
                authority_key: bytes | None = None
                if view.health is AuthorityHealth.PROTECTED:
                    authority_key = self._authority_key(required=True)
                    if authority_key is None:
                        raise ExtensionControlAuthorityError("extension-control authority key is unavailable")
                    view, stale_manifest = self._sync_trusted_catalog_manifest(view, registry, key=authority_key)
                if include_managed_controls:
                    composed = self._with_managed_controls_activation(
                        view,
                        current_manifest=self._catalog_target_manifest(registry),
                        previous_manifest=stale_manifest,
                    )
                else:
                    composed = view
                if stale_manifest is not None:
                    if authority_key is None:
                        raise ExtensionControlAuthorityError("extension-control authority key is unavailable")
                    self._write_catalog_manifest(
                        registry,
                        key=authority_key,
                        manifest=self._catalog_target_manifest(registry),
                        replace=True,
                    )
                return composed
        except NativeCommandControlMutationRequiredError:
            raise
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)
        except Exception:
            return self._degraded_view(catalog_digest)

    def _with_managed_controls_activation(
        self,
        view: ExtensionControlAuthorityView,
        *,
        current_manifest: Mapping[str, str] | None = None,
        previous_manifest: Mapping[str, str] | None = None,
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
        local_layers = tuple(layer for layer in view.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
        if active is None or active == {}:
            if revision_state is None or revision_state == {}:
                return view
            key = self._authority_key(required=True)
            assert key is not None
            managed_revision = managed_controls_revision_from_state(
                revision_state,
                authority_key=key,
            )
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
        if not isinstance(active, dict):
            raise ExtensionControlAuthorityError("invalid managed controls activation state")
        active_catalog_digest = active.get("catalogDigest")
        if not isinstance(active_catalog_digest, str) or not active_catalog_digest:
            raise ExtensionControlAuthorityError("invalid managed controls activation catalog")
        managed_layers, managed_revision = _activation_layers(
            active,
            catalog_digest=active_catalog_digest,
            authority_key=key,
        )
        fingerprint_refresh = (
            current_manifest is not None
            and previous_manifest is not None
            and previous_manifest != current_manifest
            and active_catalog_digest == view.catalog_digest
        )
        if active_catalog_digest != view.catalog_digest or fingerprint_refresh:
            if any(layer.catalog_digest != active_catalog_digest for layer in managed_layers):
                raise ExtensionControlAuthorityError("managed controls activation layer catalog mismatch")
            if current_manifest is None:
                raise ExtensionControlAuthorityError("managed controls current catalog manifest is missing")
            # A missing prior manifest must not act as an implicit fingerprint
            # match: stale managed allows remain disabled until cloud refresh.
            if fingerprint_refresh:
                if previous_manifest is None:
                    raise ExtensionControlAuthorityError("managed controls current catalog manifest is missing")
                prior_manifest: Mapping[str, str] = previous_manifest
            else:
                prior_manifest = self._load_catalog_manifest(active_catalog_digest, key=key) or {}
            managed_layers = tuple(
                replace(
                    layer,
                    catalog_digest=view.catalog_digest,
                    controls=tuple(
                        (
                            control
                            if preserve_managed_extension_control(
                                control,
                                previous_manifest=prior_manifest,
                                current_manifest=current_manifest,
                            )
                            else replace(control, state=ControlState.DISABLED)
                        )
                        for control in layer.controls
                    ),
                )
                for layer in managed_layers
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
            _activation_layers(
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

    def _read_extension_control_authority_locked(
        self,
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
    ) -> ExtensionControlAuthorityView:
        with self._connect() as connection:
            if not ensure_extension_control_authority_schema(connection, require_compatible=False):
                return self._degraded_view(catalog_digest)
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
                pending = self._pending_transition(revision + 1)
                if pending is not None and _row_str(pending, "catalog_digest") == catalog_digest:
                    with self._connect() as connection:
                        resumed = self._resume_idempotent_transition(
                            connection,
                            pending,
                            current=ExtensionControlAuthorityView(
                                AuthorityHealth.RECOVERY_REQUIRED,
                                revision,
                                stored_catalog_digest,
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
            self._ensure_catalog_migrated_event(
                revision=revision,
                catalog_digest=catalog_digest,
                layers=layers,
            )
            return ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, revision, catalog_digest, layers)
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)
