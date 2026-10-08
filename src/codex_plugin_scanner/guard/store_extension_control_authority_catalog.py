"""Trusted target manifests and authenticated catalog migrations."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import json
from dataclasses import replace

from .runtime.command_dns_control_migration import expand_legacy_dns_layers
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    SNAPSHOT_PURPOSE,
    TRANSITION_PURPOSE,
    AuthorityAnchor,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    authenticated_record,
    layers_from_json,
    layers_to_json,
    verify_authenticated_record,
)
from .runtime.extension_control_contract import (
    ExtensionControl,
    ExtensionControlLayer,
)
from .store_extension_control_authority_support import (
    _now,
    _private_hash,
    _row_int,
    _row_str,
    preserve_migrated_extension_control,
)


def _canonical_contract_value(value: object) -> object:
    from .store_extension_control_authority import _canonical_contract_value as canonical

    return canonical(value)


class ExtensionControlAuthorityCatalogMixin:
    @staticmethod
    def _catalog_target_manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
        from .store_extension_control_manifest import catalog_target_manifest

        return catalog_target_manifest(registry)

    def _sync_trusted_catalog_manifest(
        self,
        view: ExtensionControlAuthorityView,
        registry: CommandSafetyExtensionRegistry,
        *,
        key: bytes,
    ) -> tuple[ExtensionControlAuthorityView, dict[str, str] | None]:
        current = self._catalog_target_manifest(registry)
        with self._connect() as connection:
            existing = connection.execute(
                "select 1 from extension_control_catalog_manifest where catalog_digest = ?",
                (registry.catalog_digest,),
            ).fetchone()
        if existing is None:
            self._write_catalog_manifest(registry, key=key, manifest=current)
            return view, None
        persisted = self._load_catalog_manifest(registry.catalog_digest, key=key)
        if persisted is None:
            raise ExtensionControlAuthorityError("extension control catalog manifest conflict")
        if persisted == current:
            return view, None
        # Same catalog digest can still carry a newer trusted contract fingerprint
        # after a package update. Rebind local controls when needed, then let the
        # caller replace the stored manifest after managed layers are composed.
        rebound = tuple(
            replace(
                layer,
                catalog_digest=view.catalog_digest,
                controls=tuple(
                    control
                    for control in layer.controls
                    if preserve_migrated_extension_control(
                        control,
                        previous_manifest=persisted,
                        current_manifest=current,
                    )
                ),
            )
            for layer in view.layers
        )
        if rebound != view.layers:
            view = self._migrate_extension_control_catalog(view, registry=registry, key=key)
        return view, persisted

    def _write_catalog_manifest(
        self,
        registry: CommandSafetyExtensionRegistry,
        *,
        key: bytes,
        manifest: dict[str, str],
        replace: bool = False,
    ) -> None:
        manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
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
        self._invalidate_native_extension_control_policy()
        with self._connect() as connection:
            if replace:
                connection.execute(
                    """
                    update extension_control_catalog_manifest
                    set manifest_json = ?, record_json = ?, record_digest = ?, record_mac = ?, recorded_at = ?
                    where catalog_digest = ?
                    """,
                    (
                        manifest_json,
                        record_json,
                        record_digest,
                        record_mac,
                        recorded_at,
                        registry.catalog_digest,
                    ),
                )
                if connection.execute("select changes()").fetchone()[0] != 1:
                    raise ExtensionControlAuthorityError("extension control catalog manifest conflict")
                return
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

    def _ensure_catalog_migrated_event(
        self,
        *,
        revision: int,
        catalog_digest: str,
        layers: tuple[ExtensionControlLayer, ...],
    ) -> None:
        if revision < 1:
            return
        with self._connect() as connection:
            current = connection.execute(
                "select previous_revision, catalog_digest, layers_json from extension_control_authority_transition "
                "where revision = ?",
                (revision,),
            ).fetchone()
            if current is None or _row_str(current, "catalog_digest") != catalog_digest:
                return
            previous_revision = _row_int(current, "previous_revision")
            previous = connection.execute(
                "select catalog_digest, layers_json from extension_control_authority_transition where revision = ?",
                (previous_revision,),
            ).fetchone()
            if previous is None:
                return
            previous_catalog_digest = _row_str(previous, "catalog_digest")
            if previous_catalog_digest == catalog_digest:
                return
            previous_target_ids = {
                control.target.target_id
                for layer in layers_from_json(_row_str(previous, "layers_json"))
                for control in layer.controls
            }
        current_target_ids = {control.target.target_id for layer in layers for control in layer.controls}
        self._record_catalog_migrated_event_once(
            previous_revision=previous_revision,
            revision=revision,
            previous_catalog_digest=previous_catalog_digest,
            catalog_digest=catalog_digest,
            layers=layers,
            retired_targets=tuple(sorted(previous_target_ids - current_target_ids)),
        )

    def _record_catalog_migrated_event_once(
        self,
        *,
        previous_revision: int,
        revision: int,
        previous_catalog_digest: str,
        catalog_digest: str,
        layers: tuple[ExtensionControlLayer, ...],
        retired_targets: tuple[str, ...],
    ) -> None:
        payload = json.dumps(
            {
                "previous_revision": previous_revision,
                "revision": revision,
                "previous_catalog_digest": previous_catalog_digest,
                "catalog_digest": catalog_digest,
                "layer_count": len(layers),
                "control_count": sum(len(layer.controls) for layer in layers),
                "retired_target_count": len(retired_targets),
                "retired_target_ids": list(retired_targets),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._connect() as connection:
            existing = connection.execute(
                "select payload_json from guard_events where event_name = ?",
                ("extension_control_authority_catalog_migrated",),
            ).fetchall()
            for row in existing:
                try:
                    recorded = json.loads(str(row["payload_json"]))
                except json.JSONDecodeError:
                    continue
                if isinstance(recorded, dict) and recorded.get("revision") == revision:
                    return
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
                ("extension_control_authority_catalog_migrated", payload, _now()),
            )

    def _migrate_extension_control_catalog(
        self,
        previous: ExtensionControlAuthorityView,
        *,
        registry: CommandSafetyExtensionRegistry,
        key: bytes,
    ) -> ExtensionControlAuthorityView:
        """Rebind authenticated controls to a trusted built-in catalog update."""

        self._invalidate_native_extension_control_policy()
        catalog_digest = registry.catalog_digest
        previous_manifest = self._load_catalog_manifest(previous.catalog_digest, key=key) or {}
        current_manifest = self._catalog_target_manifest(registry)
        previous = replace(previous, layers=expand_legacy_dns_layers(previous.layers))

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
