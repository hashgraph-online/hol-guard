"""Trusted target manifests and authenticated catalog migrations."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from .native_extension_control_authority import (
    layers_from_wire,
    manifest_from_wire,
    manifest_sha256,
    view_to_wire,
)
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    AuthorityAnchor,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from .runtime.extension_control_contract import ExtensionControlLayer
from .store_extension_control_authority_catalog_events import (
    already_recorded,
    build_catalog_migration_payload,
    insert_catalog_migration_event,
)
from .store_extension_control_authority_support import _now, _plan_int, _plan_map, _plan_pack_digest, _plan_record


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
        allow_migration: bool = True,
    ) -> tuple[ExtensionControlAuthorityView, dict[str, str] | None]:
        """Compare the recorded manifest of this catalog with the current one.

        Returns the view to serve and the stale recorded manifest, which the
        caller replaces once managed controls are composed. The same catalog
        digest can carry a newer trusted contract fingerprint after a package
        update; the resident rebinds the local controls, and a writer commits
        that rebinding as a migration.
        """

        current = self._catalog_target_manifest(registry)
        fields: dict[str, object] = {
            "view": view_to_wire(view),
            "catalog_digest": registry.catalog_digest,
            "current_manifest_sha256": manifest_sha256(current),
            "allow_migration": allow_migration,
        }
        reply = self._extension_control_authority_op("sync_manifest", key=key, **fields)
        if reply.get("need") == "current_manifest":
            reply = self._extension_control_authority_op("sync_manifest", key=key, **fields, current_manifest=current)
        if reply.get("manifest_write") == "insert":
            self._write_catalog_manifest(registry, key=key, manifest=current)
            return view, None
        action = reply.get("action")
        if isinstance(action, dict):
            stale = manifest_from_wire(action.get("stale"))
            return self._migrate_extension_control_catalog(action, registry=registry, key=key), stale
        return self._view_from_wire(reply.get("view"), view.catalog_digest), manifest_from_wire(reply.get("stale"))

    def _write_catalog_manifest(
        self,
        registry: CommandSafetyExtensionRegistry,
        *,
        key: bytes,
        manifest: dict[str, str],
        replace: bool = False,
    ) -> None:
        sealed = self._extension_control_authority_op(
            "seal_manifest",
            key=key,
            catalog_digest=registry.catalog_digest,
            current_manifest=manifest,
            now=_now(),
        )
        record_json, record_digest, record_mac = _plan_record(sealed, "record")
        manifest_json, recorded_at = str(sealed["manifest_json"]), str(sealed["recorded_at"])
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
        reply = self._extension_control_authority_op("load_manifest", key=key, catalog_digest=catalog_digest)
        return manifest_from_wire(reply.get("manifest"))

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
        with self._connect() as connection:
            if already_recorded(connection, revision):
                return
            payload, regression = build_catalog_migration_payload(
                connection,
                previous_revision=previous_revision,
                revision=revision,
                previous_catalog_digest=previous_catalog_digest,
                catalog_digest=catalog_digest,
                layers=layers,
                retired_targets=retired_targets,
                registry=None,
                trigger="authority-read-backfill",
                writer=False,
            )
            insert_catalog_migration_event(
                connection,
                payload=payload,
                regression=regression,
                occurred_at=_now(),
                revision=revision,
                previous_catalog_digest=previous_catalog_digest,
                catalog_digest=catalog_digest,
            )

    def _migrate_extension_control_catalog(
        self,
        action: Mapping[str, object],
        *,
        registry: CommandSafetyExtensionRegistry,
        key: bytes,
        pack_activation=None,
        installed_upgrade: Mapping[str, object] | None = None,
    ) -> ExtensionControlAuthorityView:
        """Commit the rebinding the resident computed for a trusted catalog update."""

        self._invalidate_native_extension_control_policy()
        catalog_digest = registry.catalog_digest
        if action.get("catalog_digest") != catalog_digest:
            raise ExtensionControlAuthorityError("extension control catalog migration target changed")
        previous_revision = action.get("previous_revision")
        previous_catalog_digest = action.get("previous_catalog_digest")
        if type(previous_revision) is not int or not isinstance(previous_catalog_digest, str):
            raise ExtensionControlAuthorityError("invalid extension control catalog migration")
        layers = layers_from_wire(action.get("layers"))
        retired_targets = tuple(str(target) for target in cast(list[object], action.get("retired_targets") or []))
        migration = {
            "previous_revision": previous_revision,
            "previous_catalog_digest": previous_catalog_digest,
            "layers": action.get("layers"),
        }
        if installed_upgrade is not None:
            migration["installed_upgrade"] = installed_upgrade
        reply = self._extension_control_authority_op(
            "migrate_plan",
            key=key,
            catalog_digest=catalog_digest,
            now=_now(),
            catalog_migration=migration,
        )
        plan = _plan_map(reply, "plan")
        if plan.get("outcome") != "migrate":
            raise ExtensionControlAuthorityError("invalid extension control catalog migration")
        pack_digest = _plan_pack_digest(plan)
        if pack_digest != (pack_activation.digest if pack_activation is not None else None):
            raise ExtensionControlAuthorityError("installed command pack migration binding mismatch")
        revision = _plan_int(plan, "revision")
        previous_digest, created_at = str(plan["previous_digest"]), str(plan["created_at"])
        layers_json = str(plan["layers_json"])
        hashes = _plan_map(plan, "hashes")
        actor_hash, idempotency_hash, nonce_hash = (str(hashes[name]) for name in ("actor", "idempotency", "nonce"))
        snapshot_json, snapshot_digest, snapshot_mac = _plan_record(plan, "snapshot")
        transition_json, transition_digest, transition_mac = _plan_record(plan, "transition")
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
        self._write_and_verify_anchor(AuthorityAnchor(revision, snapshot_digest, AuthorityPhase.ANCHORED), key=key)
        with self._connect() as connection:
            if pack_activation is not None:
                from .catalog_delivery.activation_journal import finish

                pending = connection.execute(
                    "select * from extension_control_authority_transition where revision=?", (revision,)
                ).fetchone()
                finish(self, connection, pending, expected_pack=pack_digest)
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
                raise ExtensionControlAuthorityError("extension control catalog migration conflict")
            connection.execute(
                "update extension_control_authority_transition set phase = ?, committed_at = ? where revision = ?",
                (AuthorityPhase.COMMITTED.value, created_at, revision),
            )
            payload, regression = build_catalog_migration_payload(
                connection,
                previous_revision=previous_revision,
                revision=revision,
                previous_catalog_digest=previous_catalog_digest,
                catalog_digest=catalog_digest,
                layers=layers,
                retired_targets=retired_targets,
                registry=registry,
                trigger="catalog-migration",
                writer=True,
            )
            insert_catalog_migration_event(
                connection,
                payload=payload,
                regression=regression,
                occurred_at=created_at,
                revision=revision,
                previous_catalog_digest=previous_catalog_digest,
                catalog_digest=catalog_digest,
            )
        self._write_and_verify_anchor(AuthorityAnchor(revision, snapshot_digest, AuthorityPhase.COMMITTED), key=key)
        return self._read_extension_control_authority_locked(catalog_digest)
