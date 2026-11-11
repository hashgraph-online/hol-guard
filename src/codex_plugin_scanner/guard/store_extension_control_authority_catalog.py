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
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from .runtime.extension_control_contract import ExtensionControlLayer
from .store_extension_control_authority_catalog_events import (
    already_recorded,
    migration_provenance,
    recorded_writer_version,
)
from .store_extension_control_authority_support import _now


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
        self._invalidate_native_extension_control_policy()
        reply = self._extension_control_authority_op(
            "write_manifest",
            key=key,
            catalog_digest=registry.catalog_digest,
            current_manifest=manifest,
            now=_now(),
            manifest_replace=replace,
        )
        if reply.get("written") is not True:
            raise ExtensionControlAuthorityError("extension control catalog manifest conflict")

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
        described, downgraded_from = migration_provenance(
            None,
            catalog_digest,
            registry=None,
            trigger="authority-read-backfill",
            writer=False,
            guard_home=self.guard_home,
        )
        # The resident takes the migration from the committed head again and
        # writes its event once, in one transaction.
        self._extension_control_authority_op(
            "record_migration",
            key=None,
            catalog_digest=catalog_digest,
            revision=revision,
            now=_now(),
            migration_record={
                "provenance": described,
                "retired_target_ids": [],
                **({} if downgraded_from is None else {"downgraded_from": downgraded_from}),
            },
        )

    def _migrate_catalog_in_resident(
        self,
        request: dict[str, object],
        *,
        key: bytes,
        previous_catalog_digest: str,
        retired_targets: tuple[str, ...],
        registry: CommandSafetyExtensionRegistry,
        pack_activation=None,
    ) -> ExtensionControlAuthorityView:
        """Have the resident commit a migration.

        A migration that activates a command pack comes back ``pack_bound``
        once its row is anchored; the resident then finishes it with the
        protected pack state and records the migration as it commits the row.
        """

        catalog_digest = str(request["catalog_digest"])
        with self._connect() as connection:
            previous_writer_version = recorded_writer_version(connection, previous_catalog_digest)
        described, downgraded_from = migration_provenance(
            previous_writer_version,
            catalog_digest,
            registry,
            trigger="catalog-migration",
            writer=True,
            guard_home=self.guard_home,
        )
        # An absent downgrade is omitted, as the resident re-encodes it when it
        # binds the reply to this request.
        migration_record = {
            "provenance": described,
            **({"downgraded_from": downgraded_from} if downgraded_from is not None else {}),
            "retired_target_ids": list(retired_targets),
        }
        pack_reserve: dict[str, object] = {}
        if pack_activation is not None:
            from .catalog_delivery.activation_journal import reserve_request

            with self._connect() as connection:
                pack_reserve["pack_reserve"] = reserve_request(
                    self, connection, pack_activation, recorded_at=str(request["now"])
                )
        reply = self._extension_control_authority_op(
            "migrate", key=key, **request, **pack_reserve, migration_record=migration_record
        )
        if reply.get("pack_bound") is True:
            revision = reply.get("revision")
            anchored = reply.get("anchor_json")
            if type(revision) is not int or not isinstance(anchored, str):
                raise ExtensionControlAuthorityError("invalid extension control catalog migration")
            self._mirror_resident_anchor(anchored)
            reply = self._resume_extension_control_op(
                revision,
                key=key,
                now=str(request["now"]),
                catalog_digest=catalog_digest,
                catalog_migration=request["catalog_migration"],
                migration_record=migration_record,
            )
        migrated = reply.get("resumed")
        sealed = reply.get("anchor_json")
        if not isinstance(migrated, dict) or migrated.get("catalog_digest") != catalog_digest:
            raise ExtensionControlAuthorityError("invalid extension control catalog migration")
        if not isinstance(sealed, str):
            raise ExtensionControlAuthorityError("invalid extension control anchor seal")
        self._mirror_resident_anchor(sealed)
        return self._read_extension_control_authority_locked(catalog_digest)

    def _migrate_extension_control_catalog(
        self,
        action: Mapping[str, object],
        *,
        registry: CommandSafetyExtensionRegistry,
        key: bytes,
        pack_activation=None,
        installed_upgrade: Mapping[str, object] | None = None,
        current_manifest: Mapping[str, str] | None = None,
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
        layers_from_wire(action.get("layers"))
        retired_targets = tuple(str(target) for target in cast(list[object], action.get("retired_targets") or []))
        migration = {
            "previous_revision": previous_revision,
            "previous_catalog_digest": previous_catalog_digest,
            "layers": action.get("layers"),
        }
        if installed_upgrade is not None:
            migration["installed_upgrade"] = installed_upgrade
        request: dict[str, object] = {
            "catalog_digest": catalog_digest,
            "now": _now(),
            "catalog_migration": migration,
            # An installed upgrade asks the resident to recompute the managed
            # policy of the authority head, which needs its anchor and the
            # manifest of the catalog that head is bound to.
            "anchor_json": self._read_anchor_json(),
            "current_manifest": dict(current_manifest) if current_manifest is not None else None,
        }
        return self._migrate_catalog_in_resident(
            request,
            key=key,
            previous_catalog_digest=previous_catalog_digest,
            retired_targets=retired_targets,
            registry=registry,
            pack_activation=pack_activation,
        )
