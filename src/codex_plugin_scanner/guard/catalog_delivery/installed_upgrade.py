"""Prepare installed policy outside the mutation lease; Rust authorizes commit."""

from __future__ import annotations

import json
from typing import cast

from ..runtime.extension_control_authority import (
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
    layers_to_json,
)
from ..runtime.extension_control_contract import ControlLayerKind
from ..runtime.extension_control_proof import ExtensionControlMutation
from ..runtime.generated_command_catalog import GeneratedCommandCatalog
from . import activation_store, active_security, lifecycle
from .cache_io import Lease


@lifecycle.one_runtime
def migrate_active(store, installed):
    with store._extension_control_authority_lock(shared=True):
        previous = activation_store.read(store)
        if previous is None:
            return
        key = store._authority_key(required=True)
        anchor = store._read_anchor(key=key)
        current = (
            previous.engine == installed.engine and anchor is not None and anchor.phase is AuthorityPhase.COMMITTED
        )
    if current:
        active_security.reconcile(store)
        return
    # Finish an anchored replacement before preparing another one. A shared
    # read cannot resume the SQL/anchor journal after an interrupted startup.
    with store._extension_control_authority_lock():
        key = store._authority_key(required=True)
        anchor = store._read_anchor(key=key)
        if anchor is not None and anchor.phase is AuthorityPhase.ANCHORED:
            with store._connect() as connection:
                # The native resume plan authenticates the already-admitted
                # transition and its pack binding; no new approval is issued.
                store._resume_transition(connection, anchor.revision, key=key)
        store._read_extension_control_authority_locked(previous.metadata.catalog_digest)
    previous = activation_store.read(store)
    if previous is None:
        raise ValueError("installed command pack activation missing after recovery")
    if previous.engine == installed.engine:
        active_security.reconcile(store)
        return
    registry = GeneratedCommandCatalog.from_prepared_packs(previous)
    local = store.read_extension_control_authority_for_registry(
        registry, include_managed_controls=False, read_only=True
    )
    effective = store.read_extension_control_authority_for_registry(registry, read_only=True)
    mutation = ExtensionControlMutation(
        previous_revision=local.revision,
        catalog_digest=local.catalog_digest,
        layers=local.layers,
        actor_id="installed-release-upgrade",
        idempotency_key=previous.record_digest,
        nonce=previous.record_digest,
    )
    from ..daemon.extension_control_prepared import prepare_candidate

    candidate = prepare_candidate(
        store, registry, mutation, effective.layers, managed_revision=effective.managed_revision
    )
    if candidate is None:
        raise ValueError("installed command pack upgrade candidate missing")
    draft = candidate.draft
    try:
        evidence = {
            "release": lifecycle.release_evidence(installed),
            "candidate": {"record": draft.data, "digest": draft.digest, "mac": draft.mac},
            "floor": draft.lifecycle_before,
            "next_floor": draft.lifecycle_after,
        }
        with store._extension_control_authority_lock():
            key = store._authority_key(required=True)
            # Validate/resume the authenticated head before advancing its anchor.
            current = store._read_extension_control_authority_locked(local.catalog_digest)
            current = store._with_managed_controls_activation(
                current, current_manifest=store._catalog_target_manifest(registry)
            )
            if (
                current.health is not AuthorityHealth.PROTECTED
                or current.managed_revision != candidate.managed_revision
                or tuple(layer for layer in current.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
                != candidate.managed_layers
            ):
                raise ExtensionControlAuthorityError("managed policy changed before installed upgrade")
            with store._connect() as connection:
                row = activation_store._row(connection)
                if row is None:
                    raise ValueError("installed command pack activation missing before commit")
                evidence["previous"] = {
                    "record": row["record_json"],
                    "digest": row["record_digest"],
                    "mac": row["record_mac"],
                }
            target = candidate.registry
            if store._load_catalog_manifest(target.catalog_digest, key=key) is None:
                store._write_catalog_manifest(target, key=key, manifest=store._catalog_target_manifest(target))
            store._migrate_extension_control_catalog(
                {
                    "previous_revision": local.revision,
                    "previous_catalog_digest": local.catalog_digest,
                    "catalog_digest": target.catalog_digest,
                    "layers": json.loads(layers_to_json(candidate.mutation.layers)),
                },
                registry=target,
                key=key,
                pack_activation=draft,
                installed_upgrade=evidence,
            )
        active_security.reconcile(store)
    finally:
        cast(Lease, draft._cache_lease).close()
