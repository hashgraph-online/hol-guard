"""Prepare installed policy outside the mutation lease; Rust authorizes commit."""

from __future__ import annotations

import json
from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import cast

from ..runtime.extension_control_authority import AuthorityPhase, layers_to_json
from ..runtime.extension_control_proof import ExtensionControlMutation
from ..runtime.generated_command_catalog import GeneratedCommandCatalog
from . import activation_store, active_security, lifecycle
from .cache_io import Lease

# Who hears the migration's own steps. Only the daemon's worker host sets it,
# for its first attempt: the daemon timestamps each step in its lifecycle
# journal, so a slow startup names the step that spent the time.
_STEP_REPORTER: ContextVar[Callable[[str], None] | None] = ContextVar(
    "installed_authority_migration_step_reporter", default=None
)


@contextmanager
def reporting_migration_steps(report: Callable[[str], None] | None) -> Generator[None]:
    """Send each ``report_migration_step`` inside this block to ``report``."""

    token = _STEP_REPORTER.set(report)
    try:
        yield
    finally:
        _STEP_REPORTER.reset(token)


def report_migration_step(step: str) -> None:
    """Tell the listening caller, if any, that a migration step finished."""

    report = _STEP_REPORTER.get()
    if report is not None:
        report(step)


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
        report_migration_step("authority_current")
        active_security.reconcile(store)
        report_migration_step("pack_security_reconciled")
        return
    # Finish an anchored replacement before preparing another one. A shared
    # read cannot resume the SQL/anchor journal after an interrupted startup.
    with store._extension_control_authority_lock():
        key = store._authority_key(required=True)
        anchor = store._read_anchor(key=key)
        if anchor is not None and anchor.phase is AuthorityPhase.ANCHORED:
            # The native resume plan authenticates the already-admitted
            # transition and its pack binding; no new approval is issued.
            store._resume_transition(anchor.revision, key=key)
        # The upgrade below plans from the activation's catalog. A runtime on
        # another catalog, such as an older install still running, may have
        # moved the authority head off it; reading with the activation's
        # registry lets the resident move the head back first. Without it the
        # migration source never matches and every startup fails.
        store._read_extension_control_authority_locked(
            previous.metadata.catalog_digest,
            migration_registry=GeneratedCommandCatalog.from_prepared_packs(previous),
        )
    report_migration_step("authority_recovered")
    previous = activation_store.read(store)
    if previous is None:
        raise ValueError("installed command pack activation missing after recovery")
    if previous.engine == installed.engine:
        active_security.reconcile(store)
        report_migration_step("pack_security_reconciled")
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
    from ..extension_controls.extension_control_prepared import prepare_candidate

    candidate = prepare_candidate(
        store, registry, mutation, effective.layers, managed_revision=effective.managed_revision
    )
    if candidate is None:
        raise ValueError("installed command pack upgrade candidate missing")
    report_migration_step("candidate_prepared")
    draft = candidate.draft
    try:
        evidence = {
            "release": lifecycle.release_evidence(installed),
            "candidate": {"record": draft.data, "digest": draft.digest, "mac": draft.mac},
            "floor": draft.lifecycle_before,
            "next_floor": draft.lifecycle_after,
            # The managed policy this candidate was prepared against. The
            # resident recomputes the same view and refuses the migration if
            # it moved.
            "managed": {
                "revision": candidate.managed_revision,
                "layers": json.loads(layers_to_json(candidate.managed_layers)),
            },
        }
        with store._extension_control_authority_lock():
            key = store._authority_key(required=True)
            # Validate/resume the authenticated head before advancing its anchor.
            store._read_extension_control_authority_locked(local.catalog_digest)
            row = activation_store.read_slot(store)
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
                current_manifest=store._catalog_target_manifest(registry),
            )
        report_migration_step("catalog_migrated")
        active_security.reconcile(store)
        report_migration_step("pack_security_reconciled")
    finally:
        cast(Lease, draft._cache_lease).close()
