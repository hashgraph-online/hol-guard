"""Immutable enable candidates prepared before the existing approval transaction."""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, replace

from ..catalog_delivery import activation_store, activation_transition, lifecycle, lifecycle_store, preparation
from ..catalog_delivery.pack_store import decode
from ..catalog_delivery.preparation_authority import installed_bundle_type, load_installed_bundle
from ..runtime.extension_control_authority import layers_to_json
from ..runtime.extension_control_contract import (
    ControlLayerKind,
    ControlTargetKind,
    ExtensionControlLayer,
)
from ..runtime.extension_control_proof import ExtensionControlMutation
from ..runtime.generated_command_catalog import GeneratedCommandCatalog
from .extension_control_errors import ExtensionControlApiError
from .extension_control_preparation_failure import preparation_unavailable

MAX_CANDIDATES = 8
_REQUEST_FIELDS = ("previous_revision", "catalog_digest", "layers", "actor_id", "idempotency_key", "nonce")


def expired(candidates):
    """Ask the runtime which prepared candidates have outlived their admission."""

    if not candidates:
        return frozenset()
    response = lifecycle.invoke(
        "offline",
        operation="expired-leases",
        now=time.monotonic(),
        expires=[None if item is None else item.expires_at for item in candidates],
    )
    return frozenset(response["expired"])


def expire_leases(service):
    """Release expired preview cache leases using native unpin planning."""
    # Serialize with both preview and apply, including an apply that crossed its
    # original expiry check. Expired proof records keep their existing response.
    with service._preview_lock, service._apply_lock, service._proof_lock:
        candidates = list(service._candidates.values.values())
        candidates.extend(item.candidate for item in service._pending_proofs.values())
        for index in expired(candidates):
            candidates[index].draft._cache_lease.close()


def release_all_leases(service, *, timeout=5.0):
    """Release every prepared candidate's cache lease when the daemon stops.

    Process exit releases them too, but a daemon stopped inside a longer-lived
    process would otherwise keep the cache pinned, and on Windows an open lease
    file keeps the Guard home from being removed. The candidates are dropped
    with their leases, so none can be applied afterwards.
    """
    deadline = time.monotonic() + timeout
    held = []
    try:
        for lock in (service._preview_lock, service._apply_lock, service._proof_lock):
            if not lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
                return False
            held.append(lock)
        candidates = [*service._candidates.values.values()]
        candidates.extend(item.candidate for item in service._pending_proofs.values())
        service._candidates.values.clear()
        # A request worker that outlived the executor's bounded join must not
        # prepare a new leased candidate after this final release.
        service._candidates.closed = True
        service._pending_proofs.clear()
        for candidate in candidates:
            if candidate is not None:
                candidate.draft._cache_lease.close()
        return True
    finally:
        for lock in reversed(held):
            lock.release()


def request_digest(payload):
    return hashlib.sha256(
        json.dumps(
            {field: payload.get(field) for field in _REQUEST_FIELDS}, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class PreparedControlCandidate:
    mutation: ExtensionControlMutation
    registry: GeneratedCommandCatalog
    draft: activation_transition.ActivationDraft
    expires_at: float
    managed_layers: tuple[ExtensionControlLayer, ...]
    managed_revision: int


def _selection(layers, registry):
    owners = {
        control.target.target_id: registry.permission(control.target.target_id).extension_id
        for layer in layers
        for control in layer.controls
        if control.target.kind is ControlTargetKind.PERMISSION
    }
    result = lifecycle.invoke("selection", layers=json.loads(layers_to_json(layers)), owners=owners)
    return set(result["selected"]), set(result["retained"])


def prepare_candidate(store, registry, mutation, effective_layers, *, managed_revision=0):
    """No activation/control write and no mutation lease in this phase."""
    previous = activation_store.read(store)
    if previous is not None:
        from ..catalog_delivery.active_security import reconcile

        reconcile(store)
    installed = load_installed_bundle() if installed_bundle_type() else None
    if previous is None and installed is None:
        if lifecycle_store.read(store) is not None:
            lifecycle_store.inspect(store)
            raise ValueError("pack_lifecycle_pack_authority_unavailable")
        return None  # Legacy installation without release-bound pack capability.
    selected, retained = _selection(effective_layers, registry)
    captured_floor, floor = lifecycle_store.inspect(store)
    from ..native_command_control_authority_store import _key

    plan_input = dict(
        key=_key(store).hex(),
        floor=captured_floor,
        selected=sorted(selected),
        retained=sorted(retained),
        active=None if previous is None else sorted(previous.selected),
        active_engine=None if previous is None else previous.engine,
        registry=[] if previous is None else sorted(previous.registry_ids),
        installed=None if installed is None else lifecycle.installed_identity(installed),
    )
    plan = lifecycle.invoke("plan", **plan_input)
    if "lineage_source" in plan:
        plan = lifecycle.invoke("plan", **plan_input, ancestry=lifecycle.ancestry(floor, plan["lineage_source"]))
    if plan["profile"] == "committed-subset":
        if previous is None:
            raise ValueError("committed subset requires an existing activation")
        authority = previous
        engine = previous.engine
    elif plan["profile"] == "installed":
        if installed is None:
            raise ValueError("installed preparation authority is unavailable")
        authority = installed
        engine = installed.engine
    else:
        from ..catalog_delivery.transport import fetch_root

        authority = fetch_root(now=int(time.time()))
        engine = authority.manifest()["engine"]
    directory = previous.directory if previous is not None else activation_store.prepare_directory_for_store(store)
    if previous is not None and plan["profile"] != "committed-subset":
        from ..catalog_delivery.active_security import observe_preparation

        observe_preparation(store, authority)
    try:
        prepared = preparation.prepare(authority, selected, directory, engine=engine, retained_extension_ids=retained)
    except preparation.UnavailablePackError as error:
        lifecycle.invoke("fallback", profile=plan["profile"], reason=error.code)
        from ..catalog_delivery.transport import fetch_root

        authority = fetch_root(now=int(time.time()))
        engine = authority.manifest()["engine"]
        if previous is not None:
            from ..catalog_delivery.active_security import observe_preparation

            observe_preparation(store, authority)
        prepared = preparation.prepare(authority, selected, directory, engine=engine, retained_extension_ids=retained)
    candidate_registry = GeneratedCommandCatalog.from_prepared_packs(prepared)
    draft = activation_transition.stage(
        previous,
        prepared,
        verifier_key=_key(store),
        store=store,
        captured_floor=captured_floor,
        admission_floor=plan["admission_floor"],
    )
    layers = tuple(replace(layer, catalog_digest=candidate_registry.catalog_digest) for layer in mutation.layers)
    # The proof's exact mutation also binds the immutable activation record,
    # including authority/profile/root and program/catalog/trust identities.
    nonce = hashlib.sha256(
        json.dumps(
            [mutation.nonce, draft.digest, draft.lifecycle_before, draft.lifecycle_after, draft.security_digest],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    mapped = replace(mutation, catalog_digest=candidate_registry.catalog_digest, layers=layers, nonce=nonce)
    managed = tuple(layer for layer in effective_layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
    publication = decode(prepared._publication)
    lifetime = lifecycle.invoke(
        "admission",
        profile=prepared.authority_profile,
        now=time.time(),
        issued_at=publication.get("issued_at"),
        expires_at=publication.get("expires_at"),
    )["lifetime"]
    return PreparedControlCandidate(
        mapped, candidate_registry, draft, time.monotonic() + lifetime, managed, managed_revision
    )


class PreparedControlCandidates:
    def __init__(self):
        self.values: OrderedDict[str, PreparedControlCandidate] = OrderedDict()
        # Set once the daemon has released every lease; no candidate is prepared after.
        self.closed = False

    def get_or_prepare(self, key, factory):
        # Caller serializes preview preparation. No lock is held across apply.
        if self.closed:
            raise ExtensionControlApiError(503, "extension_control_stopped")
        keys = tuple(self.values)
        for index in expired(tuple(self.values[key] for key in keys)):
            del self.values[keys[index]]
        if key in self.values:
            self.values.move_to_end(key)
            return self.values[key]
        try:
            value = factory()
        except (ValueError, OSError) as exc:
            raise preparation_unavailable(exc, stage="candidate-preparation") from exc
        if value is not None:
            self.values[key] = value
            while len(self.values) > MAX_CANDIDATES:
                self.values.popitem(last=False)
        return value
