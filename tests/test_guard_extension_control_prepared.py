"""Real daemon proofs/anchors with synthetic transport and native admission."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_store, activation_transition, preparation, transport
from codex_plugin_scanner.guard.daemon import extension_control_prepared as candidates
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiError, ExtensionControlApiService
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    require_exclusive_command_control_mutation_lease,
)
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import layers_to_json
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from tests.guard_extension_control_authority_fixtures import _PASSWORD, MemorySecretStore, _proof, _store
from tests.guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_installed_profile import installed as installed
from tests.test_extension_pack_preparation import delivery as delivery
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)


@pytest.fixture
def flow(delivery, tmp_path, monkeypatch):
    store = _store(tmp_path, MemorySecretStore())
    seed(store)
    monkeypatch.setattr(preparation.time, "time", lambda: 1500)
    monkeypatch.setattr(preparation, "cached_fetcher", lambda directory: delivery.fetch)
    roots = []

    def fetch_root(**kwargs):
        roots.append(kwargs)
        return delivery.verified()

    monkeypatch.setattr(transport, "fetch_root", fetch_root)
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        retained_extension_ids=["command.external", "command.unused"],
        now=1500,
        fetch=delivery.fetch,
    )
    registry = GeneratedCommandCatalog.from_prepared_packs(prepared)
    draft = activation_transition.stage(None, prepared, verifier_key=_key(store), store=store, now=1500)
    view = store.commit_extension_control_layers(
        (),
        catalog_digest=registry.catalog_digest,
        actor_id="unit-admin",
        expected_revision=0,
        idempotency_key="seed",
        nonce="seed-nonce",
        migration_registry=registry,
        pack_activation=draft,
        proof=_proof(
            store,
            (),
            revision=0,
            key="seed",
            actor_id="unit-admin",
            nonce="seed-nonce",
            catalog_digest=registry.catalog_digest,
        ),
    )
    service = ExtensionControlApiService(store=store, registry=registry, runtime=ExtensionControlRuntime(view))
    layer = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.LOCAL_ADMIN,
        registry.catalog_digest,
        False,
        (
            ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.external"), ControlState.ENABLED),
            ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.unused"), ControlState.DISABLED),
            ExtensionControl(
                ControlTarget(ControlTargetKind.PERMISSION, "command.unused.permission.read"), ControlState.DISABLED
            ),
        ),
    )
    payload = dict(
        previous_revision=1,
        catalog_digest=registry.catalog_digest,
        layers=json.loads(layers_to_json((layer,))),
        actor_id="unit-admin",
        idempotency_key="enable",
        nonce="enable-nonce",
    )
    return SimpleNamespace(store=store, service=service, registry=registry, payload=payload, roots=roots)


def durable_state(store):
    with store._connect() as connection:
        return {
            table: [tuple(row) for row in connection.execute(f"select * from {table}")]
            for table in (
                "extension_command_pack_activation",
                "extension_control_authority_snapshot",
                "extension_control_authority_transition",
                "extension_command_pack_pending",
            )
        }


def test_first_installed_bundle_uses_authenticated_source_floor_and_is_inert_until_apply(
    installed, tmp_path, monkeypatch
):
    store = _store(tmp_path, MemorySecretStore())
    seed(store)
    monkeypatch.setattr(candidates, "load_installed_bundle", lambda: installed)
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)
    service = ExtensionControlApiService(
        store=store, registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY, runtime=ExtensionControlRuntime(view)
    )
    payload = {
        "previous_revision": 0,
        "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        "layers": [],
        "actor_id": "unit-admin",
        "idempotency_key": "first-bundle",
        "nonce": "first-bundle-nonce",
    }
    preview = service.preview(payload)
    assert activation_store.read(store) is None
    with store._connect() as connection:
        assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 4
        assert connection.execute("select count(*) from extension_control_authority_transition").fetchone()[0] == 0
    approved = service.preview({**payload, "session_nonce": "first-session", "approval_password": _PASSWORD})
    assert approved["canonical_diff_digest"] == preview["canonical_diff_digest"]
    assert activation_store.read(store) is None
    service.apply({**payload, "proof_id": approved["proof_id"]})
    active = activation_store.read(store)
    assert active.selected == {"command.core"}
    assert active.source_sha == installed.source_sha
    assert active.record()["issued_at"] is None
    assert active.record()["authority_profile"] == "installed"


def test_preview_proof_apply_reuse_exact_candidate_and_preserve_inactive_denies(flow, delivery):
    before = durable_state(flow.store)
    first = flow.service.preview(flow.payload)
    assert durable_state(flow.store) == before
    assert activation_store.read(flow.store).selected == {"command.core"}
    native_calls = len(delivery.native_calls)
    publication = delivery.value["publication_id"]
    # A different discovered Root cannot silently replace the reviewed candidate.
    delivery.value["publication_id"] = "13.1"
    payload = {**flow.payload, "session_nonce": "unit-session", "approval_password": _PASSWORD}
    approved = flow.service.preview(payload)
    assert approved["canonical_diff_digest"] == first["canonical_diff_digest"]
    assert len(delivery.native_calls) == native_calls
    assert len(flow.roots) == 1
    assert durable_state(flow.store) == before
    applied = flow.service.apply({**flow.payload, "proof_id": approved["proof_id"]})
    active = activation_store.read(flow.store)
    assert active.selected == {"command.core", "command.external", "command.dependency"}
    assert active.record()["publication_id"] == publication
    assert "command.unused" in active.registry_ids
    view = flow.store.read_extension_control_authority_for_registry(flow.service._registry, read_only=True)
    assert view.layers[0].controls == tuple(flow.service._runtime.current().layers[0].controls)
    assert sum(control.state is ControlState.DISABLED for control in view.layers[0].controls) == 2
    assert flow.service.apply({**flow.payload, "proof_id": approved["proof_id"]}) == applied
    assert len(delivery.native_calls) == native_calls


def test_unavailable_preparation_preserves_old_policy(flow, monkeypatch):
    before = durable_state(flow.store)

    def unavailable(**kwargs):
        raise OSError("metadata unavailable")

    monkeypatch.setattr(transport, "fetch_root", unavailable)
    with pytest.raises(ExtensionControlApiError, match="pack_preparation_unavailable"):
        flow.service.preview(flow.payload)
    assert durable_state(flow.store) == before


def test_native_preparation_is_completed_outside_the_mutation_lease(flow, monkeypatch):
    check = preparation.check_pack_cache
    checked = []

    def outside_lease(directory, digest):
        with pytest.raises(NativePolicySnapshotError, match="lease_missing"):
            require_exclusive_command_control_mutation_lease(flow.store.guard_home)
        checked.append(digest)
        return check(directory, digest)

    monkeypatch.setattr(preparation, "check_pack_cache", outside_lease)
    flow.service.preview(flow.payload)
    assert len(checked) == 1


def test_expired_preview_does_not_reprepare_under_an_existing_proof(flow, delivery, monkeypatch):
    preview = flow.service.preview({**flow.payload, "session_nonce": "session", "approval_password": _PASSWORD})
    calls = len(delivery.native_calls)
    monkeypatch.setattr(candidates.time, "monotonic", lambda: 10**15)
    with pytest.raises(ExtensionControlApiError, match="prepared_preview_expired"):
        flow.service.apply({**flow.payload, "proof_id": preview["proof_id"]})
    assert activation_store.read(flow.store).selected == {"command.core"}
    assert len(delivery.native_calls) == calls


def test_changed_request_cannot_reuse_candidate_proof(flow):
    preview = flow.service.preview({**flow.payload, "session_nonce": "session", "approval_password": _PASSWORD})
    with pytest.raises(ExtensionControlApiError, match="proof_mismatch"):
        flow.service.apply({**flow.payload, "nonce": "other", "proof_id": preview["proof_id"]})
    assert activation_store.read(flow.store).selected == {"command.core"}


def test_offline_removal_uses_committed_authority_after_expiry(flow, monkeypatch):
    approved = flow.service.preview({**flow.payload, "session_nonce": "session", "approval_password": _PASSWORD})
    flow.service.apply({**flow.payload, "proof_id": approved["proof_id"]})
    active = activation_store.read(flow.store)
    layer = flow.service._runtime.current().layers[0]
    disabled = replace(
        layer, controls=tuple(replace(control, state=ControlState.DISABLED) for control in layer.controls)
    )
    payload = {
        **flow.payload,
        "previous_revision": 2,
        "catalog_digest": active.metadata.catalog_digest,
        "layers": json.loads(layers_to_json((disabled,))),
        "idempotency_key": "remove",
        "nonce": "remove-nonce",
    }
    monkeypatch.setattr(preparation.time, "time", lambda: 10000)

    def offline(**kwargs):
        pytest.fail("removal must not fetch a Root")

    monkeypatch.setattr(transport, "fetch_root", offline)
    approved = flow.service.preview({**payload, "session_nonce": "remove-session", "approval_password": _PASSWORD})
    flow.service.apply({**payload, "proof_id": approved["proof_id"]})
    removed = activation_store.read(flow.store)
    assert removed.selected == {"command.core"}
    assert removed.record()["expires_at"] == active.record()["expires_at"]
    with flow.store._connect() as connection:
        assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 6


def test_competing_approved_candidate_cannot_replace_a_newer_commit(flow):
    first = flow.service.preview({**flow.payload, "session_nonce": "session", "approval_password": _PASSWORD})
    competing = {**flow.payload, "nonce": "competitor", "idempotency_key": "competitor"}
    second = flow.service.preview({**competing, "session_nonce": "session-2", "approval_password": _PASSWORD})
    flow.service.apply({**flow.payload, "proof_id": first["proof_id"]})
    retained = activation_store.read(flow.store).record_digest
    with pytest.raises(ExtensionControlApiError, match="authority_conflict"):
        flow.service.apply({**competing, "proof_id": second["proof_id"]})
    assert activation_store.read(flow.store).record_digest == retained


def test_managed_revision_change_invalidates_prepared_proof_even_with_unchanged_layers(flow, monkeypatch):
    approved = flow.service.preview({**flow.payload, "session_nonce": "session", "approval_password": _PASSWORD})
    read = flow.store.read_extension_control_authority_for_registry

    def changed_managed_revision(*args, **kwargs):
        return replace(read(*args, **kwargs), managed_revision=1)

    monkeypatch.setattr(flow.store, "read_extension_control_authority_for_registry", changed_managed_revision)
    with pytest.raises(ExtensionControlApiError, match="managed_layer_conflict"):
        flow.service.apply({**flow.payload, "proof_id": approved["proof_id"]})
    assert activation_store.read(flow.store).selected == {"command.core"}


def test_managed_only_external_allow_does_not_select_payload(flow):
    local = flow.service._mutation_from_payload(flow.payload).layers[0]
    managed = replace(local, kind=ControlLayerKind.SIGNED_CLOUD)
    assert candidates._selection((managed,), flow.registry)[0] == set()
    deny = replace(local, controls=(replace(local.controls[0], state=ControlState.DISABLED),))
    assert candidates._selection((local, replace(deny, kind=ControlLayerKind.SIGNED_CLOUD)), flow.registry)[0] == set()


def test_protected_floor_race_rejects_before_consuming_approved_proof(flow, monkeypatch):
    from codex_plugin_scanner.guard import store_extension_control_authority_commit as commits
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle, lifecycle_store
    from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock

    approved = flow.service.preview({**flow.payload, "session_nonce": "floor-race", "approval_password": _PASSWORD})
    before = durable_state(flow.store)
    encoded, floor = lifecycle_store.inspect(flow.store)
    candidate = {**floor["remote"], "version": "1000.1", "root": "9" * 64}
    next_record = lifecycle.invoke("transition", key=_key(flow.store).hex(), floor=encoded, candidate=candidate)[
        "record"
    ]
    with hold_command_control_authority_lock(flow.store.guard_home):
        lifecycle_store.commit(flow.store, encoded, next_record)
    monkeypatch.setattr(
        commits, "consume_extension_control_proof", lambda *args: pytest.fail("stale floor consumed proof")
    )
    with pytest.raises(ExtensionControlApiError, match="authority_conflict"):
        flow.service.apply({**flow.payload, "proof_id": approved["proof_id"]})
    assert durable_state(flow.store) == before


def test_active_security_race_rejects_before_consuming_approved_proof(flow, delivery, monkeypatch):
    from codex_plugin_scanner.guard import store_extension_control_authority_commit as commits
    from codex_plugin_scanner.guard.catalog_delivery import active_security
    from tests.test_native_active_pack_security import publication

    approved = flow.service.preview({**flow.payload, "session_nonce": "security-race", "approval_password": _PASSWORD})
    before = durable_state(flow.store)
    active_security._observe_capability(
        flow.store,
        active_security.read(flow.store),
        active_security._activation(flow.store),
        publication(delivery),
        delivery.fetch,
    )
    monkeypatch.setattr(
        commits,
        "consume_extension_control_proof",
        lambda *args: pytest.fail("stale active-security scope consumed proof"),
    )
    with pytest.raises(ExtensionControlApiError, match="authority_conflict"):
        flow.service.apply({**flow.payload, "proof_id": approved["proof_id"]})
    assert durable_state(flow.store) == before


def test_inactive_security_observation_does_not_invalidate_approved_proof(flow,delivery):
    from codex_plugin_scanner.guard.catalog_delivery import active_security
    from tests.test_native_active_pack_security import publication

    approved = flow.service.preview({**flow.payload,"session_nonce":"inactive-security","approval_password":_PASSWORD})
    active_security._observe_capability(flow.store,active_security.read(flow.store),
        active_security._activation(flow.store),publication(delivery,"command.unused"),delivery.fetch)
    applied = flow.service.apply({**flow.payload,"proof_id":approved["proof_id"]})
    assert applied["revision"] == 2


@pytest.mark.parametrize("value", [None, "invalid", "{}"])
def test_api_missing_or_corrupt_protected_floor_cannot_rebootstrap(flow, value):
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle_store

    before = durable_state(flow.store)
    backend = flow.store._policy_integrity_secret_store
    ref = flow.store._build_scoped_secret_ref(lifecycle_store.PREFIX)
    if value is None:
        backend.delete_secret(ref)
    else:
        backend.set_secret(ref, value)
    with pytest.raises(ExtensionControlApiError, match="pack_preparation_unavailable"):
        flow.service.preview(flow.payload)
    assert durable_state(flow.store) == before


def test_candidate_cache_is_bounded_and_failed_preparation_remains_retryable():
    cache = candidates.PreparedControlCandidates()
    with pytest.raises(ExtensionControlApiError, match="pack_preparation_unavailable"):
        cache.get_or_prepare("failed", lambda: (_ for _ in ()).throw(OSError("retryable")))
    assert not cache.values
    for index in range(candidates.MAX_CANDIDATES + 1):
        cache.get_or_prepare(str(index), lambda: SimpleNamespace(expires_at=10**15))
    assert len(cache.values) == candidates.MAX_CANDIDATES
    assert "0" not in cache.values
