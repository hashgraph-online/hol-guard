"""Review regressions with synthetic delivery/admission and real control commits."""

from __future__ import annotations

import hashlib

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_store, preparation, preparation_authority, transport
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded
from codex_plugin_scanner.guard.catalog_delivery.pack_store import PackReader
from codex_plugin_scanner.guard.catalog_delivery.policy_lookup import lookup
from codex_plugin_scanner.guard.daemon import extension_control_prepared as candidates
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiError, ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.extension_control_targets import request_metadata
from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_REVISION_STATE_KEY,
    build_managed_controls_revision_state,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
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
from tests.guard_extension_control_authority_fixtures import _PASSWORD, MemorySecretStore, _store
from tests.guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_installed_profile import installed as installed
from tests.test_extension_pack_preparation import delivery as delivery
from tests.test_guard_extension_control_prepared import durable_state
from tests.test_guard_extension_control_prepared import flow as flow
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)


@pytest.fixture
def bundled(installed, tmp_path, monkeypatch):
    monkeypatch.setattr(candidates, "load_installed_bundle", lambda: installed)
    store = _store(tmp_path, MemorySecretStore())
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: installed)
    seed(store)
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    view = store.read_extension_control_authority_for_registry(registry, read_only=True)
    return store, ExtensionControlApiService(store=store, registry=registry, runtime=ExtensionControlRuntime(view))


def apply(service, states, key):
    snapshot = service._runtime.current()
    digest = service.catalog_digest
    payload = {
        "previous_revision": snapshot.revision,
        "catalog_digest": digest,
        "actor_id": "unit-admin",
        "idempotency_key": key,
        "nonce": key,
        "layers": [
            {
                "schema_version": CONTROL_SCHEMA_VERSION,
                "kind": "local-admin",
                "catalog_digest": digest,
                "global_lockdown": False,
                "controls": [
                    {"target_kind": "extension", "target_id": identity, "state": state}
                    for identity, state in states.items()
                ],
            }
        ]
        if states
        else [],
    }
    approved = service.preview({**payload, "session_nonce": key, "approval_password": _PASSWORD})
    return service.apply({**payload, "proof_id": approved["proof_id"]})


@pytest.mark.parametrize("restart", [False, True])
def test_unrelated_sequential_enables_without_preretention(bundled, restart):
    store, service = bundled
    apply(service, {}, "initial")
    assert activation_store.read(store).registry_ids == {"command.core"}
    apply(service, {"command.unused": "enabled"}, "enable-a")
    assert "command.external" not in activation_store.read(store).registry_ids
    if restart:
        registry = GeneratedCommandCatalog.from_prepared_packs(activation_store.read(store))
        view = store.read_extension_control_authority_for_registry(registry, read_only=True)
        service = ExtensionControlApiService(store=store, registry=registry, runtime=ExtensionControlRuntime(view))
    apply(service, {"command.unused": "enabled", "command.external": "enabled"}, "enable-b")
    assert activation_store.read(store).selected == {
        "command.core",
        "command.unused",
        "command.external",
        "command.dependency",
    }


def test_bundled_disable_reenable_offline(bundled, monkeypatch):
    store, service = bundled

    def offline(**kwargs):
        pytest.fail("authenticated installed additions must work offline")

    monkeypatch.setattr(transport, "fetch_root", offline)
    apply(service, {}, "initial")
    apply(service, {"command.unused": "enabled"}, "enable")
    apply(service, {"command.unused": "disabled"}, "disable")
    assert activation_store.read(store).selected == {"command.core"}
    apply(service, {"command.unused": "enabled"}, "reenable")
    assert activation_store.read(store).selected == {"command.core", "command.unused"}
    assert activation_store.read(store).record()["authority_profile"] == "installed"


def test_missing_activation_cannot_fall_back_to_installed_authority(bundled):
    store, service = bundled
    apply(service, {}, "initial")
    apply(service, {"command.unused": "enabled"}, "enable")
    with store._connect() as connection:
        connection.execute("delete from extension_command_pack_activation")
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

    with pytest.raises(NativePolicySnapshotError, match="activation_missing"):
        activation_store.read(store)
    with pytest.raises(NativePolicySnapshotError, match="activation_missing"):
        apply(service, {"command.unused": "disabled"}, "after-loss")


def test_target_lookup_is_metadata_only_with_exact_active_digest(bundled, delivery):
    store, service = bundled
    apply(service, {}, "initial")
    before = durable_state(store)
    active = service._registry
    layer = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.LOCAL_ADMIN,
        active.catalog_digest,
        False,
        (ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.unused"), ControlState.ENABLED),),
    )
    calls = len(delivery.calls)
    metadata = request_metadata(store, active, (layer,))
    assert metadata.get("command.unused") is not None
    assert all(delivery.archives["command.unused"] not in target["member"] for target in delivery.calls[calls:])
    assert durable_state(store) == before
    assert service.catalog_digest == active.catalog_digest
    assert active.get("command.unused") is None


def test_legacy_install_cannot_expand_control_targets_from_discovery(tmp_path, monkeypatch):
    store = _store(tmp_path, MemorySecretStore())
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    layer = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.LOCAL_ADMIN,
        registry.catalog_digest,
        False,
        (ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.unused"), ControlState.ENABLED),),
    )
    monkeypatch.setattr(preparation_authority, "installed_bundle_type", lambda: ())

    def remote(**kwargs):
        pytest.fail("metadata discovery cannot expand a legacy install's authority")

    monkeypatch.setattr(transport, "fetch_root", remote)
    assert request_metadata(store, registry, (layer,)).get("command.unused") is None


def test_managed_update_after_api_check_rejects_before_reservation_or_consumption(flow, monkeypatch):
    approved = flow.service.preview({**flow.payload, "session_nonce": "session", "approval_password": _PASSWORD})
    before = durable_state(flow.store)
    commit = flow.store.commit_extension_control_layers
    consume_calls = []
    from codex_plugin_scanner.guard import store_extension_control_authority_commit as commits

    consume = commits.consume_extension_control_proof

    def observed_consume(*args, **kwargs):
        consume_calls.append(True)
        return consume(*args, **kwargs)

    def interleave(*args, **kwargs):
        # API has already checked the old view; publish a genuine authenticated
        # managed revision under EX before the commit obtains that same lease.
        with flow.store._extension_control_authority_lock():
            state = build_managed_controls_revision_state(1, authority_key=flow.store._authority_key(required=True))
            flow.store.set_sync_payload(MANAGED_CONTROLS_REVISION_STATE_KEY, state, "unit")
        return commit(*args, **kwargs)

    monkeypatch.setattr(commits, "consume_extension_control_proof", observed_consume)
    monkeypatch.setattr(flow.store, "commit_extension_control_layers", interleave)
    with flow.store._connect() as connection:
        proofs = [tuple(row) for row in connection.execute("select * from extension_control_authority_proof")]
    with pytest.raises(ExtensionControlApiError, match="authority_conflict"):
        flow.service.apply({**flow.payload, "proof_id": approved["proof_id"]})
    assert durable_state(flow.store) == before
    assert not consume_calls
    with flow.store._connect() as connection:
        assert [tuple(row) for row in connection.execute("select * from extension_control_authority_proof")] == proofs
    assert approved["proof_id"] in flow.service._pending_proofs


@pytest.mark.parametrize("epoch", ["authority", "revocation"])
def test_first_remote_fallback_preserves_installed_security_floors(
    bundled, installed, delivery, monkeypatch, tmp_path, epoch
):
    store, service = bundled
    root = installed.manifest()
    if epoch == "authority":
        root["authority_epoch"] = delivery.value["authority_epoch"] + 1
    else:
        root["policy"]["revocations"]["epoch"] = delivery.value["policy"]["revocations"]["epoch"] + 1
    # Build a genuine core-only installed inventory. Remote inventory still has
    # the requested optional extension; no mocked preparation failure is needed.
    policy = ObjectStore(tmp_path / "installed-policy")
    index = policy.index({"command.core": delivery.manifests["command.core"]})
    native = delivery.store.put(PackReader(policy.directory).blob(index))
    core = lookup(delivery.store, root["policy"]["root"], root["policy"]["transport"], "command.core")
    root["policy"]["root"].update(index=index, extensions=1)
    root["policy"]["transport"] = delivery.store.put_json(
        {
            "schema": "guard.policy-transport.v2",
            "kind": "leaf",
            "native": native,
            "records": [["command.core", delivery.store.put_json(core)]],
        }
    )
    delivery.plan.finish()
    installed.data = encoded(root)
    installed.digest = hashlib.sha256(installed.data).hexdigest()
    monkeypatch.setattr(preparation, "cached_fetcher", lambda directory: delivery.fetch)
    monkeypatch.setattr(preparation.time, "time", lambda: 1500)
    # A valid descendant relationship does not imply increasing security epochs.
    descendant = "b" * 40
    from codex_plugin_scanner.guard.catalog_delivery.authority import verify_distribution

    remote = {**delivery.value, "source_sha": descendant}
    verified = verify_distribution(encoded(remote), b"synthetic provenance", expected_source_sha=descendant, now=1500)
    monkeypatch.setattr(transport, "fetch_root", lambda **kwargs: verified)
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle

    ancestry = []

    def compared(floor, new):
        ancestry.append((floor["source"], new))
        return {
            "status": "ahead",
            "base_commit": {"sha": floor["source"]},
            "merge_base_commit": {"sha": floor["source"]},
            "head_commit": {"sha": new},
            "ahead_by": 1,
            "behind_by": 0,
        }

    monkeypatch.setattr(lifecycle, "ancestry", compared)
    with pytest.raises(ExtensionControlApiError, match="pack_preparation_unavailable"):
        apply(service, {"command.unused": "enabled"}, "fallback")
    assert ancestry == [(installed.source_sha, descendant)]
    assert activation_store.read(store) is None
