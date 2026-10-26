"""Compiler-backed coverage of the daemon's request-local metadata adapter."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_store, preparation_authority, transport
from codex_plugin_scanner.guard.catalog_delivery.located_store import LocatedStore
from codex_plugin_scanner.guard.daemon import extension_control_targets as targets
from codex_plugin_scanner.guard.extension_builder import native_source_compiler
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from tests.delivery_scripts import script
from tests.test_native_pack_preparation import (
    BINARY,
    remote,
)
from tests.test_native_pack_preparation import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.test_native_pack_preparation import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)
from tests.test_native_pack_preparation import (
    delivery as delivery,
)
from tests.test_native_pack_preparation import (
    inventory as inventory,
)
from tests.test_native_pack_preparation import (
    test_prepared_dataclass_through_real_daemon_control_commit as existing_enable,
)

lookup = script("extension_delivery_policy_lookup").lookup


def layers(*rows):
    return [
        SimpleNamespace(
            controls=[
                SimpleNamespace(target=SimpleNamespace(kind=SimpleNamespace(value=kind), target_id=identity))
                for kind, identity in rows
            ]
        )
    ]


def test_target_metadata_only_last_entry_permission_and_corruption(delivery, tmp_path, monkeypatch):
    installed, _, _ = delivery
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: installed)
    calls, operations = [], []
    original = type(installed).fetch
    run = native_source_compiler._run_bounded

    def traced(arguments, data, **kwargs):
        if data:
            operations.append(json.loads(data))
        return run(arguments, data, **kwargs)

    def fetch(self, target, maximum):
        calls.append(target)
        assert target.get("member", target["asset"]).startswith("object-"), "hydrated executable IR archive"
        return original(self, target, maximum)

    monkeypatch.setattr(type(installed), "fetch", fetch)
    monkeypatch.setattr(native_source_compiler, "_run_bounded", traced)
    empty = GeneratedCommandCatalog(())
    store = SimpleNamespace(guard_home=tmp_path / "home")
    identity = "command.preparation-external"
    permission = "command.preparation-dependency.permission.run-tool-registry"
    result = targets.request_metadata(store, empty, layers(("extension", identity), ("permission", permission)))
    assert result.get(identity).extension_id == identity
    assert result.permission(permission).extension_id == "command.preparation-dependency"
    assert result.permission(permission + "-absent") is None
    assert not result.get(identity).enabled
    assert result.get("command.preparation-unused") is None
    assert all(row.get("operation") == "target-metadata" for row in operations)
    assert calls and not list(store.guard_home.rglob("sets/*.json"))

    # The final row in a real authenticated leaf must be discoverable too.
    directory = activation_store.prepare_directory_for_store(store)
    metadata = LocatedStore(directory / "objects", fetch=installed.fetch)
    root = installed.manifest()["policy"]
    page = metadata.json(root["transport"])
    while page["kind"] != "leaf":
        page = metadata.json(page["children"][-1][2])
    last = page["records"][-1][0]
    assert targets.request_metadata(store, empty, layers(("extension", last))).get(last) is not None

    record = lookup(metadata, root["root"], root["transport"], identity)
    path = directory / "objects" / (record["catalog_metadata"]["sha256"] + ".json")
    original_bytes = path.read_bytes()
    path.write_bytes(b"corrupt")
    with pytest.raises(ValueError):
        targets.request_metadata(store, empty, layers(("extension", identity)))
    path.write_bytes(original_bytes)


def test_native_legacy_and_remote_fallback(delivery, tmp_path, monkeypatch):
    installed, _, _ = delivery
    verified = remote(delivery, monkeypatch)
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: None)
    monkeypatch.setattr(activation_store, "read", lambda store: None)
    monkeypatch.setattr(transport, "fetch_root", lambda **kwargs: pytest.fail("legacy discovery expanded targets"))
    store = SimpleNamespace(guard_home=tmp_path / "legacy")
    empty = GeneratedCommandCatalog(())
    requested = layers(("extension", "command.preparation-external"))
    assert targets.request_metadata(store, empty, requested).extensions == {}
    monkeypatch.setattr(activation_store, "read", lambda store: object())
    monkeypatch.setattr(transport, "fetch_root", lambda **kwargs: verified)
    monkeypatch.setattr(targets.preparation, "cached_fetcher", lambda directory: installed.fetch)
    assert targets.request_metadata(store, empty, requested).get("command.preparation-external") is not None
    assert targets.request_metadata(store, empty, layers(("extension", "command.no-such-target"))).extensions == {}


def test_existing_daemon_enable_uses_native_target_operation(delivery, tmp_path, monkeypatch):
    operations = []
    run = native_source_compiler._run_bounded

    def traced(arguments, data, **kwargs):
        if data:
            operations.append(json.loads(data).get("operation"))
        return run(arguments, data, **kwargs)

    monkeypatch.setattr(native_source_compiler, "_run_bounded", traced)
    existing_enable(delivery, tmp_path, monkeypatch)
    assert "target-metadata" in operations


@pytest.mark.parametrize("malformed", ["shape", "agreement"])
def test_authenticated_catalog_shape_and_agreement_errors(delivery, tmp_path, monkeypatch, malformed):
    from extension_delivery_assets import AssetPlan
    from extension_delivery_containers import member
    from extension_delivery_located_store import LocatedStore as Publisher

    from codex_plugin_scanner.guard.catalog_delivery import authority
    from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import encoded
    from tests.test_extension_delivery_authority import SOURCE

    installed, _, _ = delivery
    root = remote(delivery, monkeypatch).manifest()
    plan = AssetPlan(tmp_path / "publication", SOURCE)
    publisher = Publisher(tmp_path / "published", publisher=plan)
    reader = LocatedStore(tmp_path / "read", fetch=installed.fetch)
    identity = "command.preparation-external"

    def rewrite(reference):
        page = reader.json(reference)
        if page["kind"] == "leaf":
            for row in page["records"]:
                if row[0] == identity:
                    record = reader.json(row[1])
                    catalog = reader.json(record["catalog_metadata"])
                    if malformed == "shape":
                        catalog = []
                    else:
                        catalog[0]["activation"] = "default-on"
                    record["catalog_metadata"] = publisher.put_json(catalog)
                    row[1] = publisher.put_json(record)
        else:
            for row in page["children"]:
                row[2] = rewrite(row[2])
        return publisher.put_json(page)

    root["policy"]["transport"] = rewrite(root["policy"]["transport"])
    plan.finish()
    verified = authority.verify_distribution(encoded(root), b"synthetic", expected_source_sha=SOURCE, now=1500)

    def fetch(target, maximum):
        path = plan.directory / target["tag"] / target["asset"]
        if path.exists():
            return member(path.read_bytes(), target["asset"], target.get("member"), maximum)
        return installed.fetch(target, maximum)

    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: None)
    monkeypatch.setattr(activation_store, "read", lambda store: object())
    monkeypatch.setattr(transport, "fetch_root", lambda **kwargs: verified)
    monkeypatch.setattr(targets.preparation, "cached_fetcher", lambda directory: fetch)
    store = SimpleNamespace(guard_home=tmp_path / "home")
    message = "target catalog shape invalid" if malformed == "shape" else "target metadata differs from authenticated"
    with pytest.raises(ValueError, match=message):
        targets.request_metadata(store, GeneratedCommandCatalog(()), layers(("extension", identity)))


def test_existing_daemon_retains_inactive_permission_deny(delivery, tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.daemon import extension_control_prepared as candidates
    from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
    from tests.guard_extension_control_authority_fixtures import _PASSWORD
    from tests.test_native_pack_upgrade import legacy_store

    installed, _, _ = delivery
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(BINARY))
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    store = legacy_store(tmp_path, monkeypatch)
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: installed)
    monkeypatch.setattr(candidates, "load_installed_bundle", lambda: installed)
    store.migrate_installed_command_pack_authority()
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    view = store.read_extension_control_authority_for_registry(registry, read_only=True)
    service = ExtensionControlApiService(store=store, registry=registry, runtime=ExtensionControlRuntime(view))
    permission = "command.agentbridge.permission.run-tool-registry"
    payload = dict(
        previous_revision=service._runtime.current().revision,
        catalog_digest=service.catalog_digest,
        actor_id="fixture-admin",
        idempotency_key="metadata-deny",
        nonce="metadata-deny",
        layers=[
            dict(
                schema_version="1.0.0",
                kind="local-admin",
                catalog_digest=service.catalog_digest,
                global_lockdown=False,
                controls=[dict(target_kind="permission", target_id=permission, state="disabled")],
            )
        ],
    )
    # Corrupt target metadata must retain the existing API's 503 boundary.
    from codex_plugin_scanner.guard.daemon.extension_control_errors import ExtensionControlApiError

    directory = activation_store.prepare_directory_for_store(store)
    reader = LocatedStore(directory / "objects", fetch=installed.fetch)
    policy = installed.manifest()["policy"]
    record = lookup(reader, policy["root"], policy["transport"], "command.agentbridge")
    reader.json(record["catalog_metadata"])
    path = directory / "objects" / (record["catalog_metadata"]["sha256"] + ".json")
    original_bytes = path.read_bytes()
    path.write_bytes(b"corrupt")
    with pytest.raises(ExtensionControlApiError, match="pack_preparation_unavailable"):
        service.preview(payload)
    path.write_bytes(original_bytes)
    preview = service.preview({**payload, "session_nonce": "metadata-deny", "approval_password": _PASSWORD})
    service.apply({**payload, "proof_id": preview["proof_id"]})
    committed = activation_store.read(store)
    assert "command.agentbridge" not in committed.selected
    assert "command.agentbridge" in committed.registry_ids
    assert service._runtime.current().layers[0].controls[0].target.target_id == permission
