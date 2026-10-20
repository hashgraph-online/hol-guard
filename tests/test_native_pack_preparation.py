"""Real compiler inventory, installed factory and verified subprocess preparation."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_record,
    authority,
    installed_bundle,
    preparation,
)
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor
from codex_plugin_scanner.guard.catalog_delivery.located_store import LocatedStore
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded, entries
from codex_plugin_scanner.guard.catalog_delivery.pack_store import PackReader
from codex_plugin_scanner.guard.catalog_delivery.revocations import RevokedPackError, revocation_key
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport
from tests.extension_builder_support import use_installed_native_source_compiler
from tests.guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.test_extension_delivery_authority import SOURCE, root_value
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)

BINARY = Path(os.environ.get("NATIVE_PREPARATION_BINARY") or os.environ.get("HOL_GUARD_NATIVE_BINARY", ""))


@pytest.fixture(scope="module")
def inventory(tmp_path_factory):
    assert BINARY.is_file(), "pin the compiled candidate with HOL_GUARD_NATIVE_BINARY"
    root = Path(__file__).resolve().parents[1]
    scratch = tmp_path_factory.mktemp("native-preparation")
    source = scratch / "source"
    for relative in (
        "contributions/command-sources",
        "contributions/mcp-servers",
        "contracts/extensions/trust",
        "contracts/extensions/revocations",
        "contracts/catalog-delivery",
    ):
        if (root / relative).exists():
            shutil.copytree(root / relative, source / relative)
        else:
            (source / relative).mkdir(parents=True)
    # Three actual source-compiler inputs, with one permission-owner dependency
    # and one metadata-only conflict target. They inherit no publisher authority.
    template = json.loads((root / "contributions/command-sources/command.agentbridge.json").read_text())
    for name in ("preparation-external", "preparation-dependency", "preparation-direct", "preparation-unused"):
        identity = "command." + name
        value = json.loads(json.dumps(template).replace("command.agentbridge", identity))
        if name == "preparation-external":
            value["extension"]["dependencies"] = ["command.preparation-direct"]
            value["extension"]["permissions"][0]["dependencies"] = [
                "command.preparation-dependency.permission.run-tool-registry"
            ]
            value["extension"]["conflicts"] = ["command.preparation-unused"]
        elif name == "preparation-unused":
            value["extension"]["conflicts"] = ["command.preparation-external"]
        (source / "contributions/command-sources" / (identity + ".json")).write_bytes(encoded(value))
        trust = json.loads((root / "contracts/extensions/trust/command.agentbridge.v1.json").read_text())
        trust["extension"] = identity
        (source / "contracts/extensions/trust" / (identity + ".v1.json")).write_bytes(encoded(trust))
    # Build scripts are explicitly imported from the candidate, not the fixture.
    import sys

    sys.path.insert(0, str(root / "scripts"))
    try:
        import build_command_pack_bundle as builder
    finally:
        sys.path.remove(str(root / "scripts"))

    package = scratch / "package"
    native = package / "_native"
    native.mkdir(parents=True)
    raw = BINARY.read_bytes()
    executable = native / transport._COMPILER_NAME
    executable.write_bytes(raw)
    executable.chmod(0o700)
    info = json.loads(subprocess.check_output([str(BINARY), "compiler-info"]))
    engine = info["implementation_digest"]
    bundle = package / "guard/contracts/data/extensions/command-pack-bundle"
    bundle.parent.mkdir(parents=True)
    published = scratch / "published"
    report = builder.build(BINARY, bundle, SOURCE, source_root=source, assets_output=published)
    data = (bundle / MANIFEST).read_bytes()
    exported = json.loads(subprocess.check_output([str(BINARY), "export-built"]))
    program = package / "native-command-program.v1.json"
    program.write_bytes(encoded(exported["program"]))
    common = dict(
        protocol_version=1,
        package_version="3.50.0a1",
        source_sha=SOURCE,
        target="test",
        platform_tag="test",
        command_pack_bundle=descriptor(data, source_sha=SOURCE, engine=engine),
    )
    runtime = dict(
        common,
        schema="hol-guard-native-runtime.v1",
        runtime_size=len(raw),
        runtime_sha256=hashlib.sha256(raw).hexdigest(),
    )
    compiler = dict(
        common,
        schema="hol-guard-native-source-compiler.v2",
        compiler_size=len(raw),
        compiler_sha256=hashlib.sha256(raw).hexdigest(),
        executable=transport._COMPILER_NAME,
        implementation_digest=engine,
        base_program_digest=exported["program"]["program_digest"],
    )
    for name, value in (("runtime-manifest.json", runtime), ("source-compiler-manifest.json", compiler)):
        (native / name).write_bytes(encoded(value))
    return dict(
        package=package,
        native=native,
        program=program,
        engine=engine,
        bundle=bundle,
        report=report,
        published=published,
    )


@pytest.fixture
def delivery(inventory, tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.catalog_delivery import transport as release_transport

    class Response(io.BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.headers = {"Content-Encoding": "identity"}

    def mirror(request, **kwargs):
        prefix = "https://github.com/hashgraph-online/hol-guard/releases/download/"
        assert request.full_url.startswith(prefix)
        tag, asset = request.full_url.removeprefix(prefix).split("/")
        assert asset.startswith("pack-") and asset.endswith(".zip")
        return Response((inventory["published"] / tag / asset).read_bytes())

    # Preserve the normal lean installed factory and native URL/byte proofs;
    # only the public HTTP transport is replaced with emitted fixture assets.
    monkeypatch.setattr(release_transport, "managed_urlopen", mirror)
    use_installed_native_source_compiler(monkeypatch, inventory["native"])
    monkeypatch.setattr(transport, "_PACKAGED_PROGRAM", inventory["program"])
    monkeypatch.setattr(installed_bundle, "_package", lambda: inventory["package"])
    version = transport.metadata.version
    monkeypatch.setattr(transport.metadata, "version", lambda n: "3.50.0a1" if n == "hol-guard" else version(n))
    verified = installed_bundle.load_installed_bundle()
    return verified, tmp_path / "cache", inventory["engine"]


def remote(delivery, monkeypatch, **changes):
    installed, _, engine = delivery
    value = root_value()
    value["engine"] = engine
    value["policy"] = copy.deepcopy(installed.manifest()["policy"])
    value["directory"]["count"] = value["policy"]["root"]["extensions"]
    value["policy"]["root"]["engine"] = engine
    value.update(changes)
    # Only the external signature service is stubbed. Its fixed capability
    # factory, root validation, compiler, executable verifier and bridge are real.
    monkeypatch.setattr(authority, "_verify_attested_artifact", lambda *a, **k: None)
    return authority.verify_distribution(
        encoded(value), b"synthetic signature service", expected_source_sha=SOURCE, now=1500
    )


def test_installed_factory_native_closure_and_cache_agree(delivery, monkeypatch):
    verified, cache, engine = delivery
    calls = []
    operations = []
    run = transport._run_bounded

    def traced(arguments, data, **kwargs):
        if data:
            operations.append(json.loads(data).get("kind"))
        return run(arguments, data, **kwargs)

    monkeypatch.setattr(transport, "_run_bounded", traced)
    original = type(verified).fetch

    def fetch(self, target, maximum):
        calls.append(target)
        return original(self, target, maximum)

    monkeypatch.setattr(type(verified), "fetch", fetch)
    base = preparation.prepare(verified, [], cache, engine=engine, now=1500)
    assert base.authority_profile == "installed" and base.publication_id == "0.0"
    assert base.release_version == "3.50.0a1"
    assert not any(identity.startswith("command.preparation-") for identity in base.selected)
    retained = preparation.prepare(
        verified, [], cache, engine=engine, now=1500, retained_extension_ids=["command.preparation-external"]
    )
    assert retained.selected == base.selected
    assert "command.preparation-unused" in retained.registry_ids
    selected = preparation.prepare(verified, ["command.preparation-external"], cache, engine=engine, now=1500)
    assert selected.selected == base.selected | {
        "command.preparation-external",
        "command.preparation-dependency",
        "command.preparation-direct",
    }
    assert "command.preparation-unused" in selected.registry_ids - selected.selected
    assert len(list(selected.catalogs())) == len(selected.selected)
    assert len(list(selected.registry_catalogs())) == len(selected.registry_ids)
    admitted = transport.check_pack_cache(cache, selected.metadata.program_digest)
    for field in ("program_digest", "catalog_digest", "trust_digest"):
        assert admitted[field] == getattr(selected.metadata, field)
    assert admitted["extensions"] == len(selected.selected)
    assert calls
    assert "preparation" in operations, "production bypassed native preparation"
    # Authenticated committed capability: only remove selected/registry entries;
    # no fetch, even when the original remote metadata has expired.
    committed = activation_record.seal(selected, key=b"k" * 32, revision=1, previous_digest=None)
    previous = activation_record.open_record(committed[0], committed[1], committed[2], key=b"k" * 32, directory=cache)
    monkeypatch.setattr(type(verified), "fetch", lambda *a: pytest.fail("subset fetched"))
    reduced = preparation.prepare(previous, [], cache, engine=engine, now=999999)
    assert reduced.selected == base.selected
    with pytest.raises(ValueError, match="uncommitted"):
        preparation.prepare(previous, ["command.agentbridge"], cache, engine=engine, now=999999)


def test_remote_identity_stability_and_fail_closed(delivery, monkeypatch, tmp_path):
    installed, cache, engine = delivery
    verified = remote(delivery, monkeypatch)
    first = preparation.prepare(verified, [], cache, engine=engine, now=1500, fetch=installed.fetch)
    destination = cache / "sets" / (first.metadata.program_digest + ".json")
    original = destination.read_bytes()
    newer = remote(delivery, monkeypatch, publication_id="13.1")
    second = preparation.prepare(newer, [], cache, engine=engine, now=1500, fetch=installed.fetch)
    assert first.metadata == second.metadata and first.root_digest != second.root_digest
    assert destination.read_bytes() == original
    # An authenticated catalog really grows by one compiler-generated inactive
    # pack, while the earlier native cache representation remains admissible.
    from extension_delivery_assets import AssetPlan
    from extension_policy_delivery import policy_transport

    located = LocatedStore(tmp_path / "discovery-read", fetch=installed.fetch)
    records = {}

    def collect(reference):
        wrapper = located.json(reference)
        located.json(wrapper["native"])
        if wrapper["kind"] == "leaf":
            records.update(wrapper["records"])
        else:
            for child in wrapper["children"]:
                collect(child[2])

    collect(verified.manifest()["policy"]["transport"])
    full = verified.manifest()["policy"]["root"]
    manifests = dict(entries(PackReader(located.directory), full["index"], full["extensions"]))
    removed = "command.preparation-unused"
    del manifests[removed]
    del records[removed]
    objects = ObjectStore(tmp_path / "smaller-index")
    index = objects.index(manifests)
    plan = AssetPlan(tmp_path / "smaller-assets", SOURCE)
    publisher = LocatedStore(tmp_path / "smaller-metadata", publisher=plan)
    smaller = verified.manifest()
    smaller["publication_id"] = "11.1"
    smaller["directory"]["count"] -= 1
    smaller["policy"]["root"] = {**full, "index": index, "extensions": len(manifests)}
    smaller["policy"]["transport"] = policy_transport(PackReader(objects.directory), index, records, publisher)
    plan.finish()
    small_capability = authority.verify_distribution(
        encoded(smaller), b"synthetic", expected_source_sha=SOURCE, now=1500
    )

    def fetch(target, maximum):
        from codex_plugin_scanner.guard.catalog_delivery.containers import member

        path = plan.directory / target["tag"] / target["asset"]
        if path.exists():
            return member(path.read_bytes(), target["asset"], target.get("member"), maximum)
        return installed.fetch(target, maximum)

    growth_cache = tmp_path / "growth-cache"
    shutil.copytree(cache / "objects", growth_cache / "objects")
    before = preparation.prepare(small_capability, [], growth_cache, engine=engine, now=1500, fetch=fetch)
    growth_set = growth_cache / "sets" / (before.metadata.program_digest + ".json")
    before_bytes = growth_set.read_bytes()
    after = preparation.prepare(newer, [], growth_cache, engine=engine, now=1500, fetch=installed.fetch)
    assert before.metadata == after.metadata == first.metadata
    assert before.root_digest != after.root_digest and growth_set.read_bytes() == before_bytes
    for candidate, chosen_engine, now, message in (
        (verified, engine, 2500, "fresh"),
        (verified, "2" * 64, 1500, "different native engine"),
        (verified.manifest(), engine, 1500, "authenticated"),
    ):
        with pytest.raises(ValueError, match=message):
            preparation.prepare(candidate, [], cache, engine=chosen_engine, now=now, fetch=installed.fetch)
    with pytest.raises(preparation.UnavailablePackError):
        preparation.prepare(verified, ["command.no-such-policy"], cache, engine=engine, now=1500, fetch=installed.fetch)
    destination.write_bytes(b"{}")
    with pytest.raises(ValueError):
        preparation.prepare(verified, [], cache, engine=engine, now=1500, fetch=installed.fetch)


def test_revocation_and_substituted_metadata(delivery, monkeypatch, tmp_path):
    installed, cache, engine = delivery
    # Fetch native policy/defaults using the actual package and compiler first.
    base = preparation.prepare(installed, [], cache, engine=engine, now=1500)
    from extension_delivery_assets import AssetPlan

    plan = AssetPlan(tmp_path / "assets", SOURCE)
    store = LocatedStore(tmp_path / "metadata", publisher=plan)
    identity = sorted(base.selected)[0]
    for kind in ("extension", "pack"):
        value = remote(delivery, monkeypatch).manifest()
        native = value["policy"]["root"]
        manifests = dict(entries(PackReader(cache / "objects"), native["index"], native["extensions"]))
        manifest = manifests[identity]["sha256"] if kind == "pack" else None
        record = dict(
            schema="guard.extension-revocation.v1",
            extension_id=identity,
            kind=kind,
            epoch=1,
            state="revoked",
            reason="synthetic withdrawal",
        )
        if manifest:
            record["manifest_sha256"] = manifest
        value["policy"]["revocations"] = dict(
            epoch=1, count=1, index=store.index({revocation_key(identity, kind, manifest): store.put_json(record)})
        )
        plan.finish()
        verified = authority.verify_distribution(encoded(value), b"synthetic", expected_source_sha=SOURCE, now=1500)

        def fetch(target, maximum):
            from codex_plugin_scanner.guard.catalog_delivery.containers import member

            path = plan.directory / target["tag"] / target["asset"]
            if path.exists():
                return member(path.read_bytes(), target["asset"], target.get("member"), maximum)
            return installed.fetch(target, maximum)

        with pytest.raises(RevokedPackError) as caught:
            preparation.prepare(verified, [], cache, engine=engine, now=1500, fetch=fetch)
        assert caught.value.identity == identity and caught.value.epoch == 1


def test_missing_corrupt_and_related_metadata_admission(delivery, monkeypatch, tmp_path):
    installed, cache, engine = delivery
    base = preparation.prepare(installed, [], cache, engine=engine, now=1500)
    policy = installed.manifest()["policy"]
    native = policy["root"]
    reader = PackReader(cache / "objects")
    manifests = dict(entries(reader, native["index"], native["extensions"]))
    manifest = reader.json(manifests[sorted(base.selected)[0]])
    path = cache / "objects" / (manifest["program"]["sha256"] + ".json")
    original = path.read_bytes()
    path.unlink()
    recovered = preparation.prepare(installed, [], cache, engine=engine, now=1500)
    assert path.read_bytes() == original and recovered.metadata == base.metadata
    path.write_bytes(b"{}")
    with pytest.raises(ValueError):
        preparation.prepare(installed, [], cache, engine=engine, now=1500)
    path.write_bytes(original)
    from extension_delivery_assets import AssetPlan

    plan = AssetPlan(tmp_path / "mutations", SOURCE)
    store = LocatedStore(tmp_path / "metadata-mutations", publisher=plan)
    located = LocatedStore(tmp_path / "located", fetch=installed.fetch)
    identity = "command.preparation-external"
    records = {}

    def rewrite(reference, mutate):
        wrapper = located.json(reference)
        if wrapper["kind"] == "leaf":
            for row in wrapper["records"]:
                if row[0] == identity:
                    record = located.json(row[1])
                    mutate(record)
                    row[1] = store.put_json(record)
                    records[identity] = row[1]
        else:
            for row in wrapper["children"]:
                row[2] = rewrite(row[2], mutate)
        return store.put_json(wrapper)

    def fetch(target, maximum):
        from codex_plugin_scanner.guard.catalog_delivery.containers import member

        path = plan.directory / target["tag"] / target["asset"]
        if path.exists():
            return member(path.read_bytes(), target["asset"], target.get("member"), maximum)
        return installed.fetch(target, maximum)

    def verified(mutate, defaults=False):
        value = remote(delivery, monkeypatch).manifest()
        value["policy"]["transport"] = rewrite(policy["transport"], mutate)
        if defaults:
            value["policy"]["defaults"] = dict(count=1, index=store.index(records))
        plan.finish()
        return authority.verify_distribution(encoded(value), b"synthetic", expected_source_sha=SOURCE, now=1500)

    def substitute(record):
        catalog = located.json(record["catalog_metadata"])
        catalog[0]["name"] = "Substituted metadata"
        record["catalog_metadata"] = store.put_json(catalog)

    with pytest.raises(ValueError, match="metadata differs from compiled"):
        preparation.prepare(verified(substitute), [identity], cache, engine=engine, now=1500, fetch=fetch)

    def remove_owner(record):
        record["related_interfaces"] = [
            identity for identity in record["related_interfaces"] if identity != "command.preparation-dependency"
        ]

    with pytest.raises(ValueError, match="unique authenticated owner"):
        preparation.prepare(verified(remove_owner), [identity], cache, engine=engine, now=1500, fetch=fetch)
    with pytest.raises(ValueError, match="external policy"):
        preparation.prepare(verified(lambda r: None, defaults=True), [], cache, engine=engine, now=1500, fetch=fetch)


def test_prepared_dataclass_through_real_daemon_control_commit(delivery, tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.catalog_delivery import activation_store, preparation_authority, projection
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
    before_capture = projection.capture(store)
    payload = dict(
        previous_revision=service._runtime.current().revision,
        catalog_digest=service.catalog_digest,
        actor_id="fixture-admin",
        idempotency_key="native-preparation",
        nonce="native-preparation",
        layers=[
            dict(
                schema_version="1.0.0",
                kind="local-admin",
                catalog_digest=service.catalog_digest,
                global_lockdown=False,
                controls=[dict(target_kind="extension", target_id="command.agentbridge", state="enabled")],
            )
        ],
    )
    approved = service.preview({**payload, "session_nonce": "native-preparation", "approval_password": _PASSWORD})
    service.apply({**payload, "proof_id": approved["proof_id"]})
    committed = activation_store.read(store)
    assert "command.agentbridge" in committed.selected
    assert committed.engine == installed.engine
    # The daemon timer must read the authenticated active catalog after an
    # optional enable; rebinding to the core catalog changes the same revision.
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHTTPServer

    refreshed = _GuardDaemonHTTPServer.refresh_extension_control_runtime(
        SimpleNamespace(
            store=store,
            extension_control_runtime=service._runtime,
            _installed_authority_pending=False,
            _extension_control_on_core_registry=False,
        )
    )
    assert refreshed.revision == service._runtime.current().revision
    assert refreshed.catalog_digest == service.catalog_digest
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

    # Force a timer capture that preceded the committed activation. Its old
    # registry must not be rebound to the new revision or installed in memory.
    with monkeypatch.context() as patches:
        patches.setattr(projection, "capture", lambda store: before_capture)
        with pytest.raises(NativePolicySnapshotError, match="native_command_pack_projection_changed"):
            _GuardDaemonHTTPServer.refresh_extension_control_runtime(
                SimpleNamespace(
                    store=store,
                    extension_control_runtime=service._runtime,
                    _installed_authority_pending=False,
                    _extension_control_on_core_registry=False,
                )
            )
    assert service._runtime.current() == refreshed
