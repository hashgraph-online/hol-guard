"""Actual compiler IR, installed factories, packaged bridge and daemon commits."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_store,
    installed_bundle,
    lifecycle,
    lifecycle_store,
    preparation_authority,
)
from codex_plugin_scanner.guard.catalog_delivery import (
    transport as remote,
)
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor
from codex_plugin_scanner.guard.daemon import extension_control_prepared as candidates
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityPhase,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.extension_builder_support import use_installed_native_source_compiler
from tests.guard_extension_control_authority_fixtures import _PASSWORD, MemorySecretStore
from tests.guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.native_activation_support import BINARY
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)


def test_real_packaged_cross_engine_and_changed_source_offline_api_upgrade(tmp_path, monkeypatch):
    required = ("NATIVE_ACTIVATION_PREVIOUS_BINARY", "NATIVE_ACTIVATION_PREVIOUS_SOURCE")
    missing = [name for name in required if not os.environ.get(name)]
    assert not missing, (
        "native-offline-upgrade requires a real matching prior client/native artifact pair; missing "
        + ", ".join(missing)
    )
    previous = Path(os.environ["NATIVE_ACTIVATION_PREVIOUS_BINARY"]).resolve()
    assert previous.is_file(), f"prior native binary is missing: {previous}"
    source_root = Path(__file__).resolve().parents[1]
    # The old ABI must be initialized by its matching client, before loading
    # current native preparation/security adapters. All state is disposable.
    previous_source = Path(os.environ["NATIVE_ACTIVATION_PREVIOUS_SOURCE"]).resolve()
    assert (previous_source / "src/codex_plugin_scanner/guard/catalog_delivery/lifecycle.py").is_file()
    previous_info = json.loads(subprocess.check_output([str(previous), "compiler-info"]))
    current_info = json.loads(subprocess.check_output([str(BINARY), "compiler-info"]))
    assert previous_info["implementation_digest"] != current_info["implementation_digest"], (
        "offline upgrade proof requires distinct real previous and current engines"
    )
    environment = dict(os.environ)
    environment.update(
        PYTHONPATH=os.pathsep.join([str(previous_source / "src"), str(previous_source)]),
        HOL_GUARD_NATIVE_BINARY=str(previous),
        HOL_GUARD_NATIVE_SOURCE_COMPILER=str(previous),
        HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER=str(previous),
        HOL_GUARD_BUILD_SOURCE_COMPILER=str(previous),
        NATIVE_ACTIVATION_BINARY=str(previous),
    )
    subprocess.run(
        [sys.executable, str(source_root / "tests/fixtures/previous-native-pack-client.py.txt"), str(tmp_path)],
        cwd=previous_source,
        env=environment,
        check=True,
        timeout=180,
    )
    checkpoint = json.loads((tmp_path / "previous-client-checkpoint.json").read_text())
    # Current operations below use the authenticated packaged compiler. CI's
    # source-tree overrides must not coexist with that installed identity.
    monkeypatch.delenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", raising=False)
    monkeypatch.syspath_prepend(str(source_root / "scripts"))
    import build_command_pack_bundle as builder

    store = GuardStore(tmp_path, prime_policy_integrity=False)
    for attribute, name in (
        ("_extension_control_authority_secret_store", "control_secrets"),
        ("_policy_integrity_secret_store", "integrity_secrets"),
    ):
        backend = MemorySecretStore()
        backend.values.update(checkpoint[name])
        setattr(store, attribute, backend)
    store._should_skip_policy_integrity_keychain_access = lambda backend: False
    store._get_policy_integrity_secret_from_store = store._policy_integrity_secret_store.get_secret
    original_version = transport.metadata.version
    package_version = {"value": "3.49.0"}
    monkeypatch.setattr(
        transport.metadata,
        "version",
        lambda name: package_version["value"] if name == "hol-guard" else original_version(name),
    )
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", installed_bundle.load_installed_bundle)
    monkeypatch.setattr(candidates, "load_installed_bundle", installed_bundle.load_installed_bundle)
    reports = [checkpoint["report"]]

    def install(binary, version, source):
        package = tmp_path / ("package-" + version)
        native_dir = package / "_native"
        native_dir.mkdir(parents=True)
        raw = binary.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        info = json.loads(subprocess.check_output([str(binary), "compiler-info"]))
        engine = info["implementation_digest"]
        executable = native_dir / "hol-guard-runtime"
        executable.write_bytes(raw)
        executable.chmod(0o700)
        bundle = package / "guard/contracts/data/extensions/command-pack-bundle"
        bundle.parent.mkdir(parents=True)
        # The retained earlier binary compiled the same authored command
        # sources. Pin its actual fingerprint only for the historical fixture
        # builder; production admission remains the manifest-bound native check.
        with monkeypatch.context() as historical:
            historical.setattr(builder.packs.legacy, "implementation_digest", lambda: engine)
            # This test covers the explicit offline bundle upgrade profile.
            # Normal lean enable/fetch is exercised by test_native_pack_preparation.
            report = builder.build(binary, bundle, source, source_root=source_root, offline=True)
        reports.append(report)
        data = (bundle / MANIFEST).read_bytes()
        exported = json.loads(subprocess.check_output([str(binary), "export-built"]))
        program = package / "native-command-program.v1.json"
        program.write_text(json.dumps(exported["program"]))
        common = dict(
            protocol_version=1,
            package_version=version,
            source_sha=source,
            target="test",
            platform_tag="test",
            command_pack_bundle=descriptor(data, source_sha=source, engine=engine),
        )
        runtime = dict(common, schema="hol-guard-native-runtime.v1", runtime_size=len(raw), runtime_sha256=digest)
        compiler = dict(
            common,
            schema="hol-guard-native-source-compiler.v2",
            compiler_size=len(raw),
            compiler_sha256=digest,
            executable="hol-guard-runtime",
            implementation_digest=engine,
            base_program_digest=exported["program"]["program_digest"],
        )
        for name, value in [("runtime-manifest.json", runtime), ("source-compiler-manifest.json", compiler)]:
            (native_dir / name).write_text(json.dumps(value))
        use_installed_native_source_compiler(monkeypatch, native_dir)
        monkeypatch.setattr(transport, "_PACKAGED_PROGRAM", program)
        monkeypatch.setattr(installed_bundle, "_package", lambda: package)
        package_version["value"] = version
        return installed_bundle.load_installed_bundle()

    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    view = store.read_extension_control_authority_for_registry(registry, read_only=True)
    service = ExtensionControlApiService(store=store, registry=registry, runtime=ExtensionControlRuntime(view))

    def offline(*args, **kwargs):
        pytest.fail("installed upgrade attempted network lineage/publication IO")

    monkeypatch.setattr(lifecycle, "ancestry", offline)
    monkeypatch.setattr(remote, "fetch_root", offline)
    monkeypatch.setattr(remote, "download", offline)

    def apply(key):
        digest = service.catalog_digest
        payload = dict(
            previous_revision=service._runtime.current().revision,
            catalog_digest=digest,
            actor_id="fixture-admin",
            idempotency_key=key,
            nonce=key,
            layers=[
                dict(
                    schema_version="1.0.0",
                    kind="local-admin",
                    catalog_digest=digest,
                    global_lockdown=False,
                    controls=[dict(target_kind="extension", target_id="command.agentbridge", state="enabled")],
                )
            ],
        )
        approved = service.preview({**payload, "session_nonce": key, "approval_password": _PASSWORD})
        service.apply({**payload, "proof_id": approved["proof_id"]})
        return activation_store.read(store)

    old = None
    old_identity = checkpoint["old_identity"]
    remote_identity = checkpoint["remote_identity"]
    for version, source in [("3.50.0a1", "a" * 40), ("3.50.0b1", "b" * 40)]:
        authority = install(BINARY, version, source)
        if old is None:
            # The upgraded package's runtime opens the record the previous
            # client left; no record is read without an installed runtime.
            old = activation_store.read(store)
            assert "command.agentbridge" in old.selected
        with store._connect() as connection:
            saved_decisions = [tuple(row) for row in connection.execute("select * from policy_decisions")]
        previous_registry = candidates.GeneratedCommandCatalog.from_prepared_packs(activation_store.read(store))
        controls_before = store.read_extension_control_authority_for_registry(
            previous_registry, include_managed_controls=False, read_only=True
        )
        if old.engine != authority.engine and version == "3.50.0a1":
            original_anchor = store._write_and_verify_anchor
            original_migration = store._migrate_extension_control_catalog

            def check_upgrade_boundary(action, _migrate=original_migration, _old=old.engine, **kwargs):
                changed = copy.deepcopy(action)
                for layer in changed["layers"]:
                    layer["controls"] = []
                with pytest.raises(ExtensionControlAuthorityError, match="changed controls"):
                    _migrate(changed, **kwargs)
                for field in ("release", "next_floor"):
                    evidence = copy.deepcopy(kwargs["installed_upgrade"])
                    evidence[field] = None
                    with pytest.raises(ExtensionControlAuthorityError, match="not authorized"):
                        _migrate(action, **{**kwargs, "installed_upgrade": evidence})
                # The resident recomputes the managed policy the candidate
                # was prepared against and refuses evidence that claims another.
                evidence = copy.deepcopy(kwargs["installed_upgrade"])
                evidence["managed"] = {"revision": 7, "layers": []}
                with pytest.raises(ExtensionControlAuthorityError, match="managed policy changed"):
                    _migrate(action, **{**kwargs, "installed_upgrade": evidence})
                assert activation_store.read(store).engine == _old
                return _migrate(action, **kwargs)

            def interrupt_after_anchor(anchor, _write=original_anchor, **kwargs):
                _write(anchor, **kwargs)
                if anchor.phase is AuthorityPhase.ANCHORED:
                    raise RuntimeError("fixture interrupted after anchored upgrade")

            with monkeypatch.context() as interrupted:
                interrupted.setattr(store, "_write_and_verify_anchor", interrupt_after_anchor)
                interrupted.setattr(store, "_migrate_extension_control_catalog", check_upgrade_boundary)
                with pytest.raises(RuntimeError, match="fixture interrupted after anchored upgrade"):
                    store.migrate_installed_command_pack_authority()
            assert activation_store.read(store).engine == old.engine
        with store._connect() as connection:
            head = connection.execute(
                "select snapshot_json from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
        # Every upgrade reads a bound head. A catalog migration commits no pack
        # record of its own, so it carries forward the binding the head already
        # had; a runtime that dropped it stranded this install on an unbound
        # head the upgrade refused, and the authority stayed stale with every
        # hook closed until the next release.
        assert "command_pack_record_digest" in json.loads(head[0])
        store.migrate_installed_command_pack_authority()
        recovered = activation_store.read(store)
        # Startup must recover without asking the user to reapprove unchanged
        # controls. A successful floor migration alone left the old IR active.
        assert recovered.engine == authority.engine
        assert recovered.selected == old.selected
        recovered_registry = candidates.GeneratedCommandCatalog.from_prepared_packs(recovered)
        controls_after = store.read_extension_control_authority_for_registry(
            recovered_registry, include_managed_controls=False, read_only=True
        )
        assert [(layer.kind, layer.global_lockdown, layer.controls) for layer in controls_after.layers] == [
            (layer.kind, layer.global_lockdown, layer.controls) for layer in controls_before.layers
        ]
        with store._connect() as connection:
            assert [tuple(row) for row in connection.execute("select * from policy_decisions")] == saved_decisions
        lock = store._extension_control_authority_lock

        def shared_only(*args, _lock=lock, **kwargs):
            assert kwargs.get("shared") is True, "unchanged startup requested an exclusive lease"
            return _lock(*args, **kwargs)

        with monkeypatch.context() as unchanged:
            unchanged.setattr(store, "_extension_control_authority_lock", shared_only)
            store.migrate_installed_command_pack_authority()
        assert activation_store.read(store).record_digest == recovered.record_digest
        publisher = NativePolicySnapshotPublisher(store=store)
        try:
            publisher._publish_once()
            assert publisher.is_ready(), publisher.last_error
        finally:
            publisher.close()
        service = ExtensionControlApiService(
            store=store, registry=recovered_registry, runtime=ExtensionControlRuntime(controls_after)
        )
        active = apply(version)
        assert active.selected == old.selected
        assert active.engine == authority.engine and active.engine != old.engine
        assert active.record()["source_sha"] == source
        _, floor = lifecycle_store.inspect(store)
        assert floor["remote"] == remote_identity and floor["source"] == "a" * 40
        assert floor["installed"]["version"] == version
    for candidate in [old_identity, {**remote_identity, "version": "100.6"}]:
        with pytest.raises(ValueError, match="version_rollback"):
            lifecycle.invoke(
                "transition", key=_key(store).hex(), floor=lifecycle_store.read(store), candidate=candidate
            )
    # The exact remote high-water identity permits authenticated crash recovery,
    # but cannot make its old-engine executable IR admissible in the new runtime.
    with pytest.raises(transport.NativeSourceCompilerError, match="command_pack_reuse_engine_invalid"):
        transport.check_pack_cache(old.directory, old.record()["program_digest"])
    assert len(reports) == 3 and all(
        report["extensions"] > 0 and report["profile"] == "complete-offline" for report in reports
    )
