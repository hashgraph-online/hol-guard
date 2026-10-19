"""Profile semantics with synthetic installed capabilities, not release proof."""

from __future__ import annotations

import hashlib
import sys
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_record,
    activation_transition,
    installed_bundle,
    preparation,
    preparation_authority,
)
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import encoded
from codex_plugin_scanner.guard.catalog_delivery.pack_store import decode
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_preparation import delivery as delivery


@pytest.fixture
def installed(delivery, monkeypatch):
    class VerifiedInstalledBundle:
        def __new__(cls):
            raise TypeError("factory only")

        def manifest(self):
            return decode(self.data)

    module = ModuleType("codex_plugin_scanner.guard.catalog_delivery.installed_bundle")
    module.VerifiedInstalledBundle = VerifiedInstalledBundle
    # Like a source checkout, nothing is advertised until a test patches the
    # loader that hands out this bundle.
    module.advertised = lambda: False
    monkeypatch.setitem(sys.modules, module.__name__, module)
    root = {field: delivery.value[field] for field in ("source_sha", "engine", "authority_epoch", "policy")}
    root.update(schema="guard.command-pack-bundle.v1", publication_id="0.0")
    value = object.__new__(VerifiedInstalledBundle)
    value.data = encoded(root)
    value.digest = hashlib.sha256(value.data).hexdigest()
    value.source_sha = root["source_sha"]
    value.engine = root["engine"]
    value.fetch = delivery.fetch
    return value


def test_installed_profile_has_no_fabricated_remote_validity(installed, delivery):
    from types import SimpleNamespace

    store = SimpleNamespace(guard_home=delivery.cache.parent / "installed-device")
    store.guard_home.mkdir(mode=0o700)
    seed(store)
    key = b"installed-profile-fixture-key!!!!"
    prepared = preparation.prepare(installed, [], delivery.cache, engine="1" * 64, now=10000)
    assert prepared.authority_profile == "installed"
    draft = activation_transition.stage(None, prepared, verifier_key=key, store=store, now=10000)
    opened = activation_record.open_record(draft.data, draft.digest, draft.mac, key=key, directory=delivery.cache)
    header = opened.record()
    assert header["schema"] == activation_record.SCHEMA_V2
    assert header["authority_profile"] == "installed"
    assert header["issued_at"] is None and header["expires_at"] is None
    assert header["publication_id"] == "0.0"
    assert opened.selected == {"command.core"}
    assert activation_record.admission_is_current(header, 10**12)
    subset = preparation.prepare(opened, [], delivery.cache, engine="1" * 64, now=10**12)
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle_store
    from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock

    with hold_command_control_authority_lock(store.guard_home):
        lifecycle_store.commit(store, draft.lifecycle_before, draft.lifecycle_after)
    activation_transition.stage(opened, subset, verifier_key=key, store=store, now=10**12)


def test_installed_capability_does_not_make_unsigned_root_dictionary_authority(installed, delivery):
    with pytest.raises(ValueError, match="authenticated"):
        preparation.prepare(installed.manifest(), [], delivery.cache, engine="1" * 64, now=10000)


def test_absent_legacy_bundle_is_distinct_from_advertised_but_broken_bundle(tmp_path, monkeypatch):
    package = tmp_path / "package"
    monkeypatch.setattr(installed_bundle, "_package", lambda: package)
    assert preparation_authority.load_installed_bundle() is None
    native = package / "_native"
    native.mkdir(parents=True)
    runtime = {"schema": "hol-guard-native-runtime.v1"}
    compiler = {"schema": "hol-guard-native-source-compiler.v2"}
    (native / "runtime-manifest.json").write_bytes(encoded(runtime))
    (native / "source-compiler-manifest.json").write_bytes(encoded(compiler))
    assert preparation_authority.load_installed_bundle() is None
    runtime["command_pack_bundle"] = {"invalid": True}
    (native / "runtime-manifest.json").write_bytes(encoded(runtime))

    def broken():
        raise ValueError("advertised bundle invalid")

    monkeypatch.setattr(installed_bundle, "load_installed_bundle", broken)
    with pytest.raises(ValueError, match="advertised bundle invalid"):
        preparation_authority.load_installed_bundle()
