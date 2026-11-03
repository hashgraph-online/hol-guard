"""Compiled lifecycle tests with explicit synthetic publication/credential IO."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import lifecycle, lifecycle_store
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from tests.guard_extension_control_authority_fixtures import MemorySecretStore
from tests.test_extension_delivery_authority import SOURCE

BINARY = Path(
    os.environ.get("NATIVE_ACTIVATION_BINARY")
    or os.environ.get("HOL_GUARD_NATIVE_BINARY")
    or os.environ.get("NATIVE_PREPARATION_BINARY")
    or ""
)


def native(kind, **fields):
    result = subprocess.run(
        [str(BINARY), "pack-lifecycle", "--stdin"],
        input=json.dumps({"kind": kind, **fields}).encode(),
        capture_output=True,
        timeout=60,
    )
    if result.returncode:
        raise ValueError(result.stderr.decode().strip())
    return json.loads(result.stdout)


@pytest.fixture(autouse=True)
def compiled_lifecycle(monkeypatch):
    # These wire tests pin the compiled CLI directly. The packaged bridge tests
    # retain the production session, manifest factory and executable verification.
    def verified_preparation():
        return nullcontext(lambda kind="preparation", **fields: native(kind, **fields))

    # Preparation and target metadata both resolve the transport through the
    # lifecycle module, so one patch routes both to the compiled candidate.
    monkeypatch.setattr(lifecycle, "verified_preparation", verified_preparation)
    assert BINARY.is_file(), "explicitly pin the compiled candidate with HOL_GUARD_NATIVE_BINARY"
    monkeypatch.setattr(lifecycle, "invoke", native)
    original = lifecycle.installed_identity

    def installed(authority):
        if type(authority).__module__ != "tests.test_extension_pack_installed_profile":
            return original(authority)
        root = authority.manifest()
        return dict(
            profile="installed",
            source=authority.source_sha,
            engine=authority.engine,
            root=authority.digest,
            version="3.16.3",
            authority=root["authority_epoch"],
            revocation=root["policy"]["revocations"]["epoch"],
        )

    monkeypatch.setattr(lifecycle, "installed_identity", installed)


def seed(store, *, source=SOURCE, installed=None, remote=None, authority=1, revocation=0):
    """Provision a test-only authenticated floor, never a production bootstrap."""
    if not hasattr(store, "_policy_integrity_secret_material"):
        store._policy_integrity_secret_material = lambda **kwargs: (b"k" * 32, "test")
    store._policy_integrity_secret_store = MemorySecretStore()
    store._should_skip_policy_integrity_keychain_access = lambda backend: False
    if not hasattr(store, "_build_scoped_secret_ref"):
        store._build_scoped_secret_ref = lambda prefix: prefix
    store._get_policy_integrity_secret_from_store = store._policy_integrity_secret_store.get_secret
    if installed is None:
        installed = dict(
            profile="installed",
            source=source,
            engine="1" * 64,
            root="0" * 64,
            version="3.16.2",
            authority=1,
            revocation=0,
        )
    fields = ("profile", "source", "engine", "root", "version", "authority", "revocation")
    installed = {field: installed[field] for field in fields}
    remote = None if remote is None else {field: remote[field] for field in fields}
    floor = dict(
        schema="guard.command-pack-floor.v1",
        source=source,
        authority=authority,
        revocation=revocation,
        installed=installed,
        remote=remote,
    )
    raw = json.dumps(floor, separators=(",", ":")).encode()
    mac = hmac.new(_key(store), b"hol-guard.command-pack-protected-floor.v1\0" + raw, hashlib.sha256).hexdigest()
    record = json.dumps(dict(floor=floor, mac=mac), separators=(",", ":"))
    store._policy_integrity_secret_store.set_secret(store._build_scoped_secret_ref(lifecycle_store.PREFIX), record)
    return record


def subset_store(previous):
    store = SimpleNamespace(guard_home=previous.directory.parent / "subset-device")
    header = previous.record()
    identity = dict(
        profile="remote",
        source=header["source_sha"],
        engine=header["engine"],
        root=header["root_digest"],
        version=header["publication_id"],
        authority=header["authority_epoch"],
        revocation=header["revocation_epoch"],
    )
    seed(
        store,
        source=identity["source"],
        remote=identity,
        authority=identity["authority"],
        revocation=identity["revocation"],
    )
    return store
