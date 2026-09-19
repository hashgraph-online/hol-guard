"""Stable source observations coexist with native decision leases."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_control_authority_io import NativeCommandControlMutationRequiredError
from codex_plugin_scanner.guard.native_policy_authority_managed import read_frozen_native_managed_authority
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.runtime.command_extensions import CommandSafetyExtensionRegistry
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityView
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_managed_source_support import managed_store
from tests.test_native_policy_authority_managed_read import _TIME

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX cross-process flock contract")


def _shared_lease_available(store: GuardStore) -> bool:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import fcntl,sys\n"
            "with open(sys.argv[1], 'rb') as stream:\n"
            " try: fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)\n"
            " except BlockingIOError: sys.exit(2)\n",
            str(store.guard_home / "extension-control-authority.lock"),
        ],
        check=False,
        timeout=5,
        capture_output=True,
    )
    assert result.returncode in {0, 2}, result.stderr
    return result.returncode == 0


@pytest.mark.parametrize("cloud", [None, False, True])
def test_complete_capture_preparation_keeps_native_shared_lease_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cloud: bool | None
) -> None:
    store = GuardStore(tmp_path / "empty") if cloud is None else managed_store(tmp_path, monkeypatch, cloud=cloud)
    store._policy_integrity_secret_material(create=True)
    original = store._read_extension_control_authority_locked
    observations: list[bool] = []

    def observe(
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> ExtensionControlAuthorityView:
        # The first read is preparatory; the second belongs to the complete
        # SQL view. Probe during preparation, while its actual lease is held.
        if not observations:
            observations.append(_shared_lease_available(store))
        return original(catalog_digest, migration_registry=migration_registry, connection=connection)

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", observe)
    inputs = read_native_policy_authority_inputs(store, now=_TIME)
    assert observations == [True]
    assert (inputs.authority.managed is None) == (cloud is None)


def test_required_preparation_releases_shared_lease_before_exclusive_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=False)
    original = store.read_extension_control_authority_for_registry
    original_locked = store._read_extension_control_authority_locked
    observations: list[bool] = []
    modes: list[bool] = []

    def require_preparation(
        registry: CommandSafetyExtensionRegistry, *, read_only: bool = False
    ) -> ExtensionControlAuthorityView:
        modes.append(read_only)
        if read_only:
            raise NativeCommandControlMutationRequiredError()
        return original(registry, read_only=read_only)

    def observe(
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> ExtensionControlAuthorityView:
        observations.append(_shared_lease_available(store))
        return original_locked(catalog_digest, migration_registry=migration_registry, connection=connection)

    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", require_preparation)
    monkeypatch.setattr(store, "_read_extension_control_authority_locked", observe)
    frozen = read_frozen_native_managed_authority(store)
    assert frozen is not None
    assert modes == [True, False]
    assert observations == [False]
