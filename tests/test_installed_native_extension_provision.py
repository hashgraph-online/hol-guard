"""The installed-extension fixture's authority setup on a new Guard home."""

from __future__ import annotations

from pathlib import Path

from ci.native_runtime import probe_installed_native_extensions as probe
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

_CATALOG = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest


def _store(home: Path) -> GuardStore:
    store = GuardStore(home)
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(home)
    return store


def _view(store: GuardStore):
    return store.read_extension_control_authority(catalog_digest=_CATALOG)


def test_a_new_home_is_enrolled_at_an_empty_revision(tmp_path: Path) -> None:
    store = _store(tmp_path)
    probe.provision(store)
    view = _view(store)
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 0
    assert not view.layers


def test_the_authority_a_daemon_start_enrolled_is_kept(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enroll_extension_control_authority_by_default(_CATALOG)
    enrolled = _view(store)
    assert enrolled.health is AuthorityHealth.PROTECTED
    probe.provision(store)
    view = _view(store)
    assert (view.health, view.revision, view.layers) == (enrolled.health, 0, enrolled.layers)
