"""A fresh install enrolls its extension-control authority without a setup step."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore

from .guard_extension_control_authority_fixtures import MemorySecretStore, _store

_DIGEST = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest


@pytest.mark.python_daemon
def test_a_fresh_home_starts_with_a_protected_authority(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore(), enroll=False)
    assert store.read_extension_control_authority(catalog_digest=_DIGEST).health is AuthorityHealth.UNENROLLED

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    try:
        startup = daemon._server.extension_control_runtime.current()
        assert startup.health is AuthorityHealth.PROTECTED
    finally:
        daemon.stop()

    view = store.read_extension_control_authority(catalog_digest=_DIGEST)
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 0
    assert view.layers == ()


def test_a_restarted_daemon_keeps_the_enrolled_authority(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore(), enroll=False)
    first = store.enroll_extension_control_authority_by_default(_DIGEST)
    assert first.health is AuthorityHealth.PROTECTED

    second = store.enroll_extension_control_authority_by_default(_DIGEST)
    assert second.health is AuthorityHealth.PROTECTED
    assert second.revision == first.revision


def test_a_failed_default_enrollment_leaves_the_home_unenrolled_and_the_daemon_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(self: GuardStore, catalog_digest: str) -> None:
        raise ValueError("secret store unavailable")

    monkeypatch.setattr(GuardStore, "enroll_extension_control_authority_by_default", unavailable)
    store = _store(tmp_path, MemorySecretStore(), enroll=False)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    try:
        assert daemon._server.extension_control_runtime.current().health is AuthorityHealth.UNENROLLED
    finally:
        daemon.stop()


def test_a_bootstrap_that_stops_before_its_anchor_leaves_the_home_unenrolled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore(), enroll=False)
    original = GuardStore._mirror_resident_anchor

    def unavailable(self: GuardStore, sealed: str) -> None:
        raise RuntimeError("vault unavailable")

    monkeypatch.setattr(GuardStore, "_mirror_resident_anchor", unavailable)
    with pytest.raises(RuntimeError):
        store.enroll_extension_control_authority_by_default(_DIGEST)
    assert store.read_extension_control_authority(catalog_digest=_DIGEST).health is AuthorityHealth.UNENROLLED

    monkeypatch.setattr(GuardStore, "_mirror_resident_anchor", original)
    retried = store.enroll_extension_control_authority_by_default(_DIGEST)
    assert retried.health is AuthorityHealth.PROTECTED
    assert retried.revision == 0
