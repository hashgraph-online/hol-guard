"""A missing command-pack floor must leave a record instead of failing silently.

An install whose authority was enrolled before the floor record existed carries
no legacy controls to admit, so startup migration produced nothing and wrote
nothing. Every later discovery and publication refresh then failed the floor
gate with ``pack_lifecycle_protected_floor_missing``, and neither half of the
startup path left a trace: a packaged daemon has no stderr for ``_LOGGER``, and
an install that advertises no bundle returned without a word. These tests pin the two
records that make that state diagnosable.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import background_diagnostics
from codex_plugin_scanner.guard.daemon.server import (
    _GuardDaemonHTTPServer,
    _InstalledAuthorityMigrationError,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def recorded():
    events: list[tuple[str, str]] = []

    def sink(event: str, detail: str) -> None:
        events.append((event, detail))

    background_diagnostics.install_sink(sink)
    yield events
    background_diagnostics.release_sink(sink)


def test_an_absent_installed_release_is_recorded(tmp_path, recorded, monkeypatch) -> None:
    from codex_plugin_scanner.guard.catalog_delivery import preparation_authority

    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: None)

    store.migrate_installed_command_pack_authority()

    assert recorded == [("installed_authority_release_absent", "detail=installed bundle not advertised")]


def test_a_failed_startup_migration_is_recorded(recorded) -> None:
    def unavailable():
        raise ValueError("pack_lifecycle_protected_floor_missing")

    server = SimpleNamespace(
        store=SimpleNamespace(migrate_installed_command_pack_authority=unavailable),
        _installed_authority_pending=False,
    )

    with pytest.raises(_InstalledAuthorityMigrationError):
        _GuardDaemonHTTPServer._migrate_installed_authority(server)

    assert server._installed_authority_pending is True
    assert recorded == [
        ("installed_authority_migration_failed", "error=ValueError detail=pack_lifecycle_protected_floor_missing")
    ]


def test_the_recorded_startup_detail_carries_no_path(tmp_path, recorded) -> None:
    secret = tmp_path / ".ssh/id_ed25519"

    def unavailable():
        raise ValueError(f"installed bundle metadata unavailable: no such file: '{secret}'")

    server = SimpleNamespace(
        store=SimpleNamespace(migrate_installed_command_pack_authority=unavailable),
        _installed_authority_pending=False,
    )

    with pytest.raises(_InstalledAuthorityMigrationError):
        _GuardDaemonHTTPServer._migrate_installed_authority(server)

    (_event, detail) = recorded[0]
    assert "<path>" in detail
    assert "id_ed25519" not in detail
