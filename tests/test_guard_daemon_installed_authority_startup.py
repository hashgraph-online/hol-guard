"""An installed release the daemon cannot migrate fails closed instead of stopping the daemon."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore


def test_a_failed_installed_authority_migration_starts_a_fail_closed_daemon_and_retries_on_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts: list[str] = []

    def unavailable(self: GuardStore) -> None:
        attempts.append("failed")
        raise ValueError("installed bundle metadata unavailable: source compiler could not be started")

    monkeypatch.setattr(GuardStore, "migrate_installed_command_pack_authority", unavailable)
    daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    try:
        server = daemon._server
        startup = server.extension_control_runtime.current()
        assert startup.health is AuthorityHealth.TAMPERED
        assert server._installed_authority_pending is True

        # While the release stays unmigrated, a refresh admits nothing newer.
        assert server.refresh_extension_control_runtime() is startup
        assert attempts == ["failed", "failed"]

        def migrated(self: GuardStore) -> None:
            attempts.append("migrated")

        monkeypatch.setattr(GuardStore, "migrate_installed_command_pack_authority", migrated)
        server.refresh_extension_control_runtime()
        assert attempts[-1] == "migrated"
        assert server._installed_authority_pending is False
    finally:
        daemon.stop()
