"""`hol-guard sync` while another Guard process is already syncing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def busy_sync_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    original = GuardStore.hold_cloud_sync_lock

    def short_wait(self: GuardStore, *, timeout_seconds: float = 0.2):
        return original(self, timeout_seconds=min(timeout_seconds, 0.2))

    monkeypatch.setattr(GuardStore, "hold_cloud_sync_lock", short_wait)
    monkeypatch.setattr(commands_dispatch_cloud, "_cloud_guard_sync_auth_context", lambda _store: {})
    guard_home = tmp_path / "guard"
    with original(GuardStore(guard_home), timeout_seconds=1.0):
        yield ["--home", str(home_dir), "--guard-home", str(guard_home)]


def test_sync_reports_a_background_sync_as_in_progress_in_json(busy_sync_lock: list[str], capsys) -> None:
    rc = main(["guard", "sync", *busy_sync_lock, "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["synced"] is False
    assert payload["in_progress"] is True
    assert payload["error"] == commands_dispatch_cloud.GUARD_SYNC_IN_PROGRESS_MESSAGE


def test_sync_tells_the_user_a_background_sync_is_running(busy_sync_lock: list[str], capsys) -> None:
    rc = main(["guard", "sync", *busy_sync_lock])
    captured = capsys.readouterr()

    assert rc == 1
    assert "already syncing with Guard Cloud in the background" in captured.err
    assert "Timed out waiting" not in captured.err
