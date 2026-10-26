"""Keep ephemeral daemon idle settings across the detached launch boundary."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.daemon.server import _guard_daemon_idle_timeout_seconds


@pytest.mark.parametrize("frozen", [False, True])
@pytest.mark.parametrize("configured, expected", [("600", 600.0), ("invalid", 5), (None, 5)])
def test_ephemeral_daemon_idle_setting_survives_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frozen: bool, configured: str | None, expected: float
) -> None:
    guard_home = tmp_path / "pytest-daemon" / "guard-home"
    monkeypatch.setattr(manager.sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(manager, "_guard_home_is_ephemeral", lambda _home: True)
    if configured is None:
        monkeypatch.delenv("GUARD_DAEMON_IDLE_TIMEOUT_SECONDS", raising=False)
    else:
        monkeypatch.setenv("GUARD_DAEMON_IDLE_TIMEOUT_SECONDS", configured)
    child_env = manager._daemon_launcher_env(home_dir=tmp_path, guard_home=guard_home)

    # Evaluate the child's environment, not the parent that configured it.
    monkeypatch.setattr(manager.os, "environ", child_env)
    assert _guard_daemon_idle_timeout_seconds(guard_home) == expected


def test_persistent_daemon_keeps_idle_shutdown_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setenv("GUARD_DAEMON_IDLE_TIMEOUT_SECONDS", "600")
    monkeypatch.setattr(manager, "_guard_home_is_ephemeral", lambda _home: False)

    child_env = manager._daemon_launcher_env(home_dir=tmp_path, guard_home=guard_home)

    monkeypatch.setattr(manager.os, "environ", child_env)
    assert _guard_daemon_idle_timeout_seconds(guard_home) is None
