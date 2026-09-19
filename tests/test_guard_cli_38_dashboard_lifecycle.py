"""Guard CLI dashboard lifecycle behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_dashboard_opens_local_approval_center(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        from unittest.mock import MagicMock

        from codex_plugin_scanner.guard import dashboard_launcher

        monkeypatch.setattr(
            dashboard_launcher,
            "ensure_guard_daemon",
            lambda guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            dashboard_launcher,
            "load_guard_daemon_auth_token",
            lambda guard_home: "fake-token",
        )
        mock_surface = MagicMock()
        mock_surface.ensure_surface.return_value = {
            "opened": True,
            "reason": "opened",
            "browser_url": "http://127.0.0.1:5474",
        }
        monkeypatch.setattr(dashboard_launcher, "GuardSurfaceRuntime", lambda store: mock_surface)

        rc = main(["guard", "dashboard", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["approval_center_url"] == "http://127.0.0.1:5474"
        assert output["opened"] is True
        assert output["reason"] == "opened"
        assert "notification_setup_started" not in output

    def test_guard_daemon_ensure_releases_wake_reservation_after_failure(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        cleared: list[tuple[Path, str]] = []

        def fail_startup(_guard_home: Path, *, home_dir: Path | None = None) -> str:
            assert _guard_home == guard_home
            assert home_dir == tmp_path / "home"
            raise RuntimeError("startup failed")

        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", fail_startup)
        monkeypatch.setattr(
            guard_commands_module,
            "clear_guard_daemon_wake_reservation",
            lambda home, *, token: cleared.append((home, token)) or True,
        )

        exit_code = main(
            [
                "guard",
                "daemon",
                "ensure",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--wake-token",
                "wake-token",
            ]
        )

        assert exit_code == 1
        assert cleared == [(guard_home, "wake-token")]
