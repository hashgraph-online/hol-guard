"""Guard CLI connect errors behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_connect_reports_browser_authorization_errors_cleanly(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)

        def failing_browser_flow(
            *,
            store: GuardStore,
            connect_url: str,
            wait_timeout_seconds: int = 180,
        ) -> dict[str, object]:
            del store, connect_url, wait_timeout_seconds
            raise RuntimeError("browser_oauth_unreachable")

        monkeypatch.setattr(guard_commands_module, "_run_guard_browser_connect_flow", failing_browser_flow)
        connect_rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--connect-url",
                "https://hol.org/guard/connect",
                "--json",
            ]
        )
        captured = capsys.readouterr()

        assert connect_rc == 1
        assert "Guard authorization failed: browser_oauth_unreachable" in captured.err
        assert "Traceback" not in captured.err
        assert store.get_cloud_sync_profile() is None

    def test_guard_connect_never_exposes_legacy_pairing_fields(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"

        def fake_browser_flow(
            *,
            store: GuardStore,
            connect_url: str,
            wait_timeout_seconds: int = 180,
        ) -> dict[str, object]:
            del store
            assert wait_timeout_seconds == 180
            return {
                "status": "connected",
                "connect_mode": "browser_oauth",
                "browser_opened": True,
                "authorize_url": "https://hol.org/guard/oauth/authorize?request_id=req-789",
            }

        monkeypatch.setattr(guard_commands_module, "_run_guard_browser_connect_flow", fake_browser_flow)
        connect_rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--connect-url",
                "https://hol.org/guard/connect",
                "--json",
            ]
        )
        connect_output = json.loads(capsys.readouterr().out)
        rendered = json.dumps(connect_output, sort_keys=True)

        assert connect_rc == 0
        assert connect_output["connect_mode"] == "browser_oauth"
        assert "guardPairSecret" not in rendered
        assert "guardPairRequest" not in rendered
        assert "guardDaemon" not in rendered
