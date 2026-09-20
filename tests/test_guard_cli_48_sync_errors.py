"""Guard CLI sync errors behavior."""

from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from http.server import HTTPServer

from codex_plugin_scanner.cli import main
from tests.guard_cli_cloud_support import _seed_sync_credentials, _SyncRequestHandler
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)
from tests.support.network import stub_authenticated_urlopen


class TestGuardCli:
    def test_guard_sync_reports_remote_sync_errors_in_json_mode(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        _SyncRequestHandler.response_code = 403
        _SyncRequestHandler.response_payload = {
            "error": "Guard sync requires a Pro or Team plan.",
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            _seed_sync_credentials(home_dir, f"http://127.0.0.1:{server.server_port}/receipts")
            login_rc = 0

            sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            sync_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            _SyncRequestHandler.response_code = 200
            _SyncRequestHandler.response_payload = {
                "syncedAt": "2026-04-09T00:00:00Z",
                "receiptsStored": 1,
            }

        assert login_rc == 0
        assert sync_rc == 1
        assert sync_output == {
            "synced": False,
            "error": "Guard sync requires a Pro or Team plan.",
        }

    def test_guard_sync_reports_non_string_url_errors_in_json_mode(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        _seed_sync_credentials(home_dir, "https://hol.org/api/guard/receipts/sync")
        stub_authenticated_urlopen(
            monkeypatch,
            lambda *args, **kwargs: (_ for _ in ()).throw(
                urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
            ),
        )

        sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
        sync_output = json.loads(capsys.readouterr().out)

        assert sync_rc == 1
        assert sync_output == {
            "synced": False,
            "error": "Guard sync failed: [Errno 61] Connection refused",
        }
