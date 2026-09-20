"""Guard CLI service sync behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_cloud_support import _seed_guard_cloud
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_service_sync_publishes_runtime_session_before_receipts(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        now = "2026-05-01T00:00:00Z"
        _seed_guard_cloud(store)
        store.set_sync_payload(
            "service_runtime_profile",
            {
                "runtime": "openclaw",
                "label": "OpenClaw Runner",
                "workspace": "workspace_ops",
                "surface": "agent-sdk",
                "client_name": "hol-guard",
                "client_title": "OpenClaw Runner",
                "client_version": "2.0.0",
            },
            now,
        )

        captured_session: dict[str, object] = {}

        def fake_sync_runtime_session(current_store: GuardStore, *, session: dict[str, object]) -> dict[str, object]:
            assert current_store is not None
            captured_session.update(session)
            return {
                "synced_at": now,
                "runtime_session_synced_at": now,
                "runtime_session_id": "runtime-session-1",
                "runtime_sessions_visible": 1,
            }

        def fake_sync_receipts(current_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            assert current_store is not None
            return {
                "synced_at": now,
                "receipts_stored": 0,
                "inventory_stored": 0,
                "guard_events_v1": {"accepted": 0, "events": 0, "synced_at": now},
            }

        monkeypatch.setattr(guard_commands_module, "sync_runtime_session", fake_sync_runtime_session)
        monkeypatch.setattr(guard_commands_module, "sync_receipts", fake_sync_receipts)

        sync_rc = main(["guard", "service", "sync", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert sync_rc == 0
        assert payload["service"]["runtime"] == "openclaw"
        assert payload["runtime"]["runtime_session_id"] == "runtime-session-1"
        assert payload["receipts"]["receipts_stored"] == 0
        assert captured_session == {
            "harness": "openclaw",
            "surface": "agent-sdk",
            "status": "active",
            "client_name": "hol-guard",
            "client_title": "OpenClaw Runner",
            "client_version": "2.0.0",
            "workspace": "workspace_ops",
            "capabilities": ["hosted-runtime", "guard-cloud-sync"],
        }

    def test_guard_service_sync_preserves_empty_workspace(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        now = "2026-05-01T00:00:00Z"
        _seed_guard_cloud(store)
        store.set_sync_payload(
            "service_runtime_profile",
            {
                "runtime": "openclaw",
                "label": "OpenClaw Runner",
                "workspace": "",
                "surface": "agent-sdk",
                "client_name": "hol-guard",
                "client_title": "OpenClaw Runner",
                "client_version": "2.0.0",
            },
            now,
        )

        captured_session: dict[str, object] = {}

        def fake_sync_runtime_session(current_store: GuardStore, *, session: dict[str, object]) -> dict[str, object]:
            assert current_store is not None
            captured_session.update(session)
            return {
                "synced_at": now,
                "runtime_session_synced_at": now,
                "runtime_session_id": "runtime-session-1",
                "runtime_sessions_visible": 1,
            }

        def fake_sync_receipts(current_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            assert current_store is not None
            return {
                "synced_at": now,
                "receipts_stored": 0,
                "inventory_stored": 0,
                "guard_events_v1": {"accepted": 0, "events": 0, "synced_at": now},
            }

        monkeypatch.setattr(guard_commands_module, "sync_runtime_session", fake_sync_runtime_session)
        monkeypatch.setattr(guard_commands_module, "sync_receipts", fake_sync_receipts)

        sync_rc = main(["guard", "service", "sync", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert sync_rc == 0
        assert payload["runtime"]["runtime_session_id"] == "runtime-session-1"
        assert captured_session["workspace"] == ""

    def test_guard_service_status_reports_hosted_runtime_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        now = "2026-05-01T00:00:00Z"
        _seed_guard_cloud(store)
        store.set_sync_payload(
            "service_runtime_profile",
            {
                "runtime": "hermes",
                "label": "Hermes Telegram agent",
                "workspace": "workspace_ops",
                "surface": "agent-sdk",
                "client_name": "hol-guard",
                "client_title": "Hermes Telegram agent",
                "client_version": "2.0.0",
            },
            now,
        )
        store.set_sync_payload(
            "runtime_session_summary",
            {
                "runtime_session_id": "runtime-session-1",
                "runtime_session_synced_at": now,
                "runtime_sessions_visible": 1,
            },
            now,
        )
        store.set_sync_payload(
            "sync_summary",
            {
                "synced_at": now,
                "receipts_stored": 2,
            },
            now,
        )

        status_rc = main(["guard", "service", "status", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert status_rc == 0
        assert payload["configured"] is True
        assert payload["service"] == {
            "runtime": "hermes",
            "label": "Hermes Telegram agent",
            "workspace": "workspace_ops",
            "surface": "agent-sdk",
            "client_name": "hol-guard",
            "client_title": "Hermes Telegram agent",
            "client_version": "2.0.0",
        }
        assert payload["runtime"]["runtime_session_id"] == "runtime-session-1"
        assert payload["receipts"]["receipts_stored"] == 2
        assert payload["connection"]["sync_url"] == "https://hol.org/api/guard/receipts/sync"

    def test_guard_service_status_ignores_inline_legacy_sync_token(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        now = "2026-05-01T00:00:00Z"
        store.set_sync_payload(
            "credentials",
            {
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "token": "guard" + "_live" + "_secretvalue",
            },
            now,
        )
        store.set_sync_payload(
            "service_runtime_profile",
            {
                "runtime": "hermes",
                "label": "Hermes Telegram agent",
                "workspace": "workspace_ops",
                "surface": "agent-sdk",
                "client_name": "hol-guard",
                "client_title": "Hermes Telegram agent",
                "client_version": "2.0.0",
            },
            now,
        )

        status_rc = main(["guard", "service", "status", "--home", str(home_dir), "--json"])
        payload = json.loads(capsys.readouterr().out)

        assert status_rc == 0
        assert payload["configured"] is False
        assert payload["connection"] == {
            "configured": False,
            "sync_url": None,
        }
