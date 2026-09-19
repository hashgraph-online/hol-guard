"""Guard CLI service credentials behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_service_login_rejects_pasted_token_and_redirects_to_connect(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        original_device_metadata = store.get_device_metadata()

        login_rc = main(
            [
                "guard",
                "service",
                "login",
                "--home",
                str(home_dir),
                "--runtime",
                "hermes",
                "--label",
                "Hermes Telegram agent",
                "--workspace",
                "workspace_ops",
                "--sync-url",
                "https://hol.org/api/guard/receipts/sync",
                "--token",
                "guard" + "_live" + "_secretvalue",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)

        assert login_rc == 2
        assert payload == {
            "logged_in": False,
            "error": (
                "Hosted runtime token login is retired. "
                "Run `hol-guard connect --headless` or `hol-guard connect` instead."
            ),
            "service": {
                "runtime": "hermes",
                "label": "Hermes Telegram agent",
                "workspace": "workspace_ops",
            },
        }
        assert store.get_cloud_sync_profile() is None
        assert store.get_sync_payload("service_runtime_profile") is None
        assert store.get_device_metadata() == original_device_metadata

    def test_guard_service_login_without_token_points_to_ci_safe_headless_connect(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        login_rc = main(
            [
                "guard",
                "service",
                "login",
                "--home",
                str(home_dir),
                "--runtime",
                "hermes",
                "--label",
                "Hermes Telegram agent",
                "--workspace",
                "workspace_ops",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)

        assert login_rc == 2
        assert (
            payload["next_action"]["command"]
            == "hol-guard connect --headless --ci-safe --workspace workspace_ops --label 'Hermes Telegram agent'"
        )
        assert store.get_cloud_sync_profile() is None

    def test_guard_service_login_rejects_blank_token(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        login_rc = main(
            [
                "guard",
                "service",
                "login",
                "--home",
                str(home_dir),
                "--runtime",
                "hermes",
                "--label",
                "Hermes Telegram agent",
                "--workspace",
                "workspace_ops",
                "--sync-url",
                "https://hol.org/api/guard/receipts/sync",
                "--token",
                "   ",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)

        assert login_rc == 2
        assert payload == {
            "logged_in": False,
            "error": (
                "Hosted runtime token login is retired. "
                "Run `hol-guard connect --headless` or `hol-guard connect` instead."
            ),
            "service": {
                "runtime": "hermes",
                "label": "Hermes Telegram agent",
                "workspace": "workspace_ops",
            },
        }
        assert store.get_cloud_sync_profile() is None

    def test_guard_service_sync_prerequisite_points_to_guard_connect(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        sync_rc = main(
            [
                "guard",
                "service",
                "sync",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)

        assert sync_rc == 1
        assert payload == {
            "synced": False,
            "error": "Hosted Guard runtime is not configured yet. Run `hol-guard connect` first.",
        }
