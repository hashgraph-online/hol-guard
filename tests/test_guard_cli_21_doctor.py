"""Guard CLI doctor behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.desktop_notifications import DesktopNotificationSetupResult
from codex_plugin_scanner.guard.store import GuardStore
from tests import test_guard_cli as _guard_cli_fixture
from tests.guard_cli_cloud_support import _seed_guard_cloud
from tests.guard_cli_fixture_support import _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_doctor_warns_when_codex_native_hooks_are_missing(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        _write_text(
            home_dir / ".codex" / "config.toml",
            """
approval_policy = "never"

[mcp_servers.test-stdio]
command = "/bin/sh"
args = ["-lc", "echo hi"]
""".strip()
            + "\n",
        )
        monkeypatch.setattr("codex_plugin_scanner.guard.adapters.codex._command_available", lambda command: True)

        rc = main(["guard", "doctor", "codex", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["native_hook_state"]["protection_active"] is False
        assert any("managed Codex hooks are missing" in warning for warning in output["warnings"])

    def test_guard_doctor_reports_runtime_detector_registry_state(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        _write_text(
            guard_home / "config.toml",
            "\n".join(
                [
                    "runtime_detector_registry = true",
                    "runtime_detector_timeout_ms = 75",
                    'runtime_detector_disabled_ids = ["secret.local"]',
                ]
            )
            + "\n",
        )
        monkeypatch.setattr("codex_plugin_scanner.guard.adapters.codex._command_available", lambda command: True)

        rc = main(["guard", "doctor", "codex", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["runtime_detector_registry"] == {
            "enabled": True,
            "debug_trace": False,
            "timeout_ms": 75,
            "disabled_detector_ids": ["secret.local"],
        }

    def test_guard_doctor_does_not_print_oauth_or_legacy_secret_material(
        self,
        tmp_path,
        monkeypatch,
        capsys,
    ):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        _write_text(
            home_dir / ".codex" / "config.toml",
            """
approval_policy = "never"

[mcp_servers.test-stdio]
command = "/bin/sh"
args = ["-lc", "echo hi"]
""".strip()
            + "\n",
        )
        monkeypatch.setattr("codex_plugin_scanner.guard.adapters.codex._command_available", lambda command: True)
        monkeypatch.setattr(
            GuardStore,
            "get_latest_guard_connect_state",
            lambda self, *, now: {
                "status": "retry_required",
                "milestone": "first_sync_failed",
                "reason": "Guard authorization expired. Run `hol-guard connect` to sign in again.",
                "authorization_code": "auth-code-secret",
                "user_code": "ZXCV-BNMQ",
                "pairing_secret": "pairing-secret-value",
                "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=ZXCV-BNMQ",
            },
        )
        store = GuardStore(guard_home)
        _seed_guard_cloud(store)
        _guard_cli_fixture._OAuthCredentialsFixture.seed(store, now="2026-06-01T00:00:00+00:00")

        forbidden_values = (
            "access-secret-value",
            "refresh-secret-value",
            "secret-key-material",
            "auth-code-secret",
            "ZXCV-BNMQ",
            "pairing-secret-value",
        )
        forbidden_labels = (
            "access_token",
            "refresh_token",
            "dpop_private_key",
            "authorization_code",
            "user_code",
            "pairing_secret",
            "guardpairsecret",
        )

        rc = main(
            [
                "guard",
                "doctor",
                "codex",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--json",
            ]
        )
        json_output = capsys.readouterr().out

        assert rc == 0
        json_payload = json.loads(json_output)
        assert json_payload["harness"] == "codex"
        assert json_payload["connect_health"]["connect_recovery_command"] == "hol-guard connect"
        assert json_payload["connect_health"]["oauth_storage_health"] == {"state": "healthy"}
        assert json_payload["connect_health"]["latest_connect_state"]["status"] == "retry_required"
        assert set(json_payload["connect_health"]["oauth_storage_health"]) == {"state"}
        for value in forbidden_values:
            assert value not in json_output
        lowered_json_output = json_output.lower()
        for label in forbidden_labels:
            assert label not in lowered_json_output

        rc = main(
            [
                "guard",
                "doctor",
                "codex",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
            ]
        )
        human_output = capsys.readouterr().out

        assert rc == 0
        assert "OAuth storage" in human_output
        assert "Connect state" in human_output
        assert "hol-guard connect" in human_output
        for value in forbidden_values:
            assert value not in human_output
        lowered_human_output = human_output.lower()
        for label in forbidden_labels:
            assert label not in lowered_human_output

    def test_guard_doctor_notifications_opens_system_settings(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        calls: list[tuple[Path, str, bool]] = []

        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:5474")
        monkeypatch.setattr(guard_commands_module, "desktop_notification_setup_supported", lambda: True)

        def fake_setup(
            guard_home_path: Path,
            *,
            approval_url: str,
            force: bool = False,
        ) -> DesktopNotificationSetupResult:
            calls.append((guard_home_path, approval_url, force))
            return DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=True,
                settings_url="x-apple.systempreferences:com.apple.Notifications-Settings.extension",
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            )

        monkeypatch.setattr(guard_commands_module, "ensure_desktop_notification_setup", fake_setup)

        rc = main(
            [
                "guard",
                "doctor",
                "--notifications",
                "--force-notification-settings",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert calls == [
            (
                guard_home,
                "http://127.0.0.1:5474/approvals/notification-preview",
                True,
            )
        ]
        assert output["desktop_notifications"]["platform"] == "Darwin"
        assert output["desktop_notifications"]["supported"] is True
        assert output["desktop_notifications"]["preview_sent"] is True
        assert output["desktop_notifications"]["settings_opened"] is True
        assert output["desktop_notifications"]["settings_url"] == (
            "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
        )
        assert output["desktop_notifications"]["already_prompted"] is False
        assert output["desktop_notifications"]["notifier_path"] == "/usr/local/bin/terminal-notifier"
        assert "terminal-notifier" in output["desktop_notifications"]["guidance"]

    def test_guard_doctor_notifications_human_output_uses_setup_renderer(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"

        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:5474")
        monkeypatch.setattr(guard_commands_module, "desktop_notification_setup_supported", lambda: True)
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_desktop_notification_setup",
            lambda *_args, **_kwargs: DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=True,
                settings_url="x-apple.systempreferences:com.apple.Notifications-Settings.extension",
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            ),
        )

        rc = main(
            [
                "guard",
                "doctor",
                "--notifications",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
            ]
        )
        output = capsys.readouterr().out

        assert rc == 0
        assert "Guard notification setup" in output
        assert "Platform" in output
        assert "Darwin" in output
        assert "Settings opened" in output
        assert "unknown" not in output.lower()

    def test_guard_doctor_notifications_skips_daemon_when_setup_unsupported(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        calls: list[tuple[Path, str, bool]] = []

        def fail_daemon(_guard_home: Path) -> str:
            raise RuntimeError("daemon should not start")

        def fake_setup(
            guard_home_path: Path,
            *,
            approval_url: str,
            force: bool = False,
        ) -> DesktopNotificationSetupResult:
            calls.append((guard_home_path, approval_url, force))
            return DesktopNotificationSetupResult(
                platform="Linux",
                supported=False,
                preview_sent=False,
                settings_opened=False,
                settings_url=None,
                already_prompted=False,
                notifier_path=None,
            )

        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", fail_daemon)
        monkeypatch.setattr(guard_commands_module, "desktop_notification_setup_supported", lambda: False)
        monkeypatch.setattr(guard_commands_module, "ensure_desktop_notification_setup", fake_setup)

        rc = main(
            [
                "guard",
                "doctor",
                "--notifications",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert calls == [(guard_home, "hol-guard://notification-preview", False)]
        assert output["desktop_notifications"]["supported"] is False

    def test_guard_doctor_notifications_falls_back_when_daemon_start_fails(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        calls: list[tuple[Path, str, bool]] = []

        def fail_daemon(_guard_home: Path) -> str:
            raise RuntimeError("port conflict")

        def fake_setup(
            guard_home_path: Path,
            *,
            approval_url: str,
            force: bool = False,
        ) -> DesktopNotificationSetupResult:
            calls.append((guard_home_path, approval_url, force))
            return DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=True,
                settings_url="x-apple.systempreferences:com.apple.Notifications-Settings.extension",
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            )

        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", fail_daemon)
        monkeypatch.setattr(guard_commands_module, "desktop_notification_setup_supported", lambda: True)
        monkeypatch.setattr(guard_commands_module, "ensure_desktop_notification_setup", fake_setup)

        rc = main(
            [
                "guard",
                "doctor",
                "--notifications",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert calls == [(guard_home, "hol-guard://notification-preview", False)]
        assert output["desktop_notifications"]["settings_opened"] is True

    def test_guard_doctor_human_output_includes_detector_registry_line(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        _write_text(guard_home / "config.toml", "runtime_detector_registry = true\n")
        monkeypatch.setattr("codex_plugin_scanner.guard.adapters.codex._command_available", lambda command: True)

        rc = main(["guard", "doctor", "codex", "--home", str(home_dir), "--guard-home", str(guard_home)])
        output = capsys.readouterr().out

        assert rc == 0
        assert "Detector registry" in output
        assert "enabled" in output
        assert "Use status for current posture" in output
        assert "Use diff for changed artifacts" in output
        assert "Use events for the local timeline" in output
