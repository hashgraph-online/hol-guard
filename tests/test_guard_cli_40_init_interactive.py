"""Guard CLI init interactive behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.desktop_notifications import DesktopNotificationSetupResult
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_init_human_output_reports_notification_failure(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"

        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_open_approval_center",
            lambda approval_center_url, *, store, config, open_key=None, force_open=False: {
                "opened": True,
                "reason": "opened",
                "browser_url": f"{approval_center_url}/home",
            },
        )
        monkeypatch.setattr(
            guard_commands_module,
            "apply_managed_install",
            lambda *_args, **_kwargs: {"managed_installs": [{"harness": "codex", "active": True}]},
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_run_guard_device_connect_flow",
            lambda **_kwargs: {"connected": False, "status": "waiting_for_browser"},
        )
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_desktop_notification_setup",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("notification permission failed")),
        )

        rc = main(["guard", "init", "--yes", "--home", str(home_dir), "--guard-home", str(guard_home)])
        output = capsys.readouterr().out

        assert rc == 1
        assert "HOL Guard init needs attention" in output
        assert "needs attention (notification permission failed)" in output
        assert "not supported on this OS" not in output

    def test_guard_init_interactive_no_skips_only_cloud_step(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        answers = iter(["y", "y", "n", "y"])
        dashboard_calls: list[str] = []
        install_calls: list[bool] = []
        notification_calls: list[bool] = []

        monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(guard_commands_module, "_prompt_init_step", lambda *_args, **_kwargs: next(answers))
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_open_approval_center",
            lambda approval_center_url, *, store, config, open_key=None, force_open=False: (
                dashboard_calls.append(approval_center_url),
                {"opened": True, "reason": "opened", "browser_url": f"{approval_center_url}/home"},
            )[-1],
        )
        monkeypatch.setattr(
            guard_commands_module,
            "apply_managed_install",
            lambda *_args, **_kwargs: (
                install_calls.append(True),
                {"managed_installs": [{"harness": "codex", "active": True}]},
            )[-1],
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_run_guard_device_connect_flow",
            lambda **_kwargs: pytest.fail("cloud connect should be skipped"),
        )

        def fake_setup(
            guard_home_path: Path,
            *,
            approval_url: str,
            force: bool = False,
        ) -> DesktopNotificationSetupResult:
            del guard_home_path, approval_url, force
            notification_calls.append(True)
            return DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=False,
                settings_url=None,
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            )

        monkeypatch.setattr(guard_commands_module, "ensure_desktop_notification_setup", fake_setup)

        rc = main(["guard", "init", "--home", str(home_dir), "--guard-home", str(guard_home)])
        output = capsys.readouterr().out

        assert rc == 0
        assert dashboard_calls == ["http://127.0.0.1:5474"]
        assert install_calls == [True]
        assert notification_calls == [True]
        assert "skipped (user skipped)" in output
        assert "Progressive init plan" in output

    def test_guard_init_interactive_runs_each_step_before_prompting_next(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        events: list[str] = []
        answers = iter(["y", "y", "y", "y"])

        monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: True)

        def prompt_step(step: dict[str, object]) -> str:
            events.append(f"prompt:{step['id']}")
            return next(answers)

        monkeypatch.setattr(guard_commands_module, "_prompt_init_step", prompt_step)
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda _guard_home: events.append("run:dashboard-daemon") or "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_open_approval_center",
            lambda approval_center_url, *, store, config, open_key=None, force_open=False: (
                events.append("run:dashboard-open"),
                {"opened": True, "reason": "opened", "browser_url": f"{approval_center_url}/home"},
            )[-1],
        )
        monkeypatch.setattr(
            guard_commands_module,
            "apply_managed_install",
            lambda *_args, **_kwargs: (
                events.append("run:apps"),
                {"managed_installs": [{"harness": "codex", "active": True}]},
            )[-1],
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_run_guard_device_connect_flow",
            lambda **_kwargs: events.append("run:cloud") or {"connected": True, "status": "connected"},
        )

        def fake_setup(
            guard_home_path: Path,
            *,
            approval_url: str,
            force: bool = False,
        ) -> DesktopNotificationSetupResult:
            del guard_home_path, approval_url, force
            events.append("run:notifications")
            return DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=False,
                settings_url=None,
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            )

        monkeypatch.setattr(guard_commands_module, "ensure_desktop_notification_setup", fake_setup)

        rc = main(["guard", "init", "--home", str(home_dir), "--guard-home", str(guard_home)])

        assert rc == 0
        assert events == [
            "prompt:dashboard",
            "run:dashboard-daemon",
            "run:dashboard-open",
            "prompt:apps",
            "run:apps",
            "prompt:cloud",
            "run:cloud",
            "prompt:notifications",
            "run:notifications",
        ]

    def test_guard_init_skip_flags_do_not_run_install_cloud_or_notifications(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_open_approval_center",
            lambda approval_center_url, *, store, config, open_key=None, force_open=False: {
                "opened": True,
                "reason": "opened",
                "browser_url": approval_center_url,
            },
        )
        monkeypatch.setattr(
            guard_commands_module,
            "apply_managed_install",
            lambda *_args, **_kwargs: pytest.fail("install should be skipped"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_run_guard_device_connect_flow",
            lambda **_kwargs: pytest.fail("cloud connect should be skipped"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_desktop_notification_setup",
            lambda *_args, **_kwargs: pytest.fail("notification setup should be skipped"),
        )

        rc = main(
            [
                "guard",
                "init",
                "--skip-apps",
                "--skip-cloud",
                "--skip-notifications",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["apps"] == {"skipped": True, "reason": "skip_apps"}
        assert output["cloud"] == {"skipped": True, "reason": "skip_cloud"}
        assert output["desktop_notifications"] == {
            "skipped": True,
            "reason": "skip_notifications",
        }
