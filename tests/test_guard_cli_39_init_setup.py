"""Guard CLI init setup behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import commands_support_workspace as guard_workspace_support_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.desktop_notifications import DesktopNotificationSetupResult
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_init_requires_progressive_approval_before_side_effects(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        prompt_calls: list[bool] = []

        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda *_args, **_kwargs: pytest.fail("dashboard should wait for approval"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "apply_managed_install",
            lambda *_args, **_kwargs: pytest.fail("app install should wait for approval"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_run_guard_device_connect_flow",
            lambda **_kwargs: pytest.fail("cloud connect should wait for approval"),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_desktop_notification_setup",
            lambda *_args, **_kwargs: pytest.fail("notification setup should wait for approval"),
        )
        monkeypatch.setattr(guard_commands_module.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(
            guard_commands_module,
            "_prompt_init_step",
            lambda *_args, **_kwargs: prompt_calls.append(True) or "y",
        )

        rc = main(["guard", "init", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert prompt_calls == []
        assert output["status"] == "approval_required"
        assert [step["id"] for step in output["plan"]] == [
            "dashboard",
            "apps",
            "cloud",
            "notifications",
        ]
        assert output["dashboard"] == {"skipped": True, "reason": "needs_approval"}
        assert output["apps"] == {"skipped": True, "reason": "needs_approval"}
        assert output["cloud"] == {"skipped": True, "reason": "needs_approval"}
        assert output["desktop_notifications"] == {"skipped": True, "reason": "needs_approval"}
        assert output["next_command"] == "hol-guard init --yes"

    def test_guard_init_runs_apps_cloud_notifications_and_dashboard_with_yes(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"
        dashboard_calls: list[tuple[str, str | None, bool]] = []
        install_calls: list[tuple[str, str | None, bool]] = []
        notification_calls: list[tuple[Path, str, bool]] = []

        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_open_approval_center",
            lambda approval_center_url, *, store, config, open_key=None, force_open=False: (
                dashboard_calls.append((approval_center_url, open_key, force_open)),
                {"opened": True, "reason": "opened", "browser_url": f"{approval_center_url}/home"},
            )[-1],
        )

        def fake_install(
            mode: str,
            harness: str | None,
            all_flag: bool,
            context: HarnessContext,
            store: GuardStore,
            workspace: str | None,
            now: str,
        ) -> dict[str, object]:
            del context, store, workspace, now
            install_calls.append((mode, harness, all_flag))
            return {
                "managed_installs": [
                    {"harness": "codex", "active": True, "workspace": None, "manifest": {}},
                    {"harness": "opencode", "active": True, "workspace": None, "manifest": {}},
                ]
            }

        monkeypatch.setattr(guard_commands_module, "apply_managed_install", fake_install)

        def fake_device_connect_flow(**kwargs: object) -> dict[str, object]:
            assert kwargs["open_browser"] is guard_workspace_support_module.open_browser_url
            return {
                "connected": False,
                "status": "waiting_for_browser",
                "connect_url": "https://hol.org/guard/connect",
            }

        monkeypatch.setattr(guard_commands_module, "_run_guard_device_connect_flow", fake_device_connect_flow)

        def fake_setup(
            guard_home_path: Path,
            *,
            approval_url: str,
            force: bool = False,
        ) -> DesktopNotificationSetupResult:
            notification_calls.append((guard_home_path, approval_url, force))
            return DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=True,
                settings_url="x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=fr.julienxx.oss.terminal-notifier",
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            )

        monkeypatch.setattr(guard_commands_module, "ensure_desktop_notification_setup", fake_setup)

        rc = main(["guard", "init", "--yes", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["mode"] == "auto_approved"
        assert [step["decision"] for step in output["plan"]] == [
            "approved",
            "approved",
            "approved",
            "approved",
        ]
        assert dashboard_calls == [("http://127.0.0.1:5474", "init", True)]
        assert install_calls == [("install", None, True)]
        assert output["dashboard"]["opened"] is True
        assert output["apps"]["skipped"] is False
        assert [item["harness"] for item in output["apps"]["managed_installs"]] == ["codex", "opencode"]
        assert output["cloud"]["status"] == "waiting_for_browser"
        assert output["cloud"]["sync_url"] == "https://hol.org/api/guard/receipts/sync"
        assert output["desktop_notifications"]["preview_sent"] is True
        assert "terminal-notifier" in output["desktop_notifications"]["guidance"]
        assert notification_calls == [(guard_home, "http://127.0.0.1:5474/approvals/notification-preview", True)]

    def test_guard_init_yes_fails_when_notification_setup_fails(self, tmp_path, capsys, monkeypatch):
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

        rc = main(["guard", "init", "--yes", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["status"] == "needs_attention"
        assert output["desktop_notifications"]["error"] == "notification permission failed"
        assert output["desktop_notifications"]["supported"] is True

    @pytest.mark.parametrize(
        ("failing_step", "payload_key", "message"),
        [
            ("dashboard", "dashboard", "dashboard unavailable"),
            ("apps", "apps", "managed install failed"),
            ("cloud", "cloud", "cloud connect failed"),
        ],
    )
    def test_guard_init_yes_fails_when_approved_step_fails(
        self,
        tmp_path,
        capsys,
        monkeypatch,
        failing_step: str,
        payload_key: str,
        message: str,
    ):
        home_dir = tmp_path / "home"
        guard_home = tmp_path / "guard-home"

        def fake_daemon(_guard_home: Path) -> str:
            if failing_step == "dashboard":
                raise RuntimeError(message)
            return "http://127.0.0.1:5474"

        def fake_open(
            approval_center_url: str,
            *,
            store: GuardStore,
            config: GuardConfig,
            open_key: str | None = None,
            force_open: bool = False,
        ) -> dict[str, object]:
            del store, config, open_key, force_open
            return {"opened": True, "reason": "opened", "browser_url": f"{approval_center_url}/home"}

        def fake_install(*_args: object, **_kwargs: object) -> dict[str, object]:
            if failing_step == "apps":
                raise ValueError(message)
            return {"managed_installs": [{"harness": "codex", "active": True}]}

        def fake_connect(**_kwargs: object) -> dict[str, object]:
            if failing_step == "cloud":
                raise RuntimeError(message)
            return {"connected": False, "status": "waiting_for_browser"}

        monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", fake_daemon)
        monkeypatch.setattr(guard_commands_module, "_open_approval_center", fake_open)
        monkeypatch.setattr(guard_commands_module, "apply_managed_install", fake_install)
        monkeypatch.setattr(guard_commands_module, "_run_guard_device_connect_flow", fake_connect)
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_desktop_notification_setup",
            lambda *_args, **_kwargs: DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=False,
                settings_url=None,
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            ),
        )

        rc = main(["guard", "init", "--yes", "--home", str(home_dir), "--guard-home", str(guard_home), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["status"] == "needs_attention"
        assert output[payload_key]["error"] == message
