"""Guard CLI install remove behavior."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from tests.guard_cli_fixture_support import _build_guard_fixture
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_uninstall_auto_detects_managed_harnesses(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        install_rc = main(
            [
                "guard",
                "install",
                "--all",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "--all",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert all(item["active"] is False for item in output["managed_installs"])

    def test_guard_install_requires_harness_without_all(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "install",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        stderr = capsys.readouterr().err

        assert rc == 2
        assert "Guard install requires a harness or --all." in stderr

    def test_guard_uninstall_requires_harness_all_or_self(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "uninstall",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        stderr = capsys.readouterr().err

        assert rc == 2
        assert "Guard uninstall requires a harness or --all or --self." in stderr

    def test_guard_uninstall_self_runs_full_package_removal(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        uninstall_calls: list[dict[str, object]] = []

        monkeypatch.setattr(
            guard_commands_module,
            "run_guard_self_uninstall",
            lambda **kwargs: (
                uninstall_calls.append(kwargs)
                or {
                    "self_uninstall": True,
                    "status": "removed",
                    "current_version": "2.0.764",
                    "installer": "pipx",
                    "dry_run": False,
                    "command": ["pipx", "uninstall", "hol-guard"],
                    "message": "Removed HOL Guard from this environment.",
                },
                0,
            ),
        )

        rc = main(["guard", "uninstall", "--self", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert uninstall_calls and uninstall_calls[0]["dry_run"] is False
        assert output["self_uninstall"] is True
        assert output["status"] == "removed"
        assert output["command"] == ["pipx", "uninstall", "hol-guard"]

    def test_guard_uninstall_self_rejects_harness_or_all(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        rc = main(["guard", "uninstall", "codex", "--self", "--home", str(home_dir)])
        stderr = capsys.readouterr().err

        assert rc == 2
        assert "Guard self uninstall does not accept a harness or --all." in stderr

    @pytest.mark.parametrize("command", ["install", "uninstall"])
    def test_guard_install_commands_reject_harness_with_all(self, tmp_path, capsys, command: str):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                command,
                "codex",
                "--all",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        stderr = capsys.readouterr().err

        assert rc == 2
        assert "Pass either a harness or --all, not both." in stderr
