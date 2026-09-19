"""Guard CLI update codex workspace behavior."""

from __future__ import annotations

import json
import sqlite3
import subprocess

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands as guard_update_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_fixture_support import _read_codex_config, _read_codex_hooks, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_update_repairs_codex_when_managed_install_lookup_fails(self, tmp_path, monkeypatch, capsys):
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
        context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=home_dir)
        _write_text(guard_update_commands_module.CodexHarnessAdapter._backup_path(context), "# backup\n")
        monkeypatch.setattr(
            guard_update_commands_module.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(
                command,
                0,
                stdout="hol-guard is already at latest version 2.0.39",
                stderr="",
            ),
        )
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.39")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.39"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.39")
        original_get_managed_install = GuardStore.get_managed_install
        lookup_calls: list[str] = []

        def _raise_only_on_initial_lookup(self, harness: str):
            lookup_calls.append(harness)
            if len(lookup_calls) == 1:
                raise sqlite3.DatabaseError("db corrupted")
            return original_get_managed_install(self, harness)

        monkeypatch.setattr(
            GuardStore,
            "get_managed_install",
            _raise_only_on_initial_lookup,
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "current"
        assert output["managed_install"]["harness"] == "codex"
        assert output["managed_install"]["active"] is True
        assert _read_codex_hooks(home_dir / ".codex" / "config.toml")["PreToolUse"]

    def test_guard_update_does_not_infer_codex_repair_workspace_from_caller_cwd(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_text(
            workspace_dir / ".codex" / "config.toml",
            """
approval_policy = "never"

[mcp_servers.test-stdio]
command = "/bin/sh"
args = ["-lc", "echo hi"]
""".strip()
            + "\n",
        )
        workspace_context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir)
        _write_text(guard_update_commands_module.CodexHarnessAdapter._backup_path(workspace_context), "# backup\n")
        monkeypatch.chdir(workspace_dir)
        monkeypatch.setattr(
            guard_update_commands_module.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(
                command,
                0,
                stdout="hol-guard is already at latest version 2.0.39",
                stderr="",
            ),
        )
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.39")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.39"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.39")
        original_get_managed_install = GuardStore.get_managed_install
        lookup_calls: list[str] = []

        def _raise_only_on_initial_lookup(self, harness: str):
            lookup_calls.append(harness)
            if len(lookup_calls) == 1:
                raise sqlite3.DatabaseError("db corrupted")
            return original_get_managed_install(self, harness)

        monkeypatch.setattr(
            GuardStore,
            "get_managed_install",
            _raise_only_on_initial_lookup,
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "current"
        assert output["managed_install"]["workspace"] is None
        assert output["managed_install"]["active"] is True
        assert _read_codex_hooks(home_dir / ".codex" / "config.toml")["PreToolUse"]
        assert "hooks" not in _read_codex_config(workspace_dir / ".codex" / "config.toml")

    def test_guard_update_does_not_adopt_empty_caller_workspace_during_backup_repair(
        self, tmp_path, monkeypatch, capsys
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        workspace_context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir)
        _write_text(guard_update_commands_module.CodexHarnessAdapter._backup_path(workspace_context), "# backup\n")
        monkeypatch.chdir(workspace_dir)
        monkeypatch.setattr(
            guard_update_commands_module.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(
                command,
                0,
                stdout="hol-guard is already at latest version 2.0.39",
                stderr="",
            ),
        )
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.39")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.39"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.39")
        original_get_managed_install = GuardStore.get_managed_install
        lookup_calls: list[str] = []

        def _raise_only_on_initial_lookup(self, harness: str):
            lookup_calls.append(harness)
            if len(lookup_calls) == 1:
                raise sqlite3.DatabaseError("db corrupted")
            return original_get_managed_install(self, harness)

        monkeypatch.setattr(
            GuardStore,
            "get_managed_install",
            _raise_only_on_initial_lookup,
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "current"
        assert output["managed_install"]["workspace"] is None
        assert output["managed_install"]["active"] is True
        assert _read_codex_hooks(home_dir / ".codex" / "config.toml")["PreToolUse"]
        assert (workspace_dir / ".codex" / "config.toml").exists() is False
