"""Guard CLI update codex config behavior."""

from __future__ import annotations

import json
import subprocess

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import update_commands as guard_update_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_fixture_support import _read_codex_hooks, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_update_repairs_missing_codex_config_for_managed_install(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        GuardStore(home_dir).set_managed_install(
            "codex",
            True,
            None,
            {"backup_path": str(home_dir / "managed" / "codex" / "repair.backup.toml")},
            "2026-04-21T00:00:00+00:00",
        )

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

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)
        config_text = (home_dir / ".codex" / "config.toml").read_text(encoding="utf-8")
        hooks_payload = _read_codex_hooks(home_dir / ".codex" / "config.toml")

        assert rc == 0
        assert output["status"] == "current"
        assert output["managed_install"]["harness"] == "codex"
        assert output["managed_install"]["active"] is True
        assert "hooks = true" in config_text
        assert "codex_hooks" not in config_text
        assert hooks_payload["PreToolUse"]

    def test_guard_update_repairs_workspace_codex_install_in_recorded_workspace(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        GuardStore(home_dir).set_managed_install(
            "codex",
            True,
            str(workspace_dir),
            {"backup_path": str(home_dir / "managed" / "codex" / "workspace-repair.backup.toml")},
            "2026-04-21T00:00:00+00:00",
        )

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

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)
        config_text = (home_dir / ".codex" / "config.toml").read_text(encoding="utf-8")
        hooks_payload = _read_codex_hooks(home_dir / ".codex" / "config.toml")

        assert rc == 0
        assert output["status"] == "current"
        assert output["managed_install"]["workspace"] == str(workspace_dir)
        assert "hooks = true" in config_text
        assert "codex_hooks" not in config_text
        assert hooks_payload["PreToolUse"]
        assert (workspace_dir / ".codex" / "config.toml").exists() is False

    def test_guard_update_fails_closed_on_malformed_codex_config(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        _write_text(home_dir / ".codex" / "config.toml", "[broken\n")
        GuardStore(home_dir).set_managed_install(
            "codex",
            True,
            None,
            {"backup_path": str(home_dir / "managed" / "codex" / "repair.backup.toml")},
            "2026-04-21T00:00:00+00:00",
        )
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

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "current"
        assert "managed_install" not in output
        assert any("codex_hook_inventory_source_malformed" in note for note in output["notes"])
        assert (home_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == "[broken\n"

    def test_guard_update_does_not_adopt_unmanaged_codex_config(self, tmp_path, monkeypatch, capsys):
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

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "current"
        assert "managed_install" not in output
        assert (home_dir / ".codex" / "hooks.json").exists() is False

    def test_guard_update_reports_malformed_codex_hooks_without_crashing(self, tmp_path, monkeypatch, capsys):
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
        _write_text(home_dir / ".codex" / "hooks.json", "{not-json")
        GuardStore(home_dir).set_managed_install(
            "codex",
            True,
            None,
            {"backup_path": str(home_dir / "managed" / "codex" / "repair.backup.toml")},
            "2026-04-21T00:00:00+00:00",
        )
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

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "current"
        assert "managed_install" not in output
        assert any("Could not repair Codex protection during update" in note for note in output["notes"])

    def test_guard_update_reports_codex_repair_write_failures(self, tmp_path, monkeypatch, capsys):
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
        GuardStore(home_dir).set_managed_install(
            "codex",
            True,
            None,
            {"backup_path": str(home_dir / "managed" / "codex" / "repair.backup.toml")},
            "2026-04-21T00:00:00+00:00",
        )
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
        monkeypatch.setattr(
            guard_update_commands_module,
            "apply_managed_install",
            lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("read only")),
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "current"
        assert "managed_install" not in output
        assert any("Could not repair Codex protection during update: read only" in note for note in output["notes"])
