"""Guard CLI uninstall opencode behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_uninstall_uses_install_state_when_opencode_config_changes(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.jsonc"
        original_text = '{\n  "provider": {"openrouter": {}}\n}\n'
        _write_text(custom_config_path, original_text)
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        install_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        monkeypatch.delenv("OPENCODE_CONFIG")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        uninstall_output = json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        global_config_path = home_dir / ".config" / "opencode" / "opencode.json"
        assert uninstall_output["managed_install"]["manifest"]["managed_config_path"] == str(global_config_path)
        assert custom_config_path.read_text(encoding="utf-8") == original_text
        assert global_config_path.exists() is False
        assert backup_path.exists() is False
        assert state_path.exists() is False

    def test_guard_uninstall_uses_workspace_scoped_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_a = tmp_path / "workspace-a"
        workspace_b = tmp_path / "workspace-b"
        global_config_path = home_dir / ".config" / "opencode" / "opencode.json"
        original_global = '{\n  "provider": {"openai": {}}\n}\n'
        original_a = '{\n  "provider": {"openai": {}}\n}\n'
        original_b = '{\n  "provider": {"openrouter": {}}\n}\n'
        _write_text(global_config_path, original_global)
        _write_text(workspace_a / "opencode.json", original_a)
        _write_text(workspace_b / "opencode.json", original_b)

        install_a_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_a),
                "--json",
            ]
        )
        install_a_output = json.loads(capsys.readouterr().out)
        state_a_path = Path(str(install_a_output["managed_install"]["manifest"]["state_path"]))

        install_b_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_b),
                "--json",
            ]
        )
        install_b_output = json.loads(capsys.readouterr().out)
        state_b_path = Path(str(install_b_output["managed_install"]["manifest"]["state_path"]))

        uninstall_b_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_b),
                "--json",
            ]
        )
        uninstall_b_output = json.loads(capsys.readouterr().out)

        assert install_a_rc == 0
        assert install_b_rc == 0
        assert uninstall_b_rc == 0
        assert uninstall_b_output["managed_install"]["manifest"]["managed_config_path"] == str(global_config_path)
        assert (workspace_a / "opencode.json").read_text(encoding="utf-8") == original_a
        assert (workspace_b / "opencode.json").read_text(encoding="utf-8") == original_b
        assert global_config_path.read_text(encoding="utf-8") == original_global
        assert state_a_path == state_b_path
        assert state_b_path.exists() is False

    def test_guard_uninstall_uses_single_global_state_without_opencode_config(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        custom_config_path = home_dir / "custom" / "opencode.jsonc"
        global_config_path = home_dir / ".config" / "opencode" / "opencode.json"
        original_text = '{\n  "provider": {"openrouter": {}}\n}\n'
        custom_text = '{\n  "provider": {"anthropic": {}}\n}\n'
        _write_text(global_config_path, original_text)
        _write_text(custom_config_path, custom_text)
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        install_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        monkeypatch.delenv("OPENCODE_CONFIG")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        uninstall_output = json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert uninstall_output["managed_install"]["manifest"]["managed_config_path"] == str(global_config_path)
        assert global_config_path.read_text(encoding="utf-8") == original_text
        assert custom_config_path.read_text(encoding="utf-8") == custom_text
        assert state_path.exists() is False

    def test_guard_uninstall_keeps_config_when_backup_metadata_is_unreadable(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"

        install_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        config_path = Path(str(install_output["managed_install"]["manifest"]["managed_config_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        backup_path.write_text("{\n  bad json\n", encoding="utf-8")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert config_path.exists() is True
        assert backup_path.exists() is True
        assert state_path.exists() is True

    def test_guard_uninstall_keeps_config_when_backup_content_is_missing(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"

        install_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        config_path = Path(str(install_output["managed_install"]["manifest"]["managed_config_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        backup_path.write_text('{\n  "existed": true\n}\n', encoding="utf-8")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert config_path.exists() is True
        assert backup_path.exists() is True
        assert state_path.exists() is True

    def test_guard_uninstall_keeps_state_when_opencode_backup_is_missing(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"

        install_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        backup_path = Path(str(install_output["managed_install"]["manifest"]["backup_path"]))
        config_path = Path(str(install_output["managed_install"]["manifest"]["managed_config_path"]))
        state_path = Path(str(install_output["managed_install"]["manifest"]["state_path"]))
        backup_path.unlink()

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_rc == 0
        assert uninstall_rc == 0
        assert config_path.exists() is True
        assert backup_path.exists() is False
        assert state_path.exists() is True

    def test_guard_uninstall_avoids_ambiguous_workspace_state_matches(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        config_a_path = workspace_dir / "custom-a" / "opencode.jsonc"
        config_b_path = workspace_dir / "custom-b" / "opencode.jsonc"
        _write_text(config_a_path, '{\n  "provider": {"openai": {}}\n}\n')
        _write_text(config_b_path, '{\n  "provider": {"openrouter": {}}\n}\n')

        monkeypatch.setenv("OPENCODE_CONFIG", str(config_a_path))
        install_a_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_a_output = json.loads(capsys.readouterr().out)
        state_a_path = Path(str(install_a_output["managed_install"]["manifest"]["state_path"]))

        monkeypatch.setenv("OPENCODE_CONFIG", str(config_b_path))
        install_b_rc = main(
            [
                "guard",
                "install",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_b_output = json.loads(capsys.readouterr().out)
        state_b_path = Path(str(install_b_output["managed_install"]["manifest"]["state_path"]))
        monkeypatch.delenv("OPENCODE_CONFIG")
        config_a_before_uninstall = config_a_path.read_text(encoding="utf-8")
        config_b_before_uninstall = config_b_path.read_text(encoding="utf-8")

        uninstall_rc = main(
            [
                "guard",
                "uninstall",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        assert install_a_rc == 0
        assert install_b_rc == 0
        assert uninstall_rc == 0
        assert config_a_path.read_text(encoding="utf-8") == config_a_before_uninstall
        assert config_b_path.read_text(encoding="utf-8") == config_b_before_uninstall
        assert state_a_path == state_b_path
        assert state_a_path.exists() is False
