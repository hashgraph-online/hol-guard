"""Guard CLI install opencode behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _build_guard_fixture, _write_json, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_install_auto_detects_configured_harnesses(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
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
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["auto_detected"] is True
        harnesses = {item["harness"] for item in output["managed_installs"]}
        assert {"codex", "claude-code", "cursor", "antigravity", "gemini", "opencode"} <= harnesses

    def test_guard_install_creates_opencode_runtime_overlay(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "name": "workspace-opencode",
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-server.py"],
                        "environment": {"API_BASE": "https://hol.org"},
                    }
                },
            },
        )

        rc = main(
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
        output = json.loads(capsys.readouterr().out)
        manifest = output["managed_install"]["manifest"]
        runtime_config_path = Path(str(manifest["runtime_config_path"]))
        runtime_payload = json.loads(runtime_config_path.read_text(encoding="utf-8"))
        managed_config_path = Path(str(manifest["managed_config_path"]))
        managed_payload = json.loads(managed_config_path.read_text(encoding="utf-8"))
        assert rc == 0
        assert output["managed_install"]["active"] is True
        assert manifest["shim_command"] == "guard-opencode"
        assert "skill" not in runtime_payload["permission"]
        assert runtime_payload["permission"]["danger_lab_*"] == "ask"
        assert runtime_payload["mcp"]["danger_lab"]["type"] == "local"
        assert runtime_payload["mcp"]["danger_lab"]["command"][0]
        assert runtime_payload["mcp"]["danger_lab"]["command"][3] == "guard"
        assert runtime_payload["mcp"]["danger_lab"]["command"][4] == "opencode-mcp-proxy"
        assert runtime_payload["mcp"]["danger_lab"]["environment"]["API_BASE"] == "https://hol.org"
        global_config_path = home_dir / ".config" / "opencode" / "opencode.json"
        assert manifest["managed_config_path"] == str(global_config_path)
        assert Path(str(manifest["backup_path"])).is_file()
        assert "danger_lab" not in managed_payload.get("mcp", {})
        assert managed_payload["permission"]["bash"]["rm -rf *"] == "deny"
        assert json.loads((workspace_dir / "opencode.json").read_text(encoding="utf-8"))["name"] == "workspace-opencode"

    def test_guard_reinstall_does_not_double_wrap_opencode_mcp_proxies(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-server.py"],
                    }
                }
            },
        )

        first_rc = main(
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
        json.loads(capsys.readouterr().out)

        second_rc = main(
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
        second_output = json.loads(capsys.readouterr().out)
        managed_config_path = Path(str(second_output["managed_install"]["manifest"]["managed_config_path"]))
        managed_payload = json.loads(managed_config_path.read_text(encoding="utf-8"))
        runtime_config_path = Path(str(second_output["managed_install"]["manifest"]["runtime_config_path"]))
        runtime_payload = json.loads(runtime_config_path.read_text(encoding="utf-8"))
        proxy_command = runtime_payload["mcp"]["danger_lab"]["command"]

        assert first_rc == 0
        assert second_rc == 0
        assert managed_payload["mcp"]["danger_lab"]["command"] == ["python3", "danger-server.py"]
        assert "opencode-mcp-proxy" in json.dumps(managed_payload["mcp"]["hol-guard::danger_lab"])
        assert proxy_command.count("opencode-mcp-proxy") == 1
        assert proxy_command[proxy_command.index("--command") + 1] == "python3"
        assert "--arg=danger-server.py" in proxy_command

    def test_guard_install_uses_global_jsonc_when_present(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        jsonc_path = home_dir / ".config" / "opencode" / "opencode.jsonc"
        jsonc_text = (
            "{\n"
            "  // keep jsonc target\n"
            '  "provider": {"openai": {}},\n'
            '  "mcp": {"danger_lab": {"type": "local", "command": ["python3", "danger-server.py"]}}\n'
            "}\n"
        )
        _write_text(
            jsonc_path,
            jsonc_text,
        )

        rc = main(
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
        output = json.loads(capsys.readouterr().out)
        managed_config_path = Path(str(output["managed_install"]["manifest"]["managed_config_path"]))
        managed_payload = json.loads(managed_config_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert managed_config_path == jsonc_path
        assert managed_payload["provider"] == {"openai": {}}
        assert managed_payload["mcp"]["danger_lab"]["command"] == ["python3", "danger-server.py"]
        assert "hol-guard::danger_lab" in managed_payload["mcp"]

    def test_guard_install_ignores_opencode_config_for_managed_target(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.jsonc"
        _write_text(custom_config_path, '{\n  "provider": {"openrouter": {}}\n}\n')
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        rc = main(
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
        output = json.loads(capsys.readouterr().out)
        managed_config_path = Path(str(output["managed_install"]["manifest"]["managed_config_path"]))
        json.loads(managed_config_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert managed_config_path == home_dir / ".config" / "opencode" / "opencode.json"
        assert json.loads(custom_config_path.read_text(encoding="utf-8"))["provider"] == {"openrouter": {}}

    def test_guard_install_targets_global_even_with_workspace_config(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_config_path = workspace_dir / "opencode.json"
        workspace_text = '{\n  "provider": {"anthropic": {}}\n}\n'
        global_config_path = home_dir / ".config" / "opencode" / "opencode.json"
        global_text = '{\n  "provider": {"openai": {}}\n}\n'
        _write_text(workspace_config_path, workspace_text)
        _write_text(global_config_path, global_text)

        rc = main(
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
        output = json.loads(capsys.readouterr().out)
        managed_config_path = Path(str(output["managed_install"]["manifest"]["managed_config_path"]))

        assert rc == 0
        assert managed_config_path == global_config_path
        assert managed_config_path.exists() is True
        assert json.loads(global_config_path.read_text(encoding="utf-8"))["provider"] == {"openai": {}}
        assert workspace_config_path.read_text(encoding="utf-8") == workspace_text

    def test_guard_uninstall_restores_opencode_project_config(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        original_payload = {
            "name": "workspace-opencode",
            "mcp": {
                "danger_lab": {
                    "type": "local",
                    "command": ["python3", "danger-server.py"],
                    "environment": {"API_BASE": "https://hol.org"},
                }
            },
        }
        _write_json(workspace_dir / "opencode.json", original_payload)
        original_text = (workspace_dir / "opencode.json").read_text(encoding="utf-8")
        global_config_path = home_dir / ".config" / "opencode" / "opencode.json"

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
        assert uninstall_output["managed_install"]["active"] is False
        assert (workspace_dir / "opencode.json").read_text(encoding="utf-8") == original_text
        assert global_config_path.exists() is False
        assert backup_path.exists() is False

    def test_guard_install_keeps_pythonpath_in_opencode_runtime_overlay(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "name": "workspace-opencode",
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-server.py"],
                    }
                },
            },
        )
        monkeypatch.setenv("PYTHONPATH", str(tmp_path / "src"))

        rc = main(
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
        output = json.loads(capsys.readouterr().out)
        manifest = output["managed_install"]["manifest"]
        runtime_config_path = Path(str(manifest["runtime_config_path"]))
        runtime_payload = json.loads(runtime_config_path.read_text(encoding="utf-8"))

        assert rc == 0
        assert runtime_payload["mcp"]["danger_lab"]["environment"]["PYTHONPATH"] == str(tmp_path / "src")

    def test_guard_uninstall_removes_generated_opencode_config_when_no_original_exists(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        config_path = workspace_dir / "opencode.json"

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
        assert config_path.exists() is False
        assert backup_path.exists() is False
