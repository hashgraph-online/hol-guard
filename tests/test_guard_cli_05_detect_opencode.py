"""Guard CLI detect opencode behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _write_json, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_detect_scopes_opencode_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {
                "mcp": {
                    "shared-tools": {"type": "local", "command": ["node", "global.js"]},
                }
            },
        )
        _write_json(
            workspace_dir / "opencode.json",
            {
                "mcp": {
                    "shared-tools": {"type": "local", "command": ["node", "project.js"]},
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = [item["artifact_id"] for item in output["harnesses"][0]["artifacts"]]

        assert rc == 0
        assert artifact_ids == ["opencode:global:shared-tools", "opencode:project:shared-tools"]

    def test_guard_detect_reports_opencode_plugins_skills_and_commands(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {
                "plugins": [["opencode-global-plugin", {"mode": "strict", "token": "top-secret"}]],
                "command": {
                    "global-review": {
                        "template": "Review the current diff.",
                        "description": "Global review command",
                    }
                },
            },
        )
        _write_json(
            workspace_dir / "opencode.json",
            {
                "plugins": ["opencode-project-plugin"],
                "command": {
                    "project-review": {
                        "template": "Review the workspace change set.",
                        "description": "Project review command",
                    }
                },
            },
        )
        _write_text(home_dir / ".config" / "opencode" / "plugins" / "global-local.mjs", "export default {};\n")
        _write_text(home_dir / ".config" / "opencode" / "plugins" / "hol-guard-pretool.ts", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "plugins" / "project-local.mjs", "export default {};\n")
        _write_text(home_dir / ".config" / "opencode" / "commands" / "global-cmd.md", "# global\n")
        _write_text(workspace_dir / ".opencode" / "commands" / "triage.md", "# triage\n")
        _write_text(
            home_dir / ".config" / "opencode" / "skills" / "global-skill" / "SKILL.md",
            "---\nname: global-skill\ndescription: Global skill\n---\n",
        )
        _write_text(
            workspace_dir / ".opencode" / "skills" / "repo-skill" / "SKILL.md",
            "---\nname: repo-skill\ndescription: Repo skill\n---\n",
        )
        _write_text(
            workspace_dir / ".claude" / "skills" / "claude-skill" / "SKILL.md",
            "---\nname: claude-skill\ndescription: Claude-compatible skill\n---\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert "opencode:global:plugin:opencode-global-plugin" in artifacts
        assert "opencode:project:plugin:opencode-project-plugin" in artifacts
        assert "opencode:global:plugin-file:plugins/global-local.mjs" in artifacts
        assert "opencode:global:plugin-file:plugins/hol-guard-pretool.ts" in artifacts
        assert "opencode:project:plugin-file:plugins/project-local.mjs" in artifacts
        assert "opencode:global:config-command:global-review" in artifacts
        assert "opencode:project:config-command:project-review" in artifacts
        assert "opencode:global:command:global-cmd" in artifacts
        assert "opencode:project:command:triage" in artifacts
        assert "opencode:global:skill:opencode:skills/global-skill" in artifacts
        assert "opencode:project:skill:opencode:skills/repo-skill" in artifacts
        assert "opencode:project:skill:claude:skills/claude-skill" in artifacts
        assert artifacts["opencode:project:plugin-file:plugins/project-local.mjs"]["artifact_type"] == "plugin"
        assert artifacts["opencode:global:plugin-file:plugins/hol-guard-pretool.ts"]["artifact_type"] == "daemon_plugin"
        assert artifacts["opencode:project:config-command:project-review"]["metadata"]["template"] == (
            "Review the workspace change set."
        )
        assert artifacts["opencode:global:plugin:opencode-global-plugin"]["metadata"]["mode"] == "strict"
        assert artifacts["opencode:global:plugin:opencode-global-plugin"]["metadata"]["token"] == "*****"
        assert artifacts["opencode:project:skill:claude:skills/claude-skill"]["artifact_type"] == "skill"

    def test_guard_detect_keeps_unique_opencode_file_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(workspace_dir / "opencode.json", {})
        _write_text(workspace_dir / ".opencode" / "plugin" / "shared.js", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "plugins" / "shared.mjs", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "plugins" / "nested" / "shared.mjs", "export default {};\n")
        _write_text(workspace_dir / ".opencode" / "skill" / "shared" / "SKILL.md", "---\nname: shared\n---\n")
        _write_text(
            workspace_dir / ".opencode" / "skills" / "nested" / "shared" / "SKILL.md",
            "---\nname: shared\n---\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = {item["artifact_id"] for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert "opencode:project:plugin-file:plugin/shared.js" in artifact_ids
        assert "opencode:project:plugin-file:plugins/shared.mjs" in artifact_ids
        assert "opencode:project:plugin-file:plugins/nested/shared.mjs" in artifact_ids
        assert "opencode:project:skill:opencode:skill/shared" in artifact_ids
        assert "opencode:project:skill:opencode:skills/nested/shared" in artifact_ids

    def test_guard_detect_reads_opencode_config_from_environment_override(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.json"
        _write_json(custom_config_path, {"plugins": ["env-plugin"]})
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]
        artifact_ids = [item["artifact_id"] for item in detection["artifacts"]]

        assert rc == 0
        assert "opencode:project:plugin:env-plugin" in artifact_ids
        assert str(custom_config_path) in detection["config_paths"]

    def test_guard_detect_prefers_project_opencode_config_over_environment_override(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.json"
        _write_json(custom_config_path, {"plugins": [["shared-plugin", {"mode": "custom"}]]})
        _write_json(workspace_dir / "opencode.json", {"plugins": [["shared-plugin", {"mode": "project"}]]})
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert artifacts["opencode:project:plugin:shared-plugin"]["metadata"]["mode"] == "project"

    def test_guard_detect_reads_opencode_config_dir_from_environment_override(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_dir = workspace_dir / "custom-dir"
        _write_text(custom_config_dir / "plugins" / "env-plugin.mjs", "export default {};\n")
        _write_text(custom_config_dir / "commands" / "env-command.md", "# env command\n")
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(custom_config_dir))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifact_ids = {item["artifact_id"] for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert "opencode:project:plugin-file:plugins/env-plugin.mjs" in artifact_ids
        assert "opencode:project:command:env-command" in artifact_ids

    def test_guard_detect_prefers_opencode_environment_config_over_global_config(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_path = workspace_dir / "custom" / "guard-opencode.json"
        _write_json(
            home_dir / ".config" / "opencode" / "opencode.json",
            {"plugins": [["shared-plugin", {"mode": "global"}]]},
        )
        _write_json(custom_config_path, {"plugins": [["shared-plugin", {"mode": "custom"}]]})
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom_config_path))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert artifacts["opencode:project:plugin:shared-plugin"]["metadata"]["mode"] == "custom"

    def test_guard_detect_prefers_opencode_config_dir_over_default_plugin_file(self, monkeypatch, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        custom_config_dir = workspace_dir / "custom-dir"
        _write_json(workspace_dir / "opencode.json", {})
        _write_text(workspace_dir / ".opencode" / "plugins" / "shared.mjs", "export default { name: 'default' };\n")
        _write_text(custom_config_dir / "plugins" / "shared.mjs", "export default { name: 'override' };\n")
        monkeypatch.setenv("OPENCODE_CONFIG_DIR", str(custom_config_dir))

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert artifacts["opencode:project:plugin-file:plugins/shared.mjs"]["config_path"] == str(
            custom_config_dir / "plugins" / "shared.mjs"
        )

    def test_guard_detect_handles_unreadable_opencode_plugin_files(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(workspace_dir / "opencode.json", {})
        _write_text(workspace_dir / ".opencode" / "plugins" / "broken.mjs", "export default {};\n")
        original_read_bytes = Path.read_bytes

        def _patched_read_bytes(path: Path) -> bytes:
            if path.name == "broken.mjs":
                raise OSError("Permission denied")
            return original_read_bytes(path)

        monkeypatch.setattr(Path, "read_bytes", _patched_read_bytes)

        rc = main(
            [
                "guard",
                "detect",
                "opencode",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        artifacts = {item["artifact_id"]: item for item in output["harnesses"][0]["artifacts"]}

        assert rc == 0
        assert (
            artifacts["opencode:project:plugin-file:plugins/broken.mjs"]["metadata"]["content_digest_unavailable"]
            is True
        )
