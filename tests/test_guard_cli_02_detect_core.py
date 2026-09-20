"""Guard CLI detect core behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _build_guard_fixture, _write_json, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_detect_reports_supported_harnesses(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "detect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )

        output = json.loads(capsys.readouterr().out)
        harnesses = {item["harness"]: item for item in output["harnesses"]}

        assert rc == 0
        assert {"codex", "claude-code", "cursor", "antigravity", "gemini", "opencode"} <= harnesses.keys()
        assert harnesses["codex"]["artifacts"][0]["source_scope"] == "global"
        assert harnesses["claude-code"]["artifacts"][0]["artifact_type"] in {"mcp_server", "hook", "agent"}

    def test_guard_detect_scopes_codex_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_text(
            home_dir / ".codex" / "config.toml",
            """
[mcp_servers.shared_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
            + "\n",
        )
        _write_text(
            workspace_dir / ".codex" / "config.toml",
            """
[mcp_servers.shared_tools]
command = "node"
args = ["workspace-skill.js"]
""".strip()
            + "\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "codex",
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
        assert artifact_ids == ["codex:global:shared_tools", "codex:project:shared_tools"]

    def test_guard_detect_scopes_claude_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".claude" / "settings.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "python", "args": ["-m", "http.server", "9000"]},
                }
            },
        )
        _write_json(
            workspace_dir / ".mcp.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "node", "args": ["workspace.js"]},
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "claude-code",
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
        assert artifact_ids == ["claude-code:global:mcp:shared-tools", "claude-code:project:mcp:shared-tools"]

    def test_guard_detect_scopes_claude_hook_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".claude" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [{"command": "python global-hook.py"}],
                }
            },
        )
        _write_json(
            workspace_dir / ".claude" / "settings.local.json",
            {
                "hooks": {
                    "PreToolUse": [{"command": "python project-hook.py"}],
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "claude-code",
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
        assert artifact_ids == [
            "claude-code:global:pretooluse:0",
            "claude-code:project:pretooluse:0",
        ]

    def test_guard_detect_scopes_cursor_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".cursor" / "mcp.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "npx", "args": ["global-server"]},
                }
            },
        )
        _write_json(
            workspace_dir / ".cursor" / "mcp.json",
            {
                "mcpServers": {
                    "shared-tools": {"command": "npx", "args": ["project-server"]},
                }
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "cursor",
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
        assert artifact_ids == ["cursor:global:shared-tools", "cursor:project:shared-tools"]

    def test_guard_detect_scopes_gemini_artifact_ids(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".gemini" / "settings.json",
            {
                "mcpServers": {
                    "shared-settings": {"command": "node", "args": ["global-settings.js"]},
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "python global-hook.py"}],
                        }
                    ]
                },
            },
        )
        _write_text(
            home_dir / ".gemini" / "skills" / "shared-skill" / "SKILL.md",
            "---\nname: shared-skill\ndescription: Global Gemini skill\n---\n",
        )
        _write_json(
            home_dir / ".gemini" / "extensions" / "shared" / "gemini-extension.json",
            {
                "name": "shared",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["global.js"]}},
            },
        )
        _write_json(
            home_dir / ".gemini" / "antigravity" / "mcp_config.json",
            {
                "mcpServers": {
                    "should-belong-to-antigravity": {"command": "node", "args": ["antigravity.js"]},
                }
            },
        )
        _write_json(
            workspace_dir / ".gemini" / "settings.json",
            {
                "mcpServers": {
                    "shared-settings": {"command": "node", "args": ["project-settings.js"]},
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [{"type": "command", "command": "python project-hook.py"}],
                        }
                    ]
                },
            },
        )
        _write_text(
            workspace_dir / ".gemini" / "skills" / "shared-skill" / "SKILL.md",
            "---\nname: shared-skill\ndescription: Project Gemini skill\n---\n",
        )
        _write_json(
            workspace_dir / ".gemini" / "extensions" / "shared" / "gemini-extension.json",
            {
                "name": "shared",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["project.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "gemini",
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
        assert artifact_ids == [
            "gemini:global:shared",
            "gemini:global:shared:shared-tools",
            "gemini:global:mcp:shared-settings",
            "gemini:global:hook:pretooluse:0",
            "gemini:global:skill:skills/shared-skill",
            "gemini:project:shared",
            "gemini:project:shared:shared-tools",
            "gemini:project:mcp:shared-settings",
            "gemini:project:hook:pretooluse:0",
            "gemini:project:skill:skills/shared-skill",
        ]
