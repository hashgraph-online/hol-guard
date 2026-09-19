"""Guard CLI detect antigravity behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _write_json, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_detect_reports_antigravity_extensions_skills_and_mcp(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        antigravity_extension_root = home_dir / ".antigravity" / "extensions" / "hashgraph.tools-1.0.0"
        _write_json(
            home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
            {"workbench.colorTheme": "Solarized Dark"},
        )
        _write_json(
            home_dir / ".antigravity" / "extensions" / "extensions.json",
            [
                {
                    "identifier": {"id": "hashgraph.tools"},
                    "location": {"path": str(antigravity_extension_root)},
                    "metadata": {"publisherDisplayName": "Hashgraph"},
                }
            ],
        )
        _write_json(
            antigravity_extension_root / "package.json",
            {"name": "tools", "publisher": "hashgraph", "displayName": "Hashgraph Tools"},
        )
        _write_json(
            home_dir / ".gemini" / "antigravity" / "mcp_config.json",
            {
                "mcpServers": {
                    "gravity-tools": {"command": "node", "args": ["gravity.js"]},
                }
            },
        )
        _write_text(
            home_dir / ".gemini" / "antigravity" / "skills" / "gravity-review" / "SKILL.md",
            "---\nname: gravity-review\ndescription: Gravity review skill\n---\n",
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
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
        assert (
            str(home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json")
            in (detection["config_paths"])
        )
        assert str(home_dir / ".gemini" / "antigravity" / "mcp_config.json") in detection["config_paths"]
        assert artifact_ids == [
            "antigravity:global:hashgraph.tools",
            "antigravity:global:mcp:bridge:gravity-tools",
            "antigravity:global:skill:skills/gravity-review",
        ]

    def test_guard_detect_recognizes_cross_platform_antigravity_settings(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"gravity-tools": {"command": "node", "args": True}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]

        assert rc == 0
        assert str(home_dir / ".config" / "Antigravity" / "User" / "settings.json") in detection["config_paths"]
        assert [item["artifact_id"] for item in detection["artifacts"]] == [
            "antigravity:global:mcp:settings:xdg-user:gravity-tools"
        ]
        assert detection["artifacts"][0]["args"] == []

    def test_guard_detect_ignores_generic_workspace_vscode_settings_without_antigravity_ownership(
        self,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / ".vscode" / "settings.json",
            {
                "workbench.colorTheme": "Default Dark+",
                "mcpServers": {"generic-tools": {"command": "node", "args": ["generic.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        detection = output["harnesses"][0]

        assert rc == 0
        assert detection["config_paths"] == []
        assert detection["artifacts"] == []

    def test_guard_detect_includes_workspace_vscode_settings_after_antigravity_ownership(
        self,
        tmp_path,
        capsys,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".config" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
            },
        )
        _write_json(
            workspace_dir / ".vscode" / "settings.json",
            {
                "workbench.colorTheme": "Default Dark+",
                "mcpServers": {"workspace-tools": {"command": "node", "args": ["workspace.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
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
        assert str(home_dir / ".config" / "Antigravity" / "User" / "settings.json") in detection["config_paths"]
        assert str(workspace_dir / ".vscode" / "settings.json") in detection["config_paths"]
        assert artifact_ids == ["antigravity:project:mcp:settings:workspace-vscode:workspace-tools"]

    def test_guard_detect_disambiguates_antigravity_mcp_sources(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["settings.js"]}},
            },
        )
        _write_json(
            home_dir / ".gemini" / "antigravity" / "mcp_config.json",
            {
                "mcpServers": {"shared-tools": {"command": "node", "args": ["bridge.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
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
            "antigravity:global:mcp:bridge:shared-tools",
            "antigravity:global:mcp:settings:macos-user:shared-tools",
        ]

    def test_guard_detect_disambiguates_antigravity_settings_paths_with_same_server_name(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["macos.js"]}},
            },
        )
        _write_json(
            home_dir / ".config" / "Antigravity" / "User" / "settings.json",
            {
                "antigravity.profile": "default",
                "mcpServers": {"shared-tools": {"command": "node", "args": ["linux.js"]}},
            },
        )

        rc = main(
            [
                "guard",
                "detect",
                "antigravity",
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
            "antigravity:global:mcp:settings:macos-user:shared-tools",
            "antigravity:global:mcp:settings:xdg-user:shared-tools",
        ]
