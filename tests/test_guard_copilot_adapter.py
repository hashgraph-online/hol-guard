"""Guard adapter tests for Microsoft Copilot surfaces."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _build_context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )


def test_copilot_detects_documented_local_surfaces_and_redacts_secrets(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    _write_json(context.home_dir / ".copilot" / "config.json", {"trusted_repositories": ["demo"]})
    _write_json(
        context.home_dir / ".copilot" / "mcp-config.json",
        {
            "mcpServers": {
                "global-tool": {
                    "command": "npx",
                    "args": ["--token=secret-token", "server.js"],
                    "url": "https://example.com/mcp?token=secret-token&label=demo",
                }
            }
        },
    )
    _write_json(
        context.workspace_dir / ".vscode" / "mcp.json",
        {
            "servers": {
                "workspace-tool": {
                    "command": ["python", "-m", "workspace_server"],
                    "args": ["--api-key=workspace-secret"],
                }
            }
        },
    )
    _write_json(
        context.workspace_dir / ".github" / "hooks" / "custom.json",
        {
            "version": 1,
            "hooks": {
                "sessionStart": [{"command": "python banner.py"}],
                "preToolUse": [{"command": "python pre.py"}],
                "postToolUse": [{"command": "python post.py"}],
            },
        },
    )

    detection = adapter.detect(context).to_dict()

    assert detection["harness"] == "copilot"
    assert set(detection["config_paths"]) == {
        str(context.home_dir / ".copilot" / "config.json"),
        str(context.home_dir / ".copilot" / "mcp-config.json"),
        str(context.workspace_dir / ".vscode" / "mcp.json"),
        str(context.workspace_dir / ".github" / "hooks" / "custom.json"),
    }
    artifacts = {item["artifact_id"]: item for item in detection["artifacts"]}
    assert "copilot:global:global-tool" in artifacts
    assert "copilot:project:workspace-tool" in artifacts
    assert "copilot:project:hook:custom:sessionstart:0:command" in artifacts
    assert "copilot:project:hook:custom:pretooluse:0:command" in artifacts
    assert "copilot:project:hook:custom:posttooluse:0:command" in artifacts
    assert artifacts["copilot:global:global-tool"]["args"] == ["--token=*****", "server.js"]
    assert artifacts["copilot:global:global-tool"]["url"] == "https://example.com/mcp?token=%2A%2A%2A%2A%2A&label=demo"
    assert artifacts["copilot:project:workspace-tool"]["command"] == "python"
    assert artifacts["copilot:project:workspace-tool"]["args"] == ["-m", "workspace_server", "--api-key=*****"]


def test_copilot_detect_tolerates_malformed_json(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    malformed_hook = context.workspace_dir / ".github" / "hooks" / "broken.json"
    malformed_hook.parent.mkdir(parents=True, exist_ok=True)
    malformed_hook.write_text("{broken", encoding="utf-8")
    _write_json(
        context.workspace_dir / ".vscode" / "mcp.json",
        {"servers": {"workspace-tool": {"command": "python", "args": ["server.py"]}}},
    )

    detection = adapter.detect(context)

    assert str(malformed_hook) not in detection.config_paths
    assert [artifact.artifact_id for artifact in detection.artifacts] == ["copilot:project:workspace-tool"]


def test_copilot_detect_ignores_hook_json_without_hook_entries(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    unrelated_hook = context.workspace_dir / ".github" / "hooks" / "notes.json"
    _write_json(unrelated_hook, {"message": "not a hook file"})
    _write_json(
        context.workspace_dir / ".vscode" / "mcp.json",
        {"servers": {"workspace-tool": {"command": "python", "args": ["server.py"]}}},
    )

    detection = adapter.detect(context)

    assert str(unrelated_hook) not in detection.config_paths
    assert [artifact.artifact_id for artifact in detection.artifacts] == ["copilot:project:workspace-tool"]


def test_copilot_detect_records_bash_and_powershell_hook_commands_separately(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    _write_json(
        context.workspace_dir / ".github" / "hooks" / "custom.json",
        {
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {
                        "bash": "python guard-hook.py",
                        "powershell": "pwsh -File guard-hook.ps1",
                    }
                ]
            },
        },
    )

    detection = adapter.detect(context).to_dict()
    artifacts = {item["artifact_id"]: item for item in detection["artifacts"]}

    assert "copilot:project:hook:custom:pretooluse:0:bash" in artifacts
    assert "copilot:project:hook:custom:pretooluse:0:powershell" in artifacts
    assert artifacts["copilot:project:hook:custom:pretooluse:0:bash"]["command"] == "python guard-hook.py"
    assert artifacts["copilot:project:hook:custom:pretooluse:0:bash"]["metadata"] == {"shell": "bash"}
    assert (
        artifacts["copilot:project:hook:custom:pretooluse:0:powershell"]["command"]
        == "pwsh -File guard-hook.ps1"
    )
    assert artifacts["copilot:project:hook:custom:pretooluse:0:powershell"]["metadata"] == {
        "shell": "powershell"
    }


def test_copilot_install_and_uninstall_manage_guard_owned_hook_file_idempotently(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    custom_hook_path = context.workspace_dir / ".github" / "hooks" / "custom.json"
    _write_json(
        custom_hook_path,
        {
            "version": 1,
            "hooks": {
                "preToolUse": [{"command": "python custom-pre.py"}],
                "postToolUse": [{"command": "python custom-post.py"}],
            },
        },
    )

    first_install = adapter.install(context)
    second_install = adapter.install(context)
    managed_hook_path = context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json"
    managed_payload = json.loads(managed_hook_path.read_text(encoding="utf-8"))

    assert first_install["active"] is True
    assert second_install["active"] is True
    assert managed_hook_path.exists() is True
    assert managed_payload["version"] == 1
    assert len(managed_payload["hooks"]["preToolUse"]) == 1
    assert len(managed_payload["hooks"]["postToolUse"]) == 1
    assert managed_payload["hooks"]["preToolUse"][0]["type"] == "command"
    assert managed_payload["hooks"]["preToolUse"][0]["cwd"] == "."
    assert managed_payload["hooks"]["preToolUse"][0]["timeoutSec"] == 30
    assert "guard hook" in managed_payload["hooks"]["preToolUse"][0]["bash"]
    assert "--harness copilot" in managed_payload["hooks"]["preToolUse"][0]["bash"]
    assert "guard hook" in managed_payload["hooks"]["preToolUse"][0]["powershell"]
    assert managed_payload["hooks"]["postToolUse"][0]["type"] == "command"
    assert "guard hook" in managed_payload["hooks"]["postToolUse"][0]["bash"]
    assert json.loads(custom_hook_path.read_text(encoding="utf-8")) == {
        "version": 1,
        "hooks": {
            "preToolUse": [{"command": "python custom-pre.py"}],
            "postToolUse": [{"command": "python custom-post.py"}],
        },
    }


def test_copilot_install_rewrites_legacy_guard_owned_hook_file_to_documented_schema(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    managed_hook_path = context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json"
    _write_json(
        managed_hook_path,
        {
            "preToolUse": [{"command": "python old-pre.py"}],
            "postToolUse": [{"command": "python old-post.py"}],
        },
    )

    adapter.install(context)
    managed_payload = json.loads(managed_hook_path.read_text(encoding="utf-8"))

    assert managed_payload["version"] == 1
    assert set(managed_payload) == {"version", "hooks"}
    assert len(managed_payload["hooks"]["preToolUse"]) == 1
    assert len(managed_payload["hooks"]["postToolUse"]) == 1
    assert "old-pre.py" not in managed_payload["hooks"]["preToolUse"][0]["bash"]

    uninstall_payload = adapter.uninstall(context)

    assert uninstall_payload["active"] is False
    assert managed_hook_path.exists() is False


def test_copilot_install_and_uninstall_preserve_existing_managed_hook_content(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    managed_hook_path = context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json"
    _write_json(
        managed_hook_path,
        {
            "version": 1,
            "hooks": {
                "sessionStart": [{"command": "python banner.py"}],
                "preToolUse": [{"command": "python existing-pre.py"}],
            },
        },
    )

    adapter.install(context)
    managed_payload = json.loads(managed_hook_path.read_text(encoding="utf-8"))

    assert managed_payload["hooks"]["sessionStart"] == [{"command": "python banner.py"}]
    assert len(managed_payload["hooks"]["preToolUse"]) == 2
    assert managed_payload["hooks"]["preToolUse"][0] == {"command": "python existing-pre.py"}

    uninstall_payload = adapter.uninstall(context)
    remaining_payload = json.loads(managed_hook_path.read_text(encoding="utf-8"))

    assert uninstall_payload["active"] is False
    assert remaining_payload == {
        "version": 1,
        "hooks": {
            "sessionStart": [{"command": "python banner.py"}],
            "preToolUse": [{"command": "python existing-pre.py"}],
        },
    }


def test_copilot_install_and_uninstall_match_managed_hooks_after_path_changes(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    managed_hook_path = context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json"
    _write_json(
        managed_hook_path,
        {
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {
                        "type": "command",
                        "bash": (
                            "/opt/python/bin/python -m codex_plugin_scanner.cli guard hook "
                            "--guard-home /tmp/old-guard --harness copilot --home /tmp/old-home "
                            "--workspace /tmp/old-workspace"
                        ),
                        "powershell": (
                            '"C:\\Python\\python.exe" -m codex_plugin_scanner.cli guard hook '
                            '--guard-home C:\\old-guard --harness copilot --home C:\\old-home '
                            '--workspace C:\\old-workspace'
                        ),
                        "cwd": ".",
                        "timeoutSec": 30,
                    }
                ],
                "postToolUse": [
                    {
                        "type": "command",
                        "bash": (
                            "/opt/python/bin/python -m codex_plugin_scanner.cli guard hook "
                            "--guard-home /tmp/old-guard --harness copilot --home /tmp/old-home "
                            "--workspace /tmp/old-workspace"
                        ),
                        "powershell": (
                            '"C:\\Python\\python.exe" -m codex_plugin_scanner.cli guard hook '
                            '--guard-home C:\\old-guard --harness copilot --home C:\\old-home '
                            '--workspace C:\\old-workspace'
                        ),
                        "cwd": ".",
                        "timeoutSec": 30,
                    }
                ],
            },
        },
    )

    adapter.install(context)
    managed_payload = json.loads(managed_hook_path.read_text(encoding="utf-8"))

    assert len(managed_payload["hooks"]["preToolUse"]) == 1
    assert len(managed_payload["hooks"]["postToolUse"]) == 1
    assert "--workspace /tmp/old-workspace" not in managed_payload["hooks"]["preToolUse"][0]["bash"]

    uninstall_payload = adapter.uninstall(context)

    assert uninstall_payload["active"] is False
    assert managed_hook_path.exists() is False
