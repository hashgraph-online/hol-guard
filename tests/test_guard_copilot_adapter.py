"""Guard adapter tests for Microsoft Copilot surfaces."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter, _refresh_guard_proxy_entry


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
        context.workspace_dir / ".mcp.json",
        {
            "servers": {
                "workspace-cli-tool": {
                    "command": ["python", "-m", "workspace_cli_server"],
                    "args": ["--api-key=workspace-cli-secret"],
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
        str(context.workspace_dir / ".mcp.json"),
        str(context.workspace_dir / ".vscode" / "mcp.json"),
        str(context.workspace_dir / ".github" / "hooks" / "custom.json"),
    }
    artifacts = {item["artifact_id"]: item for item in detection["artifacts"]}
    assert "copilot:global:global-tool" in artifacts
    assert "copilot:project:workspace-cli-tool" in artifacts
    assert "copilot:project:workspace-tool" in artifacts
    assert "copilot:project:hook:custom:sessionstart:0:command" in artifacts
    assert "copilot:project:hook:custom:pretooluse:0:command" in artifacts
    assert "copilot:project:hook:custom:posttooluse:0:command" in artifacts
    assert artifacts["copilot:global:global-tool"]["args"] == ["--token=*****", "server.js"]
    assert artifacts["copilot:global:global-tool"]["url"] == "https://example.com/mcp?token=%2A%2A%2A%2A%2A&label=demo"
    assert artifacts["copilot:project:workspace-cli-tool"]["command"] == "python"
    assert artifacts["copilot:project:workspace-cli-tool"]["args"] == [
        "-m",
        "workspace_cli_server",
        "--api-key=*****",
    ]
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


def test_copilot_install_fails_closed_when_global_config_is_unreadable(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    config_path = context.home_dir / ".copilot" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("{broken", encoding="utf-8")

    try:
        adapter.install(context)
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected install to refuse unreadable Copilot config")

    assert "unreadable Copilot config" in message
    assert config_path.read_text(encoding="utf-8") == "{broken"


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
    assert artifacts["copilot:project:hook:custom:pretooluse:0:powershell"]["command"] == "pwsh -File guard-hook.ps1"
    assert artifacts["copilot:project:hook:custom:pretooluse:0:powershell"]["metadata"] == {"shell": "powershell"}


def test_copilot_install_and_uninstall_manage_inline_config_hooks_idempotently(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    original_pythonpath = sys.path[0]
    previous_pythonpath = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = original_pythonpath
    config_path = context.home_dir / ".copilot" / "config.json"
    custom_hook_path = context.workspace_dir / ".github" / "hooks" / "custom.json"
    _write_json(config_path, {"trusted_repositories": ["demo"]})
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

    try:
        first_install = adapter.install(context)
        second_install = adapter.install(context)
        config_payload = json.loads(config_path.read_text(encoding="utf-8"))
        managed_hook_path = context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json"
        managed_hook_payload = json.loads(managed_hook_path.read_text(encoding="utf-8"))
        managed_hooks = config_payload["hooks"]
        managed_workspace_hooks = managed_hook_payload["hooks"]

        assert first_install["active"] is True
        assert second_install["active"] is True
        assert first_install["config_path"] == str(config_path)
        assert len(managed_hooks["preToolUse"]) == 1
        assert len(managed_hooks["postToolUse"]) == 1
        assert len(managed_hooks["permissionRequest"]) == 1
        assert managed_hooks["preToolUse"][0]["type"] == "command"
        assert managed_hooks["preToolUse"][0]["cwd"] == "."
        assert managed_hooks["preToolUse"][0]["timeoutSec"] == 30
        assert managed_hooks["preToolUse"][0]["env"]["PYTHONPATH"] == original_pythonpath
        assert "guard hook" in managed_hooks["preToolUse"][0]["bash"]
        assert "--harness copilot" in managed_hooks["preToolUse"][0]["bash"]
        assert "--workspace" not in managed_hooks["preToolUse"][0]["bash"]
        assert "guard hook" in managed_hooks["preToolUse"][0]["powershell"]
        assert managed_hooks["postToolUse"][0]["type"] == "command"
        assert "guard hook" in managed_hooks["postToolUse"][0]["bash"]
        assert len(managed_workspace_hooks["preToolUse"]) == 1
        assert len(managed_workspace_hooks["postToolUse"]) == 1
        assert len(managed_workspace_hooks["permissionRequest"]) == 1
        assert "--workspace" in managed_workspace_hooks["preToolUse"][0]["bash"]
        assert config_payload["trusted_repositories"] == ["demo"]
        assert json.loads(custom_hook_path.read_text(encoding="utf-8")) == {
            "version": 1,
            "hooks": {
                "preToolUse": [{"command": "python custom-pre.py"}],
                "postToolUse": [{"command": "python custom-post.py"}],
            },
        }

        uninstall_payload = adapter.uninstall(context)
        restored_payload = json.loads(config_path.read_text(encoding="utf-8"))

        assert uninstall_payload["active"] is False
        assert "hooks" not in restored_payload
        assert managed_hook_path.exists() is False
        assert restored_payload["trusted_repositories"] == ["demo"]
    finally:
        if previous_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = previous_pythonpath


def test_refresh_guard_proxy_entry_preserves_list_form_proxy_args():
    refreshed = _refresh_guard_proxy_entry(
        {
            "command": [
                "/old/python",
                "-m",
                "codex_plugin_scanner.cli",
                "guard",
                "copilot-mcp-proxy",
                "--server-name",
                "danger_lab",
            ]
        },
        launcher_env={"PYTHONPATH": "/tmp/src"},
    )

    assert refreshed["command"] == sys.executable
    assert refreshed["args"] == [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "copilot-mcp-proxy",
        "--server-name",
        "danger_lab",
    ]
    assert refreshed["env"] == {"PYTHONPATH": "/tmp/src"}


def test_copilot_install_migrates_legacy_workspace_hook_file_out_of_band(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    config_path = context.home_dir / ".copilot" / "config.json"
    managed_hook_path = context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json"
    _write_json(config_path, {"trusted_repositories": ["demo"]})
    _write_json(
        managed_hook_path,
        {
            "preToolUse": [{"command": "python old-pre.py"}],
            "postToolUse": [{"command": "python old-post.py"}],
        },
    )

    install_payload = adapter.install(context)
    config_payload = json.loads(config_path.read_text(encoding="utf-8"))
    managed_hook_payload = json.loads(managed_hook_path.read_text(encoding="utf-8"))

    assert install_payload["active"] is True
    assert len(config_payload["hooks"]["preToolUse"]) == 1
    assert len(config_payload["hooks"]["postToolUse"]) == 1
    assert len(config_payload["hooks"]["permissionRequest"]) == 1
    assert "old-pre.py" not in config_payload["hooks"]["preToolUse"][0]["bash"]
    assert managed_hook_path.exists() is True
    assert len(managed_hook_payload["hooks"]["preToolUse"]) == 1
    assert "old-pre.py" not in managed_hook_payload["hooks"]["preToolUse"][0]["bash"]
    assert "--workspace" in managed_hook_payload["hooks"]["preToolUse"][0]["bash"]


def test_copilot_install_and_uninstall_preserve_existing_inline_hook_content(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    config_path = context.home_dir / ".copilot" / "config.json"
    _write_json(
        config_path,
        {
            "trusted_repositories": ["demo"],
            "hooks": {
                "sessionStart": [{"command": "python banner.py"}],
                "preToolUse": [{"command": "python existing-pre.py"}],
            },
        },
    )

    adapter.install(context)
    managed_payload = json.loads(config_path.read_text(encoding="utf-8"))

    assert managed_payload["hooks"]["sessionStart"] == [{"command": "python banner.py"}]
    assert len(managed_payload["hooks"]["preToolUse"]) == 2
    assert managed_payload["hooks"]["preToolUse"][0] == {"command": "python existing-pre.py"}

    uninstall_payload = adapter.uninstall(context)
    remaining_payload = json.loads(config_path.read_text(encoding="utf-8"))

    assert uninstall_payload["active"] is False
    assert remaining_payload == {
        "trusted_repositories": ["demo"],
        "hooks": {
            "sessionStart": [{"command": "python banner.py"}],
            "preToolUse": [{"command": "python existing-pre.py"}],
        },
    }


def test_copilot_install_and_uninstall_match_inline_hooks_after_path_changes(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    config_path = context.home_dir / ".copilot" / "config.json"
    _write_json(
        config_path,
        {
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
                            "--guard-home C:\\old-guard --harness copilot --home C:\\old-home "
                            "--workspace C:\\old-workspace"
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
                            "--guard-home C:\\old-guard --harness copilot --home C:\\old-home "
                            "--workspace C:\\old-workspace"
                        ),
                        "cwd": ".",
                        "timeoutSec": 30,
                    }
                ],
            },
        },
    )

    adapter.install(context)
    managed_payload = json.loads(config_path.read_text(encoding="utf-8"))

    assert len(managed_payload["hooks"]["preToolUse"]) == 1
    assert len(managed_payload["hooks"]["postToolUse"]) == 1
    assert len(managed_payload["hooks"]["permissionRequest"]) == 1
    assert "--workspace /tmp/old-workspace" not in managed_payload["hooks"]["preToolUse"][0]["bash"]
    assert "--workspace" not in managed_payload["hooks"]["preToolUse"][0]["bash"]

    uninstall_payload = adapter.uninstall(context)

    assert uninstall_payload["active"] is False
    assert "hooks" not in json.loads(config_path.read_text(encoding="utf-8"))


def test_copilot_uninstall_keeps_workspace_mcp_config_when_backup_metadata_is_unreadable(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    workspace_cli_mcp_path = context.workspace_dir / ".mcp.json"
    original_payload = {
        "mcpServers": {
            "danger_lab": {
                "command": "python3",
                "args": ["server.py"],
            }
        }
    }
    _write_json(workspace_cli_mcp_path, original_payload)

    install_payload = adapter.install(context)
    primary_backup_path = Path(str(install_payload["backup_paths"][0]))
    primary_backup_path.write_text("{\n  bad json\n", encoding="utf-8")

    uninstall_payload = adapter.uninstall(context)

    assert uninstall_payload["active"] is False
    assert workspace_cli_mcp_path.exists() is True
    assert json.loads(workspace_cli_mcp_path.read_text(encoding="utf-8")) != {}
    assert primary_backup_path.exists() is True


def test_copilot_uninstall_keeps_backup_when_restore_content_is_missing(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    workspace_cli_mcp_path = context.workspace_dir / ".mcp.json"
    original_payload = {
        "mcpServers": {
            "danger_lab": {
                "command": "python3",
                "args": ["server.py"],
            }
        }
    }
    _write_json(workspace_cli_mcp_path, original_payload)

    install_payload = adapter.install(context)
    primary_backup_path = Path(str(install_payload["backup_paths"][0]))
    primary_backup_path.write_text(json.dumps({"existed": True}, indent=2) + "\n", encoding="utf-8")

    uninstall_payload = adapter.uninstall(context)

    assert uninstall_payload["active"] is False
    assert workspace_cli_mcp_path.exists() is True
    assert primary_backup_path.exists() is True


def test_copilot_install_manages_workspace_mcp_servers_for_ide(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    workspace_cli_mcp_path = context.workspace_dir / ".mcp.json"
    workspace_mcp_path = context.workspace_dir / ".vscode" / "mcp.json"
    _write_json(
        context.home_dir / ".copilot" / "mcp-config.json",
        {
            "servers": {
                "global-tool": {
                    "command": "python",
                    "args": ["-m", "global_server"],
                }
            }
        },
    )
    _write_json(
        workspace_cli_mcp_path,
        {
            "servers": {
                "workspace-cli-tool": {
                    "command": "python",
                    "args": ["-m", "workspace_cli_server"],
                }
            }
        },
    )
    _write_json(
        workspace_mcp_path,
        {
            "servers": {
                "workspace-tool": {
                    "command": "python",
                    "args": ["-m", "workspace_server"],
                },
                "existing-tool": {
                    "command": "node",
                    "args": ["existing.js"],
                },
            }
        },
    )

    install_payload = adapter.install(context)
    cli_payload = json.loads(workspace_cli_mcp_path.read_text(encoding="utf-8"))
    managed_payload = json.loads(workspace_mcp_path.read_text(encoding="utf-8"))

    assert install_payload["active"] is True
    assert set(install_payload["managed_servers"]) == {
        "global-tool",
        "workspace-cli-tool",
        "workspace-tool",
        "existing-tool",
    }
    assert install_payload["managed_config_paths"] == [str(workspace_cli_mcp_path), str(workspace_mcp_path)]
    assert len(install_payload["backup_paths"]) == 2
    assert cli_payload["servers"]["workspace-cli-tool"]["type"] == "local"
    assert cli_payload["servers"]["workspace-cli-tool"]["tools"] == ["*"]
    assert managed_payload["servers"]["global-tool"]["type"] == "stdio"
    assert managed_payload["servers"]["workspace-tool"]["type"] == "stdio"
    assert managed_payload["servers"]["existing-tool"]["type"] == "stdio"
    assert cli_payload["servers"]["workspace-cli-tool"]["command"] == sys.executable
    assert cli_payload["servers"]["workspace-cli-tool"]["args"][:4] == [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "copilot-mcp-proxy",
    ]
    assert managed_payload["servers"]["global-tool"]["args"][2:5] == [
        "guard",
        "copilot-mcp-proxy",
        "--guard-home",
    ]
    assert managed_payload["servers"]["global-tool"]["command"] == sys.executable
    assert managed_payload["servers"]["workspace-tool"]["command"] == sys.executable
    assert managed_payload["servers"]["existing-tool"]["command"] == sys.executable


def test_copilot_install_preserves_existing_workspace_mcp_key_schema(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    workspace_cli_mcp_path = context.workspace_dir / ".mcp.json"
    _write_json(
        workspace_cli_mcp_path,
        {
            "servers": {
                "workspace-cli-tool": {
                    "command": "python",
                    "args": ["-m", "workspace_cli_server"],
                }
            }
        },
    )

    adapter.install(context)
    payload = json.loads(workspace_cli_mcp_path.read_text(encoding="utf-8"))

    assert "servers" in payload
    assert "mcpServers" not in payload
    assert payload["servers"]["workspace-cli-tool"]["command"] == sys.executable


def test_copilot_install_keeps_target_specific_workspace_servers_distinct(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    workspace_cli_mcp_path = context.workspace_dir / ".mcp.json"
    workspace_mcp_path = context.workspace_dir / ".vscode" / "mcp.json"
    _write_json(
        workspace_cli_mcp_path,
        {
            "mcpServers": {
                "danger_lab": {
                    "command": "python",
                    "args": ["-m", "cli_server"],
                }
            }
        },
    )
    _write_json(
        workspace_mcp_path,
        {
            "servers": {
                "danger_lab": {
                    "command": "node",
                    "args": ["ide-server.js"],
                }
            }
        },
    )

    install_payload = adapter.install(context)
    cli_payload = json.loads(workspace_cli_mcp_path.read_text(encoding="utf-8"))
    ide_payload = json.loads(workspace_mcp_path.read_text(encoding="utf-8"))
    cli_args = cli_payload["mcpServers"]["danger_lab"]["args"]
    ide_args = ide_payload["servers"]["danger_lab"]["args"]

    assert install_payload["active"] is True
    assert cli_payload["mcpServers"]["danger_lab"]["command"] == sys.executable
    assert ide_payload["servers"]["danger_lab"]["command"] == sys.executable
    assert cli_args[cli_args.index("--command") + 1] == "python"
    assert "--arg=-m" in cli_args
    assert "--arg=cli_server" in cli_args
    assert ide_args[ide_args.index("--command") + 1] == "node"
    assert "--arg=ide-server.js" in ide_args


def test_copilot_install_refreshes_existing_guard_proxy_entries_to_current_interpreter(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    original_pythonpath = sys.path[0]
    previous_pythonpath = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = original_pythonpath
    workspace_cli_mcp_path = context.workspace_dir / ".mcp.json"
    _write_json(
        workspace_cli_mcp_path,
        {
            "mcpServers": {
                "danger_lab": {
                    "command": "/tmp/old-python",
                    "args": [
                        "-m",
                        "codex_plugin_scanner.cli",
                        "guard",
                        "copilot-mcp-proxy",
                        "--guard-home",
                        str(context.guard_home),
                        "--server-name",
                        "danger_lab",
                        "--source-scope",
                        "project",
                        "--config-path",
                        str(context.workspace_dir / ".vscode" / "mcp.json"),
                        "--transport",
                        "stdio",
                        "--command",
                        "python3",
                    ],
                    "env": {"PYTHONPATH": "/tmp/old-src"},
                    "type": "local",
                    "tools": ["*"],
                }
            }
        },
    )

    try:
        adapter.install(context)
        cli_payload = json.loads(workspace_cli_mcp_path.read_text(encoding="utf-8"))

        assert cli_payload["mcpServers"]["danger_lab"]["command"] == sys.executable
        assert cli_payload["mcpServers"]["danger_lab"]["args"][2:5] == [
            "guard",
            "copilot-mcp-proxy",
            "--guard-home",
        ]
        assert cli_payload["mcpServers"]["danger_lab"]["env"]["PYTHONPATH"].startswith(original_pythonpath)
        assert cli_payload["mcpServers"]["danger_lab"]["env"]["PYTHONPATH"].endswith("/tmp/old-src")
    finally:
        if previous_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = previous_pythonpath


def test_copilot_install_refreshes_list_form_guard_proxy_entries_without_losing_args(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    workspace_cli_mcp_path = context.workspace_dir / ".mcp.json"
    _write_json(
        workspace_cli_mcp_path,
        {
            "mcpServers": {
                "danger_lab": {
                    "command": [
                        "/tmp/old-python",
                        "-m",
                        "codex_plugin_scanner.cli",
                        "guard",
                        "copilot-mcp-proxy",
                        "--guard-home",
                        str(context.guard_home),
                        "--server-name",
                        "danger_lab",
                        "--source-scope",
                        "project",
                        "--config-path",
                        str(workspace_cli_mcp_path),
                        "--transport",
                        "stdio",
                        "--command",
                        "python3",
                    ],
                    "type": "local",
                    "tools": ["*"],
                }
            }
        },
    )

    adapter.install(context)
    cli_payload = json.loads(workspace_cli_mcp_path.read_text(encoding="utf-8"))

    assert cli_payload["mcpServers"]["danger_lab"]["command"] == sys.executable
    assert cli_payload["mcpServers"]["danger_lab"]["args"][:4] == [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "copilot-mcp-proxy",
    ]


def test_copilot_detect_ignores_guard_managed_proxy_entries(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    _write_json(
        context.workspace_dir / ".mcp.json",
        {
            "mcpServers": {
                "guarded-tool": {
                    "type": "local",
                    "command": sys.executable,
                    "args": [
                        "-m",
                        "codex_plugin_scanner.cli",
                        "guard",
                        "copilot-mcp-proxy",
                        "--guard-home",
                        str(context.guard_home),
                    ],
                    "tools": ["*"],
                }
            }
        },
    )

    detection = adapter.detect(context)

    assert detection.artifacts == ()


def test_copilot_detect_marks_local_cli_install_as_available_when_not_on_path(tmp_path, monkeypatch):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    local_binary = tmp_path / "actual-home" / ".local" / "copilot-cli" / "copilot"
    local_binary.parent.mkdir(parents=True, exist_ok=True)
    local_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_binary.chmod(0o755)

    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.base.shutil.which", lambda command: None)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "actual-home")

    detection = adapter.detect(context)

    assert detection.command_available is True
    assert detection.installed is True


def test_copilot_detect_ignores_non_executable_local_cli_candidate_when_not_on_path(tmp_path, monkeypatch):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    local_binary = tmp_path / "actual-home" / ".local" / "copilot-cli" / "copilot"
    local_binary.parent.mkdir(parents=True, exist_ok=True)
    local_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_binary.chmod(0o644)

    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.base.shutil.which", lambda command: None)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "actual-home")

    detection = adapter.detect(context)

    assert detection.command_available is False
    assert detection.installed is False


def test_copilot_launch_command_uses_local_cli_install_when_not_on_path(tmp_path, monkeypatch):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    local_binary = tmp_path / "actual-home" / ".local" / "copilot-cli" / "copilot"
    local_binary.parent.mkdir(parents=True, exist_ok=True)
    local_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_binary.chmod(0o755)

    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.base.shutil.which", lambda command: None)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "actual-home")

    command = adapter.launch_command(context, ["--help"])

    assert command[0] == str(local_binary)
    assert command[1:] == ["--help"]


def test_copilot_uninstall_restores_install_time_workspace_targets_when_scope_changes(tmp_path):
    workspace_context = _build_context(tmp_path)
    global_context = HarnessContext(
        home_dir=workspace_context.home_dir,
        workspace_dir=None,
        guard_home=workspace_context.guard_home,
    )
    adapter = CopilotHarnessAdapter()
    workspace_cli_mcp_path = workspace_context.workspace_dir / ".mcp.json"
    workspace_mcp_path = workspace_context.workspace_dir / ".vscode" / "mcp.json"
    cli_payload = {
        "mcpServers": {
            "danger_lab": {
                "command": "python",
                "args": ["-m", "cli_server"],
            }
        }
    }
    ide_payload = {
        "servers": {
            "danger_lab": {
                "command": "node",
                "args": ["ide-server.js"],
            }
        }
    }
    _write_json(workspace_cli_mcp_path, cli_payload)
    _write_json(workspace_mcp_path, ide_payload)

    install_payload = adapter.install(workspace_context)
    uninstall_payload = adapter.uninstall(global_context)

    assert install_payload["active"] is True
    assert uninstall_payload["active"] is False
    assert set(uninstall_payload["managed_config_paths"]) == {
        str(workspace_cli_mcp_path),
        str(workspace_mcp_path),
    }
    assert json.loads(workspace_cli_mcp_path.read_text(encoding="utf-8")) == cli_payload
    assert json.loads(workspace_mcp_path.read_text(encoding="utf-8")) == ide_payload
    for state_path in uninstall_payload["state_paths"]:
        assert Path(state_path).exists() is False


def test_copilot_uninstall_keeps_shared_cli_hook_while_other_workspace_remains_installed(tmp_path):
    first_context = _build_context(tmp_path / "first")
    second_workspace = tmp_path / "second" / "workspace"
    second_workspace.mkdir(parents=True, exist_ok=True)
    second_context = HarnessContext(
        home_dir=first_context.home_dir,
        workspace_dir=second_workspace,
        guard_home=first_context.guard_home,
    )
    adapter = CopilotHarnessAdapter()

    first_install = adapter.install(first_context)
    second_install = adapter.install(second_context)
    first_uninstall = adapter.uninstall(first_context)

    config_payload = json.loads((first_context.home_dir / ".copilot" / "config.json").read_text(encoding="utf-8"))
    managed_hook_path = second_context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json"

    assert first_install["active"] is True
    assert second_install["active"] is True
    assert first_uninstall["active"] is False
    assert "hooks" in config_payload
    assert "preToolUse" in config_payload["hooks"]
    assert len(config_payload["hooks"]["preToolUse"]) == 1
    assert managed_hook_path.exists() is True


def test_copilot_launch_command_adds_workspace_mcp_config_for_cli_sessions(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    _write_json(
        context.workspace_dir / ".mcp.json",
        {"mcpServers": {"danger_lab": {"command": "python3", "args": ["server.py"]}}},
    )

    command = adapter.launch_command(context, ["--help"])

    assert command[0].endswith("copilot")
    assert command[1:] == [
        "--additional-mcp-config",
        f"@{context.workspace_dir / '.mcp.json'}",
        "--help",
    ]


def test_copilot_launch_command_skips_workspace_override_when_cli_mcp_config_is_missing(tmp_path):
    context = _build_context(tmp_path)
    adapter = CopilotHarnessAdapter()
    _write_json(
        context.workspace_dir / ".vscode" / "mcp.json",
        {"servers": {"danger_lab": {"command": "python3", "args": ["server.py"]}}},
    )

    command = adapter.launch_command(context, ["--help"])

    assert command[0].endswith("copilot")
    assert command[1:] == ["--help"]
