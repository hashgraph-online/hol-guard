from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python3"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
env = { API_BASE = "https://hol.org", FEATURE_FLAG = "1" }
""".strip()
        + "\n",
    )


def test_guard_install_codex_rewrites_workspace_config_with_proxy_entries(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    managed_install = output["managed_install"]
    manifest = managed_install["manifest"]
    config_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")
    hooks_path = workspace_dir / ".codex" / "hooks.json"
    hooks_payload = json.loads(hooks_path.read_text(encoding="utf-8"))

    assert rc == 0
    assert managed_install["active"] is True
    assert manifest["mode"] == "codex-mcp-proxy"
    assert manifest["managed_config_path"] == str(workspace_dir / ".codex" / "config.toml")
    assert manifest["managed_hooks_path"] == str(hooks_path)
    assert set(manifest["managed_servers"]) == {"global_tools", "workspace_skill"}
    assert "--server-name" in config_text
    assert "guard" in config_text
    assert "codex-mcp-proxy" in config_text
    assert 'approval_policy = "never"' in config_text
    assert "codex_hooks = true" in config_text
    assert 'API_BASE = "https://hol.org"' in config_text
    assert 'FEATURE_FLAG = "1"' in config_text
    assert hooks_payload["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
    handler = hooks_payload["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler["type"] == "command"
    assert "codex_plugin_scanner.cli" in handler["command"]
    assert "hook" in handler["command"]
    assert "codex" in handler["command"]


def test_guard_uninstall_codex_restores_original_workspace_config(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    original_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
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
            "codex",
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
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_text
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False


def test_guard_install_codex_merges_managed_hooks_without_removing_existing_entries(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                        }
                    ],
                    "SessionStart": [
                        {
                            "matcher": "startup|resume",
                            "hooks": [{"type": "command", "command": "python3 custom-start.py"}],
                        }
                    ],
                }
            },
            indent=2,
        )
        + "\n",
    )

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    hooks_payload = json.loads((workspace_dir / ".codex" / "hooks.json").read_text(encoding="utf-8"))

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    restored_hooks = json.loads((workspace_dir / ".codex" / "hooks.json").read_text(encoding="utf-8"))

    assert install_rc == 0
    assert uninstall_rc == 0
    assert len(hooks_payload["hooks"]["PreToolUse"]) == 2
    assert hooks_payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "python3 custom-pre.py"
    managed_group = hooks_payload["hooks"]["PreToolUse"][1]
    assert managed_group["matcher"] == "Bash"
    assert "codex_plugin_scanner.cli" in managed_group["hooks"][0]["command"]
    assert "hook" in managed_group["hooks"][0]["command"]
    assert "codex" in managed_group["hooks"][0]["command"]
    assert restored_hooks["hooks"]["PreToolUse"] == [
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
        }
    ]
    assert restored_hooks["hooks"]["SessionStart"] == [
        {
            "matcher": "startup|resume",
            "hooks": [{"type": "command", "command": "python3 custom-start.py"}],
        }
    ]


def test_guard_install_codex_workspace_cleans_stale_global_managed_hook(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".codex" / "config.toml",
        '[mcp_servers.global_tools]\ncommand = "python3"\nargs = ["-m", "http.server", "9000"]\n',
    )
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')

    global_install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    workspace_install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    home_hooks_path = home_dir / ".codex" / "hooks.json"
    workspace_hooks_path = workspace_dir / ".codex" / "hooks.json"
    workspace_hooks = json.loads(workspace_hooks_path.read_text(encoding="utf-8"))

    assert global_install_rc == 0
    assert workspace_install_rc == 0
    assert home_hooks_path.exists() is False
    assert len(workspace_hooks["hooks"]["PreToolUse"]) == 1
    managed_group = workspace_hooks["hooks"]["PreToolUse"][0]
    assert managed_group["matcher"] == "Bash"
    assert "codex_plugin_scanner.cli" in managed_group["hooks"][0]["command"]


def test_guard_uninstall_codex_preserves_user_hooks_in_managed_bash_group(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    hooks_path = workspace_dir / ".codex" / "hooks.json"
    hooks_payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    hooks_payload["hooks"]["PreToolUse"][0]["hooks"].append({"type": "command", "command": "python3 custom-pre.py"})
    hooks_path.write_text(json.dumps(hooks_payload, indent=2) + "\n", encoding="utf-8")

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    restored_hooks = json.loads(hooks_path.read_text(encoding="utf-8"))

    assert install_rc == 0
    assert uninstall_rc == 0
    assert restored_hooks["hooks"]["PreToolUse"] == [
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
        }
    ]


def test_guard_install_codex_refuses_invalid_alternate_hook_file_before_config_write(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)
    _write_text(home_dir / ".codex" / "hooks.json", '{"hooks": ')

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert "Guard refused to overwrite unreadable Codex hooks file" in captured.err
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (home_dir / ".codex" / "hooks.json").read_text(encoding="utf-8") == '{"hooks": '


def test_guard_install_codex_refuses_non_file_alternate_hook_path_before_config_write(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)
    (home_dir / ".codex" / "hooks.json").mkdir(parents=True)

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert "Guard refused to overwrite non-file Codex hooks file" in captured.err
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (home_dir / ".codex" / "hooks.json").is_dir() is True


def test_guard_uninstall_codex_succeeds_when_alternate_hook_file_is_invalid(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(home_dir / ".codex" / "hooks.json", '{"hooks": ')

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
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
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert (home_dir / ".codex" / "hooks.json").read_text(encoding="utf-8") == '{"hooks": '


def test_guard_uninstall_codex_preserves_invalid_target_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    original_config = 'approval_policy = "never"\n'
    _write_text(workspace_dir / ".codex" / "config.toml", original_config)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(workspace_dir / ".codex" / "hooks.json", '{"hooks": ')

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
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
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_config
    assert (workspace_dir / ".codex" / "hooks.json").read_text(encoding="utf-8") == '{"hooks": '


def test_guard_install_codex_skips_unchanged_read_only_alternate_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = json.dumps(
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                    }
                ]
            }
        },
        indent=2,
    )
    _write_text(home_hooks_path, original_hooks + "\n")
    os.chmod(home_hooks_path, 0o444)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert home_hooks_path.read_text(encoding="utf-8") == original_hooks + "\n"


def test_guard_uninstall_codex_skips_unchanged_read_only_alternate_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = json.dumps(
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                    }
                ]
            }
        },
        indent=2,
    )
    _write_text(home_hooks_path, original_hooks + "\n")

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    os.chmod(home_hooks_path, 0o444)

    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
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
    assert home_hooks_path.read_text(encoding="utf-8") == original_hooks + "\n"


def test_guard_install_codex_preserves_unchanged_empty_alternate_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = '{\n  "hooks": {}\n}\n'
    _write_text(home_hooks_path, original_hooks)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert home_hooks_path.read_text(encoding="utf-8") == original_hooks


def test_guard_uninstall_codex_preserves_unchanged_empty_alternate_hook_file(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    home_hooks_path = home_dir / ".codex" / "hooks.json"
    original_hooks = '{\n  "hooks": {}\n}\n'
    _write_text(home_hooks_path, original_hooks)

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
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
            "codex",
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
    assert home_hooks_path.read_text(encoding="utf-8") == original_hooks


def test_guard_detect_codex_collects_global_and_workspace_hooks(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "python3 global-pre.py"}],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "python3 workspace-pre.py"}],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
    )

    detection = CodexHarnessAdapter().detect(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=tmp_path / "guard-home",
        )
    )

    hook_artifacts = [artifact for artifact in detection.artifacts if artifact.artifact_type == "hook"]

    assert {artifact.command for artifact in hook_artifacts} == {
        "python3 global-pre.py",
        "python3 workspace-pre.py",
    }
    assert {artifact.source_scope for artifact in hook_artifacts} == {"global", "project"}
    assert set(detection.config_paths) == {
        str(home_dir / ".codex" / "hooks.json"),
        str(workspace_dir / ".codex" / "hooks.json"),
    }


def test_guard_install_codex_encodes_dash_prefixed_server_args_safely(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.flagged_tool]
command = "python3"
args = ["server.py", "--marker-path", "marker.json"]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    assert rc == 0
    assert "--arg=--marker-path" in config_text


def test_guard_reinstall_codex_preserves_original_backup(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    original_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    first_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    second_install = main(
        [
            "guard",
            "install",
            "codex",
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
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    backup_path = Path(first_output["managed_install"]["manifest"]["backup_path"])

    assert first_install == 0
    assert second_install == 0
    assert uninstall_rc == 0
    assert backup_path.exists() is False
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_text


def test_guard_install_codex_preserves_inline_tables_inside_arrays(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"
profiles = [{ name = "default", mode = "safe" }, { name = "strict", mode = "review" }]

[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)

    assert rc == 0
    assert payload["profiles"] == [
        {"name": "default", "mode": "safe"},
        {"name": "strict", "mode": "review"},
    ]


def test_guard_reinstall_codex_refreshes_backup_after_completed_uninstall(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    first_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.workspace_skill]
command = "node"
args = ["edited-workspace-skill.js"]
""".strip()
        + "\n",
    )

    second_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)
    second_uninstall = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    backup_path = Path(first_output["managed_install"]["manifest"]["backup_path"])

    assert first_install == 0
    assert uninstall_rc == 0
    assert second_install == 0
    assert second_uninstall == 0
    assert backup_path == Path(second_output["managed_install"]["manifest"]["backup_path"])
    assert backup_path.exists() is False
    assert "edited-workspace-skill.js" in (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")


def test_guard_install_codex_proxy_entry_boots_outside_dev_shell_when_pythonpath_is_required(
    tmp_path, capsys, monkeypatch
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    marker_path = tmp_path / "marker.json"
    canary_path = Path(__file__).resolve().parent / "fixtures" / "mcp-canary-server.py"
    source_root = Path(__file__).resolve().parents[1] / "src"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        f"""
[mcp_servers.danger_lab]
command = "python3"
args = [{str(canary_path)!r}, "--marker-path", {str(marker_path)!r}]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_entry = payload["mcp_servers"]["danger_lab"]
    proxy_env = dict(proxy_entry.get("env", {}))
    result = subprocess.run(
        [proxy_entry["command"], *proxy_entry["args"]],
        input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}\n',
        text=True,
        capture_output=True,
        cwd=workspace_dir,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(home_dir),
            **proxy_env,
        },
        check=False,
    )

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == str(source_root)
    assert result.returncode == 0
    assert json.loads(result.stdout)["result"]["serverInfo"]["name"] == "danger-lab"


def test_guard_install_codex_preserves_server_relative_pythonpath_entries(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    source_root = Path(__file__).resolve().parents[1] / "src"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.danger_lab]
command = "python3"
args = ["danger-lab.py"]
env = { PYTHONPATH = "app/src", API_BASE = "https://hol.org" }
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_env = payload["mcp_servers"]["danger_lab"]["env"]

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == os.pathsep.join((str(source_root), "app/src"))


def test_guard_install_codex_allows_server_to_clear_launcher_pythonpath(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.danger_lab]
command = "python3"
args = ["danger-lab.py"]
env = { PYTHONPATH = "" }
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_env = payload["mcp_servers"]["danger_lab"]["env"]

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == ""
