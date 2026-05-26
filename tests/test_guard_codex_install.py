from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
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

[features]
codex_hooks = true

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
    config_payload = tomllib.loads(config_text)
    hooks_path = workspace_dir / ".codex" / "hooks.json"
    hooks_payload = config_payload["hooks"]

    assert rc == 0
    assert managed_install["active"] is True
    assert manifest["mode"] == "codex-mcp-proxy"
    assert manifest["managed_config_path"] == str(workspace_dir / ".codex" / "config.toml")
    assert manifest["managed_hooks_path"] == str(hooks_path)
    assert manifest["managed_shell_guard_path"] == str(home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh")
    assert manifest["managed_shell_guard_paths"] == {
        "zsh": str(home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh"),
        "bash": str(home_dir / "managed" / "codex" / "codex-bashenv-guard.bash"),
        "fish": str(home_dir / "managed" / "codex" / "codex-fish-guard.fish"),
        "fish_conf": str(home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish"),
    }
    assert set(manifest["managed_servers"]) == {"global_tools", "workspace_skill"}
    assert "--server-name" in config_text
    assert "guard" in config_text
    assert "codex-mcp-proxy" in config_text
    assert 'approval_policy = "never"' in config_text
    assert "hooks = true" in config_text
    assert "codex_hooks" not in config_text
    assert hooks_path.exists() is False
    assert 'API_BASE = "https://hol.org"' in config_text
    assert 'FEATURE_FLAG = "1"' in config_text
    assert hooks_payload["PreToolUse"][0]["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
    assert hooks_payload["PermissionRequest"][0]["matcher"] == codex_adapter._CODEX_GUARD_PERMISSION_MATCHER
    assert "UserPromptSubmit" in hooks_payload
    assert "matcher" not in hooks_payload["UserPromptSubmit"][0]
    prompt_handler = hooks_payload["UserPromptSubmit"][0]["hooks"][0]
    assert prompt_handler["type"] == "command"
    assert "codex_plugin_scanner.cli" in prompt_handler["command"]
    assert "hook" in prompt_handler["command"]
    assert "codex" in prompt_handler["command"]
    handler = hooks_payload["PreToolUse"][0]["hooks"][0]
    assert handler["type"] == "command"
    assert "codex_plugin_scanner.cli" in handler["command"]
    assert "hook" in handler["command"]
    assert "codex" in handler["command"]
    permission_handler = hooks_payload["PermissionRequest"][0]["hooks"][0]
    assert permission_handler["type"] == "command"
    assert "codex_plugin_scanner.cli" in permission_handler["command"]
    assert "hook" in permission_handler["command"]
    assert "codex" in permission_handler["command"]
    zshenv_text = (home_dir / ".zshenv").read_text(encoding="utf-8")
    shell_guard_text = (home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh").read_text(encoding="utf-8")
    bash_guard_text = (home_dir / "managed" / "codex" / "codex-bashenv-guard.bash").read_text(encoding="utf-8")
    fish_guard_text = (home_dir / "managed" / "codex" / "codex-fish-guard.fish").read_text(encoding="utf-8")
    fish_conf_text = (home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish").read_text(encoding="utf-8")
    assert "HOL Guard Codex shell guard" in zshenv_text
    assert "TRAPDEBUG" in shell_guard_text
    assert "BASH_ENV" in (home_dir / ".bash_profile").read_text(encoding="utf-8")
    assert "BASH_ENV" in (home_dir / ".bashrc").read_text(encoding="utf-8")
    assert "BASH_ENV" in (home_dir / ".profile").read_text(encoding="utf-8")
    assert "extdebug" in bash_guard_text
    assert "fish_preexec" in fish_guard_text
    assert "codex-fish-guard.fish" in fish_conf_text
    assert ".npmrc" in shell_guard_text


def test_guard_install_codex_replaces_existing_zshenv_guard_block(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    _write_text(
        home_dir / ".zshenv",
        "\n".join(
            [
                "export KEEP_ME=1",
                "",
                "# >>> HOL Guard Codex shell guard >>>",
                "source /tmp/old",
                "# <<< HOL Guard Codex shell guard <<<",
                "",
            ]
        ),
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
    zshenv_text = (home_dir / ".zshenv").read_text(encoding="utf-8")

    assert rc == 0
    assert "export KEEP_ME=1" in zshenv_text
    assert "/tmp/old" not in zshenv_text
    assert zshenv_text.count("HOL Guard Codex shell guard") == 2


def test_guard_uninstall_codex_removes_shell_guard_blocks(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / ".zshenv", "export KEEP_ME=1\n")
    _write_text(home_dir / ".bashrc", "export KEEP_BASHRC=1\n")
    _write_text(home_dir / ".bash_profile", "export KEEP_BASH_PROFILE=1\n")
    _write_text(home_dir / ".profile", "export KEEP_PROFILE=1\n")

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
    guard_path = home_dir / "managed" / "codex" / "codex-zshenv-guard.zsh"
    bash_guard_path = home_dir / "managed" / "codex" / "codex-bashenv-guard.bash"
    fish_guard_path = home_dir / "managed" / "codex" / "codex-fish-guard.fish"

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
    assert guard_path.exists() is False
    assert bash_guard_path.exists() is False
    assert fish_guard_path.exists() is False
    assert (home_dir / ".zshenv").read_text(encoding="utf-8") == "export KEEP_ME=1\n"
    assert (home_dir / ".bashrc").read_text(encoding="utf-8") == "export KEEP_BASHRC=1\n"
    assert (home_dir / ".bash_profile").read_text(encoding="utf-8") == "export KEEP_BASH_PROFILE=1\n"
    assert (home_dir / ".profile").read_text(encoding="utf-8") == "export KEEP_PROFILE=1\n"
    assert (home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish").exists() is False


def test_guard_uninstall_codex_deletes_managed_only_shell_startup_files(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

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
    assert (home_dir / ".zshenv").exists() is False
    assert (home_dir / ".bashrc").exists() is False
    assert (home_dir / ".bash_profile").exists() is False
    assert (home_dir / ".profile").exists() is False
    assert (home_dir / ".config" / "fish" / "conf.d" / "hol-guard-codex.fish").exists() is False


def test_guard_codex_shell_guards_block_zsh_and_bash_secret_reads(tmp_path, capsys):
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
    json.loads(capsys.readouterr().out)
    npmrc_path = home_dir / ".npmrc"
    _write_text(npmrc_path, "FAKE_HOL_GUARD_SHOULD_NOT_PRINT\n")

    assert rc == 0
    shell_commands = []
    if Path("/bin/zsh").is_file():
        shell_commands.append(("/bin/zsh", ["/bin/zsh", "-lc", "cat ~/.np''mrc"]))
    if Path("/bin/bash").is_file():
        shell_commands.append(("/bin/bash", ["/bin/bash", "-lc", "cat ~/.np''mrc"]))
    if not shell_commands:
        return

    for shell_name, command in shell_commands:
        result = subprocess.run(
            command,
            cwd=workspace_dir,
            env={**os.environ, "HOME": str(home_dir), "CODEX_MANAGED_BY_BUN": "1"},
            text=True,
            capture_output=True,
            check=False,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        assert "FAKE_HOL_GUARD_SHOULD_NOT_PRINT" not in combined, shell_name
        assert "HOL Guard blocked Codex before it could read a secret-looking local file." in combined, shell_name


def test_guard_apps_connect_codex_defaults_to_project_scope_when_local_codex_config_exists(
    tmp_path,
    monkeypatch,
    capsys,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.chdir(workspace_dir)

    rc = main(
        [
            "guard",
            "apps",
            "connect",
            "codex",
            "--home",
            str(home_dir),
            "--guard-home",
            str(home_dir / ".hol-guard"),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["managed_install"]["active"] is True
    assert output["managed_install"]["workspace"] == str(workspace_dir)
    assert output["managed_install"]["manifest"]["managed_config_path"] == str(workspace_dir / ".codex" / "config.toml")


def test_guard_apps_connect_codex_stays_global_without_local_codex_config(
    tmp_path,
    monkeypatch,
    capsys,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python3"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    monkeypatch.chdir(workspace_dir)

    rc = main(
        [
            "guard",
            "apps",
            "connect",
            "codex",
            "--home",
            str(home_dir),
            "--guard-home",
            str(home_dir / ".hol-guard"),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["managed_install"]["active"] is True
    assert output["managed_install"]["workspace"] is None
    assert output["managed_install"]["manifest"]["managed_config_path"] == str(home_dir / ".codex" / "config.toml")


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
                            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
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
    config_payload = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
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
    assert len(config_payload["hooks"]["PreToolUse"]) == 1
    assert hooks_payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "python3 custom-pre.py"
    managed_group = config_payload["hooks"]["PreToolUse"][0]
    assert managed_group["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
    assert "codex_plugin_scanner.cli" in managed_group["hooks"][0]["command"]
    assert "hook" in managed_group["hooks"][0]["command"]
    assert "codex" in managed_group["hooks"][0]["command"]
    assert restored_hooks["hooks"]["PreToolUse"] == [
        {
            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
        }
    ]
    assert restored_hooks["hooks"]["SessionStart"] == [
        {
            "matcher": "startup|resume",
            "hooks": [{"type": "command", "command": "python3 custom-start.py"}],
        }
    ]


def test_guard_install_codex_migrates_legacy_bash_only_managed_hook(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    context = HarnessContext(home_dir=home_dir, guard_home=home_dir / ".hol-guard", workspace_dir=workspace_dir)
    legacy_group = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": (
                    f"python -m codex_plugin_scanner.cli guard hook --guard-home {context.guard_home} --harness codex"
                ),
                "timeoutSec": 30,
                "statusMessage": "HOL Guard checking Bash command",
            }
        ],
    }
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps({"hooks": {"PreToolUse": [legacy_group]}}, indent=2) + "\n",
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
    config_payload = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert install_rc == 0
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert len(config_payload["hooks"]["PreToolUse"]) == 1
    assert len(config_payload["hooks"]["PermissionRequest"]) == 1
    assert len(config_payload["hooks"]["UserPromptSubmit"]) == 1
    assert config_payload["hooks"]["PreToolUse"][0]["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
    assert config_payload["hooks"]["PreToolUse"][0]["hooks"][0]["statusMessage"] == "HOL Guard checking tool action"
    assert len(config_payload["hooks"]["UserPromptSubmit"]) == 1


def test_guard_install_codex_migrates_stale_python_c_managed_hooks(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    stale_worktree = tmp_path / "deleted-worktree"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    stale_command = f"{sys.executable} -c " + shlex.quote(
        "import sys;"
        f"sys.path[:0]=[{str(stale_worktree / 'src')!r}];"
        "from codex_plugin_scanner.cli import main;"
        "raise SystemExit(main(["
        '"guard", "hook", "--guard-home", '
        f"{str(home_dir / '.hol-guard')!r}, "
        '"--harness", "codex"'
        "]))"
    )
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": stale_command,
                                    "timeoutSec": 30,
                                    "statusMessage": "HOL Guard checking tool action",
                                }
                            ],
                        }
                    ],
                    "UserPromptSubmit": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": stale_command,
                                    "timeoutSec": 30,
                                    "statusMessage": "HOL Guard checking prompt",
                                }
                            ]
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
    config_payload = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert install_rc == 0
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert len(config_payload["hooks"]["PreToolUse"]) == 1
    assert len(config_payload["hooks"]["UserPromptSubmit"]) == 1
    assert len(config_payload["hooks"]["PermissionRequest"]) == 1
    assert len(config_payload["hooks"]["PostToolUse"]) == 1
    all_commands = json.dumps(config_payload["hooks"])
    assert str(stale_worktree) not in all_commands


def test_guard_install_codex_migrates_legacy_wrapper_script_hook(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".codex" / "config.toml", 'approval_policy = "never"\n')
    wrapper_command = shlex.join([str(home_dir / ".codex" / "hooks" / "hol-guard-codex-hook.sh"), "--legacy"])
    managed_events = {
        "PreToolUse": {
            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking tool action",
                }
            ],
        },
        "PermissionRequest": {
            "matcher": "Bash|^apply_patch$|Edit|Write|mcp__.*",
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking Codex approval request",
                }
            ],
        },
        "UserPromptSubmit": {
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking prompt",
                }
            ],
        },
        "PostToolUse": {
            "matcher": "Bash",
            "hooks": [
                {
                    "type": "command",
                    "command": wrapper_command,
                    "timeout": 30,
                    "statusMessage": "HOL Guard checking tool result",
                }
            ],
        },
    }
    _write_text(
        workspace_dir / ".codex" / "hooks.json",
        json.dumps({"hooks": {key: [value] for key, value in managed_events.items()}}, indent=2) + "\n",
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
    config_payload = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))

    assert install_rc == 0
    assert (workspace_dir / ".codex" / "hooks.json").exists() is False
    assert len(config_payload["hooks"]["PreToolUse"]) == 1
    assert len(config_payload["hooks"]["PermissionRequest"]) == 1
    assert len(config_payload["hooks"]["UserPromptSubmit"]) == 1
    assert len(config_payload["hooks"]["PostToolUse"]) == 1
    all_commands = json.dumps(config_payload["hooks"])
    assert wrapper_command not in all_commands


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
    workspace_config = tomllib.loads((workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    workspace_hooks = workspace_config["hooks"]

    assert global_install_rc == 0
    assert workspace_install_rc == 0
    assert home_hooks_path.exists() is False
    assert len(workspace_hooks["PreToolUse"]) == 1
    managed_group = workspace_hooks["PreToolUse"][0]
    assert managed_group["matcher"] == codex_adapter._CODEX_GUARD_TOOL_MATCHER
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
    hooks_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
                            "hooks": [{"type": "command", "command": "python3 custom-pre.py"}],
                        }
                    ]
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

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
            "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
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


def test_guard_install_codex_strips_server_python_injection_env_entries(tmp_path, capsys, monkeypatch):
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
    assert proxy_env["PYTHONPATH"] == str(source_root)
    assert proxy_env["API_BASE"] == "https://hol.org"


def test_guard_install_codex_ignores_server_attempt_to_clear_launcher_pythonpath(tmp_path, capsys, monkeypatch):
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
    assert proxy_env["PYTHONPATH"] == str(source_root)
