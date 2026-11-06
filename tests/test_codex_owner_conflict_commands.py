"""Install, connect and repair must preserve conflicting unowned hooks."""

import json
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_config import dump_toml


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_guard_codex_install_rejects_ambiguous_foreign_direct_hook(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    config_path = CodexHarnessAdapter._hook_config_path(context)
    foreign_command = shlex.join(codex_adapter._local_hook_command_parts(context))
    foreign_group = {
        "matcher": codex_adapter._CODEX_GUARD_TOOL_MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": foreign_command,
                "statusMessage": "HOL Guard checking tool action",
            }
        ],
    }
    _write_text(
        config_path,
        dump_toml({"features": {"hooks": True}, "hooks": {"PreToolUse": [foreign_group]}}),
    )

    original_config = config_path.read_bytes()
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        CodexHarnessAdapter().install(context)
    assert config_path.read_bytes() == original_config
    assert not codex_adapter.hook_manifest_path(context.guard_home, config_path).exists()


def test_guard_install_and_repair_codex_reject_ambiguous_legacy_post_tool_hooks(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = home_dir / ".hol-guard"
    codex_home = home_dir / ".codex"
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_support_interaction._open_guard_cloud_app",
        lambda **_kwargs: {"status": "test"},
    )
    stale_bridge_path = (
        home_dir
        / ".local"
        / "share"
        / "uv"
        / "tools"
        / "hol-guard"
        / "lib"
        / "python3.12"
        / "site-packages"
        / "codex_plugin_scanner"
        / "guard"
        / "adapters"
        / "codex_daemon_hook_bridge.py"
    )
    stale_bridge_command = shlex.join(
        [
            str(home_dir / ".local" / "share" / "uv" / "tools" / "hol-guard" / "bin" / "python"),
            str(stale_bridge_path),
            json.dumps(
                {
                    "state_path": str(guard_home / "daemon-state.json"),
                    "fallback_command": [
                        str(home_dir / ".local" / "bin" / "python"),
                        "-m",
                        "codex_plugin_scanner.cli",
                        "guard",
                        "hook",
                        "--harness",
                        "codex",
                    ],
                    "start_command": [str(home_dir / ".local" / "bin" / "python"), "-c", "pass"],
                    "query": "guard-home=stale",
                    "hook_timeouts": {"PostToolUse": 30},
                },
                separators=(",", ":"),
            ),
        ]
    )
    stale_direct_command = shlex.join(
        [
            str(home_dir / ".local" / "pipx" / "venvs" / "hol-guard" / "bin" / "python"),
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--harness",
            "codex",
            "--workspace",
            str(workspace_dir),
        ]
    )
    lean_command = "lean-ctx hook observe"
    _write_text(
        codex_home / "config.toml",
        dump_toml(
            {
                "features": {"hooks": True},
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": ".*",
                            "hooks": [{"type": "command", "command": lean_command}],
                        },
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": stale_bridge_command,
                                    "statusMessage": "HOL Guard checking tool result",
                                }
                            ],
                        },
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": stale_direct_command}],
                        },
                    ]
                },
            }
        ),
    )

    config_path = codex_home / "config.toml"
    original_config = config_path.read_bytes()
    for command in (
        ["guard", "install", "codex"],
        ["guard", "apps", "connect", "codex"],
        ["guard", "apps", "repair", "codex"],
    ):
        rc = main(
            [
                *command,
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--guard-home",
                str(guard_home),
                "--json",
            ]
        )
        captured = capsys.readouterr()
        assert rc != 0
        assert "codex_hook_owner_conflict" in captured.out + captured.err
        assert config_path.read_bytes() == original_config
        assert not codex_adapter.hook_manifest_path(guard_home, config_path).exists()
