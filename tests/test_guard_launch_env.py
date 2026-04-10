"""Launch environment tests for Guard wrapper execution."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )


class _CompletedProcess:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


def test_guard_run_launches_with_configured_home(monkeypatch, tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
    captured_env: dict[str, str] = {}
    captured_cwd: Path | None = None

    def _fake_run(command, cwd=None, check=False, env=None):
        del command, check
        nonlocal captured_cwd
        captured_cwd = cwd
        captured_env.update(env or {})
        return _CompletedProcess(0)

    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--arg=--help",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["launched"] is True
    assert captured_env["HOME"] == str(home_dir)
    assert captured_cwd == workspace_dir
