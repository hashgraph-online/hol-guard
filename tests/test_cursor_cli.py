"""Tests for Cursor CLI entry-point resolution and launch shims."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor_cli import (
    cursor_cli_command_available,
    cursor_cli_detected,
    resolve_cursor_cli_entry,
)
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home.mkdir()
    workspace.mkdir()
    guard_home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _write_fake_cursor_agent(bin_dir: Path) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "cursor-agent"
    script.write_text(
        '#!/bin/sh\nif [ "$1" = "mcp" ] && [ "$2" = "list" ]; then exit 0; fi\nexit 0\n',
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | 0o755)
    return script


def _write_fake_cursor_with_agent_subcommand(bin_dir: Path) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "cursor"
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "agent" ]; then\n'
        "  shift\n"
        '  if [ "$1" = "--help" ] || [ "$1" = "mcp" ]; then exit 0; fi\n'
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | 0o755)
    return script


def test_resolve_cursor_cli_entry_prefers_cursor_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    _write_fake_cursor_agent(bin_dir)
    _write_fake_cursor_with_agent_subcommand(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    context = _context(tmp_path)

    entry = resolve_cursor_cli_entry(context)

    assert entry is not None
    assert Path(entry.executable).name == "cursor-agent"
    assert entry.prefix_args == ()
    assert entry.launch_argv(["--print", "hello"]) == [
        str(bin_dir / "cursor-agent"),
        "--print",
        "hello",
    ]


def test_resolve_cursor_cli_entry_uses_cursor_agent_subcommand(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    _write_fake_cursor_with_agent_subcommand(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    context = _context(tmp_path)

    entry = resolve_cursor_cli_entry(context)

    assert entry is not None
    assert Path(entry.executable).name == "cursor"
    assert entry.launch_argv(["--print", "hello"]) == [
        str(bin_dir / "cursor"),
        "agent",
        "--print",
        "hello",
    ]
    assert entry.launch_argv(["agent", "--print", "hello"]) == [
        str(bin_dir / "cursor"),
        "agent",
        "--print",
        "hello",
    ]


def test_cursor_cli_install_creates_dual_shims_and_shell_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    _write_fake_cursor_with_agent_subcommand(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)

    install_payload = apply_managed_install(
        "install",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-29T12:00:00Z",
        surface="cli",
    )
    managed_install = install_payload["managed_install"]

    assert managed_install["shim_command"] == "guard-cursor-agent"
    assert managed_install["shim_commands"] == ["guard-cursor-agent", "guard-cursor"]
    assert Path(managed_install["shim_paths"][0]).exists()
    assert Path(managed_install["shim_paths"][1]).exists()
    profile_path = context.home_dir / ".zshrc"
    assert profile_path.exists()
    assert "HOL Guard harness launchers" in profile_path.read_text(encoding="utf-8")
    assert str(context.guard_home / "bin") in profile_path.read_text(encoding="utf-8")


def test_guard_run_launches_cursor_agent_subcommand(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    cursor_path = _write_fake_cursor_with_agent_subcommand(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    context = _context(tmp_path)
    captured: dict[str, object] = {}

    class _CompletedProcess:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(command, cwd=None, check=False, env=None, **kwargs):
        del check, kwargs, cwd, env
        captured["command"] = list(command)
        return _CompletedProcess()

    monkeypatch.setattr(guard_runner_module.subprocess, "run", _fake_run)

    from codex_plugin_scanner.guard.config import load_guard_config
    from codex_plugin_scanner.guard.runtime.runner import guard_run
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(context.guard_home)
    config = load_guard_config(context.guard_home, workspace=context.workspace_dir)
    evaluation = guard_run(
        "cursor",
        context,
        store,
        config,
        dry_run=False,
        passthrough_args=["agent", "--print", "hello"],
        default_action="allow",
    )

    assert evaluation["launched"] is True
    assert captured["command"] == [str(cursor_path), "agent", "--print", "hello"]


def test_cursor_cli_detected_without_shims_when_cursor_agent_subcommand_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    _write_fake_cursor_with_agent_subcommand(bin_dir)
    monkeypatch.setenv("PATH", str(bin_dir))
    context = _context(tmp_path)

    assert cursor_cli_command_available(context) is True
    assert cursor_cli_detected(context) is True
    assert CursorHarnessAdapter().detect(context).command_available is True
