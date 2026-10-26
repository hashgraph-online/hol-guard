"""A Desktop-managed frozen Core must not bake its pruneable versions/ path into harness config."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import stable_guard_cli
from codex_plugin_scanner.guard.adapters import claude_hook_argv, cline_mcp, copilot, hermes
from codex_plugin_scanner.guard.adapters._modules.claude.claude_frozen_hook import FROZEN_CLAUDE_HOOK_COMMAND
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.hook_python import guard_cli_command
from codex_plugin_scanner.guard.adapters.mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    proxy_cli_args,
    proxy_launcher_entry,
)


def _write_launcher(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o700)
    return path


@pytest.fixture
def versioned_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    core = tmp_path / "core"
    executable = _write_launcher(core / "versions" / "2.0.900" / "hol-guard")
    shim = _write_launcher(core / "current-hol-guard")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "linux")
    launcher = stable_guard_cli.guard_cli_launcher()
    assert launcher == str(shim)
    return executable, launcher


def _context(tmp_path: Path) -> HarnessContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=tmp_path / "guard-home")


def _server(tmp_path: Path) -> ManagedMcpServer:
    return ManagedMcpServer(
        harness="cursor",
        name="fixture",
        source_scope="user",
        config_path=str(tmp_path / "mcp.json"),
        command="node",
        args=("server.js",),
        transport="stdio",
        env={},
        enabled=True,
    )


def test_source_install_keeps_the_running_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)

    assert stable_guard_cli.guard_cli_launcher() == sys.executable


def test_claude_frozen_hooks_use_the_stable_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, versioned_core: tuple[Path, str]
) -> None:
    _, launcher = versioned_core

    def no_native_bridge(_guard_home: Path) -> None:
        return None

    monkeypatch.setattr(claude_hook_argv, "_native_bridge_executable", no_native_bridge)
    context = _context(tmp_path)

    hook = claude_hook_argv.guard_hook_command_parts(context)
    daemon = claude_hook_argv.daemon_hook_command_parts(context, fallback_daemon_url="http://127.0.0.1:1")
    session = claude_hook_argv._python_session_start_command_parts(context)  # pyright: ignore[reportPrivateUsage]

    assert [hook[0], daemon[0], session[0]] == [launcher, launcher, launcher]
    assert hook[1] == "hook"
    assert daemon[1] == session[1] == FROZEN_CLAUDE_HOOK_COMMAND


def test_frozen_mcp_proxies_use_the_stable_launcher(tmp_path: Path, versioned_core: tuple[Path, str]) -> None:
    executable, launcher = versioned_core
    context = _context(tmp_path)
    server = _server(tmp_path)
    python_args = proxy_cli_args(proxy_command="cursor-mcp-proxy", guard_home=str(context.guard_home), server=server)
    stale: dict[str, object] = {"command": str(executable), "args": python_args}

    commands = [
        proxy_launcher_entry(proxy_command="cursor-mcp-proxy", context=context, server=server)["command"],
        CursorHarnessAdapter()._proxy_server_entry(context, server)["command"],  # pyright: ignore[reportPrivateUsage]
        CursorHarnessAdapter._refresh_guard_proxy_entry(stale)["command"],  # pyright: ignore[reportPrivateUsage]
        copilot._refresh_guard_proxy_entry(stale, launcher_env={})["command"],  # pyright: ignore[reportPrivateUsage]
        cline_mcp._proxy_entry(context, server)["command"],  # pyright: ignore[reportPrivateUsage]
        hermes._overlay_servers(context=context, source_configs={"fixture": {"command": "node"}})["fixture"]["command"],  # pyright: ignore[reportPrivateUsage]
    ]

    assert commands == [launcher] * len(commands)
    assert is_guard_proxy_command(launcher, tuple(python_args))
    assert not is_guard_proxy_command(str(tmp_path / "other-tool"), ("server.js",))


def test_frozen_opencode_cli_command_uses_the_stable_launcher(tmp_path: Path, versioned_core: tuple[Path, str]) -> None:
    _, launcher = versioned_core

    command = guard_cli_command(_context(tmp_path), ["-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"])

    assert command == [launcher, "opencode-mcp-proxy"]


def test_transition_binding_keeps_the_exact_process(versioned_core: tuple[Path, str]) -> None:
    executable, _ = versioned_core

    with stable_guard_cli.exact_process_guard_cli_binding():
        bound = stable_guard_cli.guard_cli_launcher()

    assert bound == str(executable.resolve())


def test_windows_never_uses_the_extensionless_shim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    core = tmp_path / "core"
    executable = _write_launcher(core / "versions" / "2.0.900" / "hol-guard")
    _ = _write_launcher(core / "current-hol-guard")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "win32")

    assert stable_guard_cli.guard_cli_launcher() == str(executable)
    assert stable_guard_cli.prune_safe_cli_executable(str(executable)) == str(executable)


def test_windows_keeps_the_core_executable_over_a_batch_shim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    core = tmp_path / "core"
    executable = _write_launcher(core / "versions" / "2.0.900" / "hol-guard")
    shim = _write_launcher(core / "current-hol-guard.cmd")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "platform", "win32")

    assert stable_guard_cli.resolve_frozen_guard_cli() == str(shim)
    assert stable_guard_cli.guard_cli_launcher() == str(executable)
