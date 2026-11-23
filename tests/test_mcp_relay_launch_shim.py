"""The Python ``*-mcp-proxy`` commands only start the native MCP relay."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.cli import commands_dispatch_proxy as dispatch
from codex_plugin_scanner.guard.cli import commands_mcp_relay_launch as launch
from codex_plugin_scanner.guard.harness_context import HarnessContext


def _options(**fields: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "home": "/home/agent",
        "workspace": "/work/space",
        "server_name": "docs",
        "source_scope": "project",
        "config_path": "/work/space/.codex/config.toml",
        "transport": "stdio",
    }
    return argparse.Namespace(**{**defaults, **fields})


def test_the_relay_argv_keeps_every_value_bound_to_its_flag() -> None:
    guard_home = Path("/guard/home")
    argv = launch.relay_argv(
        "codex-mcp-proxy",
        _options(),
        guard_home=guard_home,
        server_command="node",
        server_args=["--inspect", "server.js"],
        server_id="mcp_server:codex:project:docs:1",
        server_env_keys=("API_REGION",),
    )

    assert argv == [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "codex-mcp-proxy",
        f"--guard-home={guard_home}",
        "--home=/home/agent",
        "--workspace=/work/space",
        "--server-name=docs",
        "--server-id=mcp_server:codex:project:docs:1",
        "--source-scope=project",
        "--config-path=/work/space/.codex/config.toml",
        "--transport=stdio",
        "--command=node",
        "--arg=--inspect",
        "--arg=server.js",
        "--server-env-key=API_REGION",
    ]


def test_an_unset_optional_flag_is_left_out() -> None:
    argv = launch.relay_argv(
        "cursor-mcp-proxy",
        _options(home=None, workspace=None),
        guard_home=Path("/guard/home"),
        server_command="node",
        server_args=[],
        server_id=None,
        server_env_keys=(),
    )

    assert not [item for item in argv if item.startswith(("--home", "--workspace", "--server-id", "--arg"))]


def test_without_a_relaying_runtime_the_command_refuses_and_names_the_repair(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(launch, "native_hook_bridge_executable", lambda *_args, **_kwargs: None)

    def no_exec(*_args: object) -> None:
        pytest.fail("nothing may start without the relay")

    monkeypatch.setattr(launch.os, "execv", no_exec)
    monkeypatch.setattr(launch.subprocess, "call", no_exec)

    assert launch.run_relay(["-m", "codex_plugin_scanner.cli"], guard_home=Path("/guard/home")) == 1
    assert "hol-guard repair" in capsys.readouterr().err


@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_a_runtime_that_cannot_start_names_the_repair(
    platform: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        launch, "native_hook_bridge_executable", lambda *_args, **_kwargs: Path("/opt/guard/hol-guard-runtime")
    )

    def missing(*_args: object) -> None:
        raise FileNotFoundError("hol-guard-runtime")

    monkeypatch.setattr(launch, "os", SimpleNamespace(name=platform, execv=missing))
    monkeypatch.setattr(launch.subprocess, "call", missing)

    assert launch.run_relay(["-m", "codex_plugin_scanner.cli"], guard_home=Path("/guard/home")) == 1
    assert "hol-guard repair" in capsys.readouterr().err


def test_the_command_hands_its_argv_to_the_relay(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = Path("/opt/guard/hol-guard-runtime")
    asked: list[str] = []
    launched: list[list[str]] = []

    def executable(feature: str, **_kwargs: object) -> Path:
        asked.append(feature)
        return runtime

    def exec_relay(path: str, argv: list[str]) -> None:
        assert path == str(runtime)
        launched.append(argv)

    monkeypatch.setattr(launch, "native_hook_bridge_executable", executable)
    monkeypatch.setattr(launch, "os", SimpleNamespace(name="posix", execv=exec_relay))

    launch.run_relay(["-m", "codex_plugin_scanner.cli", "guard"], guard_home=Path("/guard/home"))

    assert asked == [launch.RELAY_FEATURE]
    assert launched == [[str(runtime), "mcp-relay", sys.executable, "-m", "codex_plugin_scanner.cli", "guard"]]


@pytest.mark.parametrize(
    ("proxy", "command"),
    [
        ("codex-mcp-proxy", dispatch._run_guard_codex_mcp_proxy_command),
        ("cursor-mcp-proxy", dispatch._run_guard_cursor_mcp_proxy_command),
        ("cline-mcp-proxy", dispatch._run_guard_cline_mcp_proxy_command),
        ("opencode-mcp-proxy", dispatch._run_guard_opencode_mcp_proxy_command),
        ("copilot-mcp-proxy", dispatch._run_guard_copilot_mcp_proxy_command),
    ],
)
def test_each_proxy_command_relays_its_server(
    proxy: str, command: Callable[..., int], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relayed: list[list[str]] = []
    guard_home = tmp_path / "guard-home"

    def run_relay(argv: list[str], *, guard_home: Path) -> int:
        relayed.append(argv)
        return 0

    monkeypatch.setattr(launch, "run_relay", run_relay)
    args = _build_parser("codex-plugin-scanner", program_mode="combined").parse_args(
        [
            "guard",
            proxy,
            "--guard-home",
            str(guard_home),
            "--server-name",
            "docs",
            "--config-path",
            str(tmp_path / "config.toml"),
            "--command",
            "node",
            "--arg=--inspect",
        ]
    )
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)

    assert command(args, context=context) == 0
    assert len(relayed) == 1
    argv = relayed[0]
    assert argv[:5] == ["-m", "codex_plugin_scanner.cli", "guard", proxy, f"--guard-home={guard_home}"]
    assert "--server-name=docs" in argv
    assert argv[-2:] == ["--command=node", "--arg=--inspect"]
