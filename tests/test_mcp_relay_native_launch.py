"""Installer selection of the native MCP stdio relay versus the Python proxy."""

from __future__ import annotations

import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import mcp_relay_native, native_hook_bridge
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import discover_harness_mcp_servers
from codex_plugin_scanner.guard.adapters.managed_mcp_upstream import proxy_argument_tail
from codex_plugin_scanner.guard.adapters.mcp_relay_native import (
    MCP_RELAY_SELECTION_ENV,
    NATIVE_MCP_RELAY_COMMAND,
    NATIVE_MCP_RELAY_DECIDE_FEATURE,
    NATIVE_MCP_RELAY_FEATURE,
    RELAY_PROXY_COMMANDS,
    mcp_proxy_command,
    mcp_proxy_launch,
    python_proxy_launch,
)
from codex_plugin_scanner.guard.adapters.mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    proxy_cli_args,
    proxy_launcher_entry,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection

_RUNTIME_SRC = Path(__file__).resolve().parents[1] / "rust" / "crates" / "guard-runtime" / "src"
_RUNTIME = Path("/opt/guard/hol-guard-runtime")


def _server(tmp_path: Path, harness: str = "codex") -> ManagedMcpServer:
    return ManagedMcpServer(
        harness=harness,
        name="fixture",
        source_scope="user",
        config_path=str(tmp_path / "config.toml"),
        command="python",
        args=("fixture_server.py", "--stdio"),
        transport="stdio",
        env={},
        enabled=True,
    )


def _python_args(tmp_path: Path, proxy: str = "codex-mcp-proxy", harness: str = "codex") -> list[str]:
    return proxy_cli_args(proxy_command=proxy, guard_home=str(tmp_path / "guard"), server=_server(tmp_path, harness))


@pytest.fixture
def advertised(monkeypatch: pytest.MonkeyPatch) -> set[str]:
    features: set[str] = set()
    monkeypatch.delenv(MCP_RELAY_SELECTION_ENV, raising=False)
    monkeypatch.setattr(
        native_hook_bridge,
        "native_hook_bridge_executable",
        lambda feature: _RUNTIME if feature in features else None,
    )
    return features


def test_feature_and_proxy_names_match_the_native_relay() -> None:
    relay = (_RUNTIME_SRC / "mcp_relay.rs").read_text(encoding="utf-8")
    decide = (_RUNTIME_SRC / "mcp_relay_decide.rs").read_text(encoding="utf-8")
    args = (_RUNTIME_SRC / "mcp_relay_args.rs").read_text(encoding="utf-8")
    assert f'RELAY_COMMAND: &str = "{NATIVE_MCP_RELAY_COMMAND}"' in relay
    assert f'RELAY_FEATURE: &str = "{NATIVE_MCP_RELAY_FEATURE}"' in relay
    assert f'MCP_RELAY_DECIDE_FEATURE: &str = "{NATIVE_MCP_RELAY_DECIDE_FEATURE}"' in decide
    assert set(re.findall(r'\("([a-z]+-mcp-proxy)", "[a-z]+", "[a-z]+", (?:true|false)\)', args)) == set(
        RELAY_PROXY_COMMANDS
    )


def test_an_unadvertised_relay_keeps_the_python_proxy(tmp_path: Path, advertised: set[str]) -> None:
    advertised.add(NATIVE_MCP_RELAY_DECIDE_FEATURE)
    args = _python_args(tmp_path)
    assert mcp_proxy_launch(sys.executable, args) == (sys.executable, args)


@pytest.mark.parametrize("proxy", sorted(RELAY_PROXY_COMMANDS))
def test_an_advertised_relay_wraps_the_unchanged_python_argv(tmp_path: Path, advertised: set[str], proxy: str) -> None:
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    args = _python_args(tmp_path, proxy, proxy.removesuffix("-mcp-proxy"))
    command, launch_args = mcp_proxy_launch("/venv/bin/python", args)
    assert command == str(_RUNTIME)
    assert launch_args == [NATIVE_MCP_RELAY_COMMAND, "/venv/bin/python", *args]
    # The relay finds `guard <proxy>` in its argv exactly as in the Python launch.
    assert launch_args[launch_args.index("guard") + 1] == proxy
    assert python_proxy_launch(command, launch_args) == ("/venv/bin/python", tuple(args))
    assert mcp_proxy_command(["/venv/bin/python", *args]) == [command, *launch_args]
    assert is_guard_proxy_command(command, tuple(launch_args))
    assert proxy_argument_tail(tuple(launch_args), RELAY_PROXY_COMMANDS) == (proxy, tuple(args[4:]))


def test_other_guard_proxies_are_never_relayed(tmp_path: Path, advertised: set[str]) -> None:
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    for proxy in ("mcp-proxy", "hermes-mcp-proxy"):
        args = _python_args(tmp_path, proxy)
        assert mcp_proxy_launch(sys.executable, args) == (sys.executable, args)
    assert mcp_proxy_launch(sys.executable, ["-m", "other.module", "guard", "codex-mcp-proxy"])[0] == sys.executable


def test_python_selection_overrides_an_advertised_relay(
    tmp_path: Path, advertised: set[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    advertised.update({NATIVE_MCP_RELAY_FEATURE, NATIVE_MCP_RELAY_DECIDE_FEATURE})
    monkeypatch.setenv(MCP_RELAY_SELECTION_ENV, "python")
    args = _python_args(tmp_path)
    assert mcp_proxy_launch(sys.executable, args) == (sys.executable, args)


def test_native_canary_needs_a_runtime_serving_relay_decisions(
    tmp_path: Path, advertised: set[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(MCP_RELAY_SELECTION_ENV, "native")
    args = _python_args(tmp_path)
    assert mcp_proxy_launch(sys.executable, args)[0] == sys.executable
    advertised.add(NATIVE_MCP_RELAY_DECIDE_FEATURE)
    assert mcp_proxy_launch(sys.executable, args)[0] == str(_RUNTIME)


def test_frozen_builds_keep_the_python_proxy_and_windows_selects_the_relay(
    tmp_path: Path, advertised: set[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    args = _python_args(tmp_path)
    monkeypatch.setattr(mcp_relay_native.sys, "frozen", True, raising=False)
    assert mcp_proxy_launch(sys.executable, args)[0] == sys.executable
    monkeypatch.delattr(mcp_relay_native.sys, "frozen")
    assert mcp_proxy_launch(sys.executable, args)[0] == str(_RUNTIME)


def test_shared_launcher_entry_selects_the_relay(tmp_path: Path, advertised: set[str]) -> None:
    context = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard")
    python_entry = proxy_launcher_entry(proxy_command="codex-mcp-proxy", context=context, server=_server(tmp_path))
    assert python_entry["command"] == sys.executable
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    native_entry = proxy_launcher_entry(proxy_command="codex-mcp-proxy", context=context, server=_server(tmp_path))
    assert native_entry["command"] == str(_RUNTIME)
    assert native_entry["args"] == [NATIVE_MCP_RELAY_COMMAND, sys.executable, *python_entry["args"]]  # type: ignore[misc]


def test_refresh_moves_entries_between_launchers(tmp_path: Path, advertised: set[str]) -> None:
    args = _python_args(tmp_path, "cursor-mcp-proxy", "cursor")
    stale_native = {"command": "/old/runtime", "args": [NATIVE_MCP_RELAY_COMMAND, "/old/python", *args]}
    refreshed = CursorHarnessAdapter._refresh_guard_proxy_entry(stale_native)
    assert refreshed["command"] == sys.executable
    assert refreshed["args"] == args
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    refreshed = CursorHarnessAdapter._refresh_guard_proxy_entry({"command": "/old/python", "args": args})
    assert refreshed["command"] == str(_RUNTIME)
    assert refreshed["args"] == [NATIVE_MCP_RELAY_COMMAND, sys.executable, *args]


def test_codex_interpreter_refresh_reselects_the_launcher(tmp_path: Path, advertised: set[str]) -> None:
    args = _python_args(tmp_path)
    servers: dict[str, object] = {"fixture": {"command": "/old/python", "args": list(args)}}
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    assert CodexHarnessAdapter._refresh_managed_proxy_interpreters(servers) == ("fixture",)
    entry = servers["fixture"]
    assert isinstance(entry, dict)
    assert entry["command"] == str(_RUNTIME)
    assert entry["args"][:2] == [NATIVE_MCP_RELAY_COMMAND, entry["args"][1]]
    assert entry["args"][2:] == args
    assert CodexHarnessAdapter._refresh_managed_proxy_interpreters(servers) == ()
    advertised.clear()
    assert CodexHarnessAdapter._refresh_managed_proxy_interpreters(servers) == ("fixture",)
    assert entry["args"] == args


@pytest.mark.skipif(sys.platform == "win32", reason="the server identity digest needs the resident runtime")
def test_inventory_recovers_the_original_launch_behind_the_relay(tmp_path: Path) -> None:
    server = replace(_server(tmp_path, "cursor"), config_path=str(tmp_path / "mcp.json"))
    args = proxy_cli_args(proxy_command="cursor-mcp-proxy", guard_home=str(tmp_path / "guard"), server=server)
    artifact = GuardArtifact(
        artifact_id="cursor:fixture",
        name=server.name,
        harness="cursor",
        artifact_type="mcp_server",
        source_scope=server.source_scope,
        config_path=server.config_path,
        command=str(_RUNTIME),
        args=(NATIVE_MCP_RELAY_COMMAND, "/venv/bin/python", *args),
        transport="stdio",
        metadata={"env": {}, "guard_managed_proxy": True},
    )
    detection = HarnessDetection(
        harness="cursor",
        installed=True,
        command_available=False,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
        warnings=(),
    )
    servers = discover_harness_mcp_servers(home_dir=tmp_path, guard_home=tmp_path / "guard", detections=(detection,))
    assert len(servers) == 1
    assert servers[0].launch_command == "python fixture_server.py --stdio"
