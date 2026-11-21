"""Guard recognition of the native MCP stdio relay launch.

Launcher selection (relay versus Python proxy) is decided and tested in the
runtime (``harness_adapter/tests_mcp_launch.rs``); these tests cover the
Python callers that read a relay launch back.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_caller
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.mcp_discovery_client import discover_harness_mcp_servers
from codex_plugin_scanner.guard.mcp_server_client import ManagedMcpServer, is_guard_proxy_command, proxy_cli_args
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from tests import codex_plan_segments as segments

_RUNTIME = Path("/opt/guard/hol-guard-runtime")
_RELAY_COMMAND = "mcp-relay"
_RELAY_FEATURE = "mcp-stdio-relay-v1"
_RELAY_PROXIES = (
    "cline-mcp-proxy",
    "codex-mcp-proxy",
    "copilot-mcp-proxy",
    "cursor-mcp-proxy",
    "hermes-mcp-proxy",
    "opencode-mcp-proxy",
)


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
    # The native side reads the runtime from the caller stamp.
    monkeypatch.setattr(
        native_caller,
        "_native_runtime",
        lambda: {"path": str(_RUNTIME), "size": 0, "sha256": "0" * 64, "features": sorted(features)},
    )
    return features


@pytest.mark.skipif(sys.platform == "win32", reason="proxy recognition needs the resident runtime")
@pytest.mark.parametrize("proxy", _RELAY_PROXIES)
def test_an_advertised_relay_launch_is_recognized_as_a_guard_proxy(tmp_path: Path, proxy: str) -> None:
    args = _python_args(tmp_path, proxy, proxy.removesuffix("-mcp-proxy"))
    assert is_guard_proxy_command(str(_RUNTIME), (_RELAY_COMMAND, "/venv/bin/python", *args))


@pytest.mark.skipif(sys.platform == "win32", reason="the Guard proxy recognition needs the resident runtime")
def test_codex_interpreter_refresh_reselects_the_launcher(tmp_path: Path, advertised: set[str]) -> None:
    args = _python_args(tmp_path)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard-home")

    def refresh(payload: dict[str, object]) -> tuple[dict[str, object], tuple[str, ...]]:
        return segments.render_codex_managed_mcp(context, payload, managed_servers=(), workspace_payload={})

    payload: dict[str, object] = {"mcp_servers": {"fixture": {"command": "/old/python", "args": list(args)}}}
    advertised.add(_RELAY_FEATURE)
    payload, migrated = refresh(payload)
    assert migrated == ("fixture",)
    entry = payload["mcp_servers"]["fixture"]  # type: ignore[index]
    assert isinstance(entry, dict)
    assert entry["command"] == str(_RUNTIME)
    assert entry["args"][:2] == [_RELAY_COMMAND, entry["args"][1]]
    assert entry["args"][2:] == args
    payload, migrated = refresh(payload)
    assert migrated == ()
    advertised.clear()
    payload, migrated = refresh(payload)
    assert migrated == ("fixture",)
    assert payload["mcp_servers"]["fixture"]["args"] == args  # type: ignore[index]


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
        args=(_RELAY_COMMAND, "/venv/bin/python", *args),
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


def test_a_frozen_cli_runs_the_module_argv_the_relay_hands_back(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner import cli

    module_argv = ["-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy", "--guard-home", "g"]
    assert cli._frozen_module_argv(module_argv) == module_argv  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    assert cli._frozen_module_argv(module_argv) == module_argv[2:]  # pyright: ignore[reportPrivateUsage]
    assert cli._frozen_module_argv(["-m", "pip"]) == ["-m", "pip"]  # pyright: ignore[reportPrivateUsage]
