"""Installer selection of the native MCP stdio relay versus the Python proxy."""

from __future__ import annotations

import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import hermes as hermes_adapter
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
from codex_plugin_scanner.guard.stable_guard_cli import guard_cli_launcher

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
        lambda feature, *, guard_home=None: _RUNTIME if feature in features else None,
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
    args = _python_args(tmp_path, "mcp-proxy")
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


def test_the_relay_is_resolved_for_the_proxys_guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(MCP_RELAY_SELECTION_ENV, raising=False)
    homes: list[Path | None] = []

    def executable(feature: str, *, guard_home: Path | None = None) -> Path | None:
        homes.append(guard_home)
        return _RUNTIME

    monkeypatch.setattr(native_hook_bridge, "native_hook_bridge_executable", executable)
    args = _python_args(tmp_path)
    assert mcp_proxy_launch(sys.executable, args)[0] == str(_RUNTIME)
    inline = [*args[:4], f"--guard-home={tmp_path / 'other'}", *args[4:], "--guard-home", str(tmp_path / "last")]
    assert mcp_proxy_launch(sys.executable, inline)[0] == str(_RUNTIME)
    assert homes == [tmp_path / "guard", tmp_path / "last"]


def test_a_frozen_build_launches_the_durable_runtime_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime, native_runtime_durable

    monkeypatch.delenv(MCP_RELAY_SELECTION_ENV, raising=False)
    monkeypatch.setattr(native_hook_bridge.sys, "frozen", True, raising=False)
    identity = type("Identity", (), {"path": _RUNTIME})()
    capabilities = type("Capabilities", (), {"features": frozenset({NATIVE_MCP_RELAY_FEATURE})})()
    status = type(
        "Status", (), {"available": True, "compatible": True, "identity": identity, "capabilities": capabilities}
    )()
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_: status)
    durable = tmp_path / "guard" / "native-runtime" / "copy" / "hol-guard-runtime"
    published: list[Path] = []

    def durable_hook_runtime(_identity: object, guard_home: Path) -> Path:
        published.append(guard_home)
        return durable

    monkeypatch.setattr(native_runtime_durable, "durable_hook_runtime", durable_hook_runtime)
    args = _python_args(tmp_path)
    assert mcp_proxy_launch(sys.executable, args) == (
        str(durable),
        [NATIVE_MCP_RELAY_COMMAND, sys.executable, *args],
    )
    assert published == [tmp_path / "guard"]
    without_home = [value for value in args if value not in {"--guard-home", str(tmp_path / "guard")}]
    assert mcp_proxy_launch(sys.executable, without_home)[0] == sys.executable


def test_shared_launcher_entry_selects_the_relay(tmp_path: Path, advertised: set[str]) -> None:
    context = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard")
    python_entry = proxy_launcher_entry(proxy_command="codex-mcp-proxy", context=context, server=_server(tmp_path))
    assert python_entry["command"] == sys.executable
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    native_entry = proxy_launcher_entry(proxy_command="codex-mcp-proxy", context=context, server=_server(tmp_path))
    assert native_entry["command"] == str(_RUNTIME)
    assert native_entry["args"] == [NATIVE_MCP_RELAY_COMMAND, sys.executable, *python_entry["args"]]  # type: ignore[misc]


def _hermes_sources() -> dict[str, dict[str, object]]:
    return {
        "yaml:demo": {
            "name": "demo",
            "command": "python",
            "args": ["-m", "demo"],
            "env": {"DEMO_TOKEN": "secret"},
            "config_path": "/hermes/config.yaml",
        },
        "yaml:remote": {"name": "remote", "url": "https://example.test/mcp", "config_path": "/hermes/config.yaml"},
        "yaml:bare": {"name": "bare", "config_path": "/hermes/config.yaml"},
    }


def _hermes_overlay(tmp_path: Path) -> dict[str, dict[str, object]]:
    context = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard")
    return hermes_adapter._overlay_servers(context=context, source_configs=_hermes_sources())


def test_hermes_stdio_servers_launch_the_python_proxy_without_an_advertised_relay(
    tmp_path: Path, advertised: set[str]
) -> None:
    entry = _hermes_overlay(tmp_path)["demo"]
    assert entry["command"] == sys.executable
    args = entry["args"]
    assert isinstance(args, list)
    assert args[args.index("guard") + 1] == "hermes-mcp-proxy"
    assert args[args.index("--command") + 1] == "python"
    assert "--arg=-m" in args
    assert "--arg=demo" in args
    assert "--server-env-key=DEMO_TOKEN" in args
    assert not any("secret" in str(value) for value in args)


def test_hermes_stdio_servers_launch_through_the_native_relay_when_advertised(
    tmp_path: Path, advertised: set[str]
) -> None:
    python_entry = _hermes_overlay(tmp_path)["demo"]
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    entry = _hermes_overlay(tmp_path)["demo"]
    assert entry["command"] == str(_RUNTIME)
    args = entry["args"]
    assert isinstance(args, list)
    assert args[:2] == [NATIVE_MCP_RELAY_COMMAND, sys.executable]
    assert args[2:] == python_entry["args"]
    assert entry["metadata"] == python_entry["metadata"]


def test_hermes_remote_and_bare_servers_keep_the_manifest_resolved_proxy(tmp_path: Path, advertised: set[str]) -> None:
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    overlay = _hermes_overlay(tmp_path)
    for name, key, transport in (("remote", "yaml:remote", "remote"), ("bare", "yaml:bare", "stdio")):
        entry = overlay[name]
        assert entry["command"] == str(Path(guard_cli_launcher()))
        args = entry["args"]
        assert isinstance(args, list)
        assert args[args.index("hermes") + 1] == "mcp-proxy"
        assert args[-3:] == ["--server", key, "--stdio"]
        assert "hermes-mcp-proxy" not in args
        assert entry["metadata"]["guard_transport"] == transport  # type: ignore[index]


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


def test_a_frozen_opencode_argv_relays_in_module_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advertised: set[str]
) -> None:
    advertised.add(NATIVE_MCP_RELAY_FEATURE)
    module_args = _python_args(tmp_path, "opencode-mcp-proxy", "opencode")
    frozen_args = module_args[3:]
    launcher = str(tmp_path / "hol-guard")
    assert mcp_proxy_launch(launcher, frozen_args) == (launcher, frozen_args)

    monkeypatch.setattr(mcp_relay_native.sys, "frozen", True, raising=False)
    relayed = mcp_proxy_launch(launcher, frozen_args)
    assert relayed == (str(_RUNTIME), [NATIVE_MCP_RELAY_COMMAND, launcher, *module_args])
    assert python_proxy_launch(*relayed) == (launcher, tuple(module_args))
    assert mcp_proxy_launch(launcher, ["scan", "--guard-home", "x"]) == (launcher, ["scan", "--guard-home", "x"])


def test_a_frozen_cli_runs_the_module_argv_the_relay_hands_back(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner import cli

    module_argv = ["-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy", "--guard-home", "g"]
    assert cli._frozen_module_argv(module_argv) == module_argv  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    assert cli._frozen_module_argv(module_argv) == module_argv[2:]  # pyright: ignore[reportPrivateUsage]
    assert cli._frozen_module_argv(["-m", "pip"]) == ["-m", "pip"]  # pyright: ignore[reportPrivateUsage]
