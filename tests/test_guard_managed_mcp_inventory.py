from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_mcp import detect_cline_mcp, install_cline_mcp_proxies
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import discover_harness_mcp_servers
from codex_plugin_scanner.guard.adapters.mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,
    managed_stdio_servers,
    proxy_cli_args,
)
from codex_plugin_scanner.guard.adapters.opencode_artifacts import append_config_artifacts
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def _wrapped(tmp_path: Path, *, native: bool, layers: int = 1, account: str = "one") -> GuardArtifact:
    server = ManagedMcpServer(
        harness="cursor",
        name="fixture",
        source_scope="user",
        config_path=str(tmp_path / "mcp.json"),
        command="python",
        args=("fixture_server.py", "--stdio"),
        transport="stdio",
        env={"FIXTURE_ACCOUNT": account},
        enabled=True,
    )
    for _ in range(layers):
        args = proxy_cli_args(proxy_command="cursor-mcp-proxy", guard_home=str(tmp_path / "guard"), server=server)
        server = replace(server, command="hol-guard" if native else "python", args=tuple(args))
    return GuardArtifact(
        artifact_id="cursor:fixture",
        name=server.name,
        harness=server.harness,
        artifact_type="mcp_server",
        source_scope=server.source_scope,
        config_path=server.config_path,
        command=server.command,
        args=server.args,
        transport="stdio",
        metadata={"env": {**server.env, "HOL_GUARD_DESKTOP": "1"}, "guard_managed_proxy": True},
    )


def _detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness="cursor",
        installed=True,
        command_available=False,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
        warnings=(),
    )


def test_frozen_launcher_recognizes_generated_python_module_proxy() -> None:
    assert is_guard_proxy_command("hol-guard", ("-m", "codex_plugin_scanner.cli", "guard", "cursor-mcp-proxy"))


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("layers", [1, 2, 4])
def test_proxy_inventory_recovers_original_launch_without_rewrapping(tmp_path: Path, native: bool, layers: int) -> None:
    artifact = _wrapped(tmp_path, native=native, layers=layers)
    detection = _detection(artifact)
    assert managed_stdio_servers(detection) == ()
    servers = discover_harness_mcp_servers(home_dir=tmp_path, guard_home=tmp_path / "guard", detections=(detection,))
    assert len(servers) == 1
    assert servers[0].server_identity.command == "python"
    assert servers[0].launch_command == "python fixture_server.py --stdio"
    assert dict(servers[0].env) == {"FIXTURE_ACCOUNT": "one"}
    original = replace(
        artifact,
        command="python",
        args=("fixture_server.py", "--stdio"),
        metadata={"env": {"FIXTURE_ACCOUNT": "one"}},
    )
    before = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        detections=(_detection(original),),
    )
    assert servers[0].identity.identity_hash == before[0].identity.identity_hash


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--server-name", "different"),
        ("--source-scope", "workspace"),
        ("--config-path", "different.json"),
        ("--server-id", "mcp_server:unrelated"),
    ],
)
def test_proxy_inventory_rejects_mismatched_connection_context(tmp_path: Path, flag: str, value: str) -> None:
    artifact = _wrapped(tmp_path, native=True)
    args = list(artifact.args)
    args[args.index(flag) + 1] = value
    artifact = replace(artifact, args=tuple(args))
    assert (
        discover_harness_mcp_servers(
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            detections=(_detection(artifact),),
        )
        == ()
    )


def test_proxy_inventory_rejects_ambiguous_duplicate_upstream(tmp_path: Path) -> None:
    artifact = _wrapped(tmp_path, native=True)
    artifact = replace(artifact, args=(*artifact.args, "--command", "different"))
    assert (
        discover_harness_mcp_servers(
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            detections=(_detection(artifact),),
        )
        == ()
    )


def test_proxy_inventory_declines_excessive_nesting(tmp_path: Path) -> None:
    artifact = _wrapped(tmp_path, native=True, layers=5)
    assert (
        discover_harness_mcp_servers(
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            detections=(_detection(artifact),),
        )
        == ()
    )


def test_cursor_config_discovery_recovers_frozen_proxy(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = home / ".cursor/mcp.json"
    config.parent.mkdir(parents=True)
    # Bind every generated layer to the real adapter config path.
    server = ManagedMcpServer(
        harness="cursor",
        name="fixture",
        source_scope="global",
        config_path=str(config),
        command="python",
        args=("fixture_server.py", "--stdio"),
        transport="stdio",
        env={"FIXTURE_ACCOUNT": "one"},
        enabled=True,
    )
    for _ in range(2):
        args = proxy_cli_args(proxy_command="cursor-mcp-proxy", guard_home=str(tmp_path / "guard"), server=server)
        server = replace(server, command="hol-guard", args=tuple(args))
    config.write_text(
        json.dumps({"mcpServers": {"fixture": {"command": server.command, "args": server.args, "env": server.env}}})
    )
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard")
    detection = CursorHarnessAdapter().detect(context)
    assert managed_stdio_servers(detection) == ()
    servers = discover_harness_mcp_servers(home_dir=home, guard_home=context.guard_home, detections=(detection,))
    assert len(servers) == 1 and servers[0].launch_command == "python fixture_server.py --stdio"


def test_proxy_inventory_keeps_distinct_accounts_separate(tmp_path: Path) -> None:
    servers = [
        discover_harness_mcp_servers(
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            detections=(_detection(_wrapped(tmp_path, native=True, layers=2, account=account)),),
        )[0]
        for account in ("one", "two")
    ]
    assert servers[0].identity.identity_hash != servers[1].identity.identity_hash
    assert dict(servers[0].env) == {"FIXTURE_ACCOUNT": "one"}
    assert dict(servers[1].env) == {"FIXTURE_ACCOUNT": "two"}


@pytest.mark.parametrize(
    "suffix",
    [
        ("--unknown", "value"),
        ("--home", "--arg=x"),
        ("--workspace", "--arg=x"),
        ("--command",),
        ("--arg=bad\x00value",),
        ("--server-env-key=missing",),
        ("--server-env-key=FIXTURE_ACCOUNT",),
        ("--server-env-key=invalid=key",),
        ("--arg=\ud800",),
        tuple("--arg=x" for _ in range(513)),
        ("--arg=" + "x" * 262_144,),
    ],
)
def test_proxy_inventory_declines_invalid_launches(tmp_path: Path, suffix: tuple[str, ...]) -> None:
    artifact = _wrapped(tmp_path, native=True)
    artifact = replace(artifact, args=(*artifact.args, *suffix))
    assert (
        discover_harness_mcp_servers(
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            detections=(_detection(artifact),),
        )
        == ()
    )


def test_proxy_inventory_declines_wrong_host(tmp_path: Path) -> None:
    artifact = replace(_wrapped(tmp_path, native=True), harness="codex")
    assert (
        discover_harness_mcp_servers(
            home_dir=tmp_path,
            guard_home=tmp_path / "guard",
            detections=(_detection(artifact),),
        )
        == ()
    )


def test_cursor_reinstall_refreshes_launcher_without_adding_proxy_layers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    config = home / ".cursor/mcp.json"
    config.parent.mkdir(parents=True)
    server = ManagedMcpServer(
        harness="cursor",
        name="fixture",
        source_scope="global",
        config_path=str(config),
        command="python",
        args=("fixture_server.py", "--stdio"),
        transport="stdio",
        env={"FIXTURE_ACCOUNT": "one"},
        enabled=True,
    )
    args = proxy_cli_args(proxy_command="cursor-mcp-proxy", guard_home=str(tmp_path / "guard"), server=server)
    config.write_text(
        json.dumps({"mcpServers": {"fixture": {"command": "hol-guard", "args": args, "env": server.env}}})
    )
    # Hook installation is independent of the MCP JSON update under test.
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor.install_cursor_hooks", lambda context: {})
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard")
    for _ in range(2):
        CursorHarnessAdapter().install(context)
        entry = json.loads(config.read_text())["mcpServers"]["fixture"]
        assert entry["command"] == sys.executable
        assert entry["args"] == args
        assert entry["env"] == server.env
    servers = discover_harness_mcp_servers(
        home_dir=home,
        guard_home=context.guard_home,
        detections=(CursorHarnessAdapter().detect(context),),
    )
    assert len(servers) == 1 and servers[0].launch_command == "python fixture_server.py --stdio"


@pytest.mark.parametrize(
    "blocked", ["PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONBREAKPOINT", "__PYVENV_LAUNCHER__"]
)
def test_cursor_install_inventory_keeps_only_effective_server_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocked: str,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    config = context.home_dir / ".cursor/mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {
                        "command": "python",
                        "args": ["fixture_server.py", "--stdio"],
                        "env": {blocked: "untrusted", "FIXTURE_ACCOUNT": "one"},
                    }
                }
            }
        )
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor.install_cursor_hooks", lambda context: {})
    CursorHarnessAdapter().install(context)
    installed = json.loads(config.read_text())["mcpServers"]["fixture"]
    assert f"--server-env-key={blocked}" not in installed["args"]
    servers = discover_harness_mcp_servers(
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        detections=(CursorHarnessAdapter().detect(context),),
    )
    assert len(servers) == 1 and dict(servers[0].env) == {"FIXTURE_ACCOUNT": "one"}
    # Earlier installations advertised blocked keys even though their values
    # were deliberately omitted. Recover that effective launch too.
    installed["args"].append(f"--server-env-key={blocked}")
    config.write_text(json.dumps({"mcpServers": {"fixture": installed}}))
    legacy = discover_harness_mcp_servers(
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        detections=(CursorHarnessAdapter().detect(context),),
    )
    assert len(legacy) == 1 and legacy[0].identity.identity_hash == servers[0].identity.identity_hash


def test_cursor_global_copy_recovers_saved_workspace_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home", workspace_dir=tmp_path / "workspace", guard_home=tmp_path / "guard"
    )
    assert context.workspace_dir is not None
    project_config = context.workspace_dir / ".cursor/mcp.json"
    project_config.parent.mkdir(parents=True)
    project_config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {
                        "command": "python",
                        "args": ["fixture_server.py", "--stdio"],
                        "env": {"FIXTURE_ACCOUNT": "one"},
                    }
                }
            }
        )
    )
    before = discover_harness_mcp_servers(
        home_dir=context.home_dir,
        workspace_dir=context.workspace_dir,
        guard_home=context.guard_home,
        detections=(CursorHarnessAdapter().detect(context),),
    )
    assert len(before) == 1
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor.install_cursor_hooks", lambda context: {})
    CursorHarnessAdapter().install(context)
    global_context = replace(context, workspace_dir=None)
    # Simulate the state format written by earlier published installations.
    state_path = CursorHarnessAdapter._state_path(context.home_dir / ".cursor/mcp.json", context)
    state = json.loads(state_path.read_text())
    state.pop("managed_origins")
    state_path.write_text(json.dumps(state))
    CursorHarnessAdapter().install(global_context)
    assert json.loads(state_path.read_text())["managed_origins"]["fixture"] == ["project", str(project_config)]
    CursorHarnessAdapter().install(global_context)
    after = discover_harness_mcp_servers(
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        detections=(CursorHarnessAdapter().detect(global_context),),
    )
    assert len(after) == 1
    assert after[0].identity.identity_hash == before[0].identity.identity_hash
    # A copied proxy cannot claim a different workspace origin.
    assert (
        discover_harness_mcp_servers(
            home_dir=context.home_dir,
            guard_home=tmp_path / "other-guard",
            detections=(CursorHarnessAdapter().detect(replace(global_context, guard_home=tmp_path / "other-guard")),),
        )
        == ()
    )
    global_config = context.home_dir / ".cursor/mcp.json"
    payload = json.loads(global_config.read_text())
    args = payload["mcpServers"]["fixture"]["args"]
    args[args.index("--config-path") + 1] = str(tmp_path / "other/.cursor/mcp.json")
    global_config.write_text(json.dumps(payload))
    assert (
        discover_harness_mcp_servers(
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            detections=(CursorHarnessAdapter().detect(global_context),),
        )
        == ()
    )


def test_cline_installed_inventory_uses_private_launch_values(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    config = context.home_dir / ".cline/data/settings/cline_mcp_settings.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {
                        "command": "python",
                        "args": ["fixture_server.py", "--token=secret-token-value"],
                        "env": {"TOKEN": "secret-env-value"},
                    }
                }
            }
        )
    )
    before = discover_harness_mcp_servers(
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        detections=(detect_cline_mcp(context),),
    )
    install_cline_mcp_proxies(context)
    detection = detect_cline_mcp(context)
    serialized = json.dumps([artifact.to_dict() for artifact in detection.artifacts])
    for secret in ("secret-token-value", "secret-env-value"):
        assert secret not in serialized and secret not in repr(detection)
    after = discover_harness_mcp_servers(
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        detections=(detection,),
    )
    assert len(before) == len(after) == 1
    assert after[0].identity.identity_hash == before[0].identity.identity_hash
    assert dict(after[0].env) == {"TOKEN": "secret-env-value"}


def test_opencode_installed_inventory_normalizes_padded_env_keys(tmp_path: Path) -> None:
    server = ManagedMcpServer(
        harness="opencode",
        name="fixture",
        source_scope="global",
        config_path=str(tmp_path / "opencode.json"),
        command="python",
        args=("fixture_server.py",),
        transport="local",
        env={" TOKEN ": "secret-env-value"},
        enabled=True,
    )
    args = proxy_cli_args(proxy_command="opencode-mcp-proxy", guard_home=str(tmp_path / "guard"), server=server)
    artifacts: list[GuardArtifact] = []
    append_config_artifacts(
        artifacts=artifacts,
        seen_artifact_ids=set(),
        scope="global",
        config_path=Path(server.config_path),
        payload={"mcp": {"fixture": {"type": "local", "command": ["hol-guard", *args], "environment": server.env}}},
    )
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        detections=(_detection(artifacts[0]),),
    )
    assert len(servers) == 1 and dict(servers[0].env) == {"TOKEN": "secret-env-value"}
