from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    discover_harness_mcp_servers,
    extra_env_for_mcp_launch,
)
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.local_cli_commands import OTHER_COMMAND_ID, LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_probe import McpProbeResult, probe_stdio_mcp_server
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import probe_env
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore


def _artifact(
    *,
    harness: str,
    name: str,
    command: str,
    args: tuple[str, ...],
    env: dict[str, str] | None = None,
) -> GuardArtifact:
    metadata: dict[str, object] = {}
    if env is not None:
        metadata["env"] = env
    return GuardArtifact(
        artifact_id=f"{harness}:mcp:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope="user",
        config_path=f"{harness}/mcp.json",
        command=command,
        args=args,
        transport="stdio",
        metadata=metadata,
    )


def _detection(harness: str, *artifacts: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(f"{harness}/mcp.json",),
        artifacts=artifacts,
    )


def _require_env_server(tmp_path: Path) -> Path:
    server = tmp_path / "require-env-mcp.py"
    server.write_text(
        """
import json
import os
import sys

if not os.environ.get("Z_AI_API_KEY"):
    sys.exit(1)
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "require-env", "version": "0"},
            },
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "ui_to_artifact", "description": "Convert UI"}]}
        }), flush=True)
""",
        encoding="utf-8",
    )
    return server


def test_probe_env_merges_harness_values_without_replacing_path(tmp_path: Path) -> None:
    env = probe_env(
        str(tmp_path),
        {
            "Z_AI_API_KEY": "probe-key",
            "PATH": "evil-path",
            "HOME": "evil-home",
            "BAD=NAME": "x",
            "NULL": "a\x00b",
        },
    )
    assert env["Z_AI_API_KEY"] == "probe-key"
    assert env["PATH"] != "evil-path"
    assert env["HOME"] == str(tmp_path)
    assert "BAD=NAME" not in env
    assert "NULL" not in env


def test_probe_lists_tools_when_harness_env_is_supplied(tmp_path: Path) -> None:
    server = _require_env_server(tmp_path)
    command = f"python3 {server}"
    missing = probe_stdio_mcp_server(command, cwd=tmp_path, home_dir=tmp_path)
    assert missing is None
    probed = probe_stdio_mcp_server(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extra_env={"Z_AI_API_KEY": "probe-key"},
    )
    assert probed is not None
    assert probed.status == "ok"
    assert any(tool.name == "ui_to_artifact" for tool in probed.tools)


def test_discover_keeps_harness_env_for_listing(tmp_path: Path, monkeypatch) -> None:
    detections = (
        _detection(
            "opencode",
            _artifact(
                harness="opencode",
                name="zai-mcp-server",
                command="npx",
                args=("-y", "@z_ai/mcp-server"),
                env={"Z_AI_API_KEY": "config-key", "Z_AI_MODE": "ZAI"},
            ),
        ),
    )
    discovered = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path,
        detections=detections,
    )
    assert len(discovered) == 1
    extra = extra_env_for_mcp_launch(discovered, command="npx -y @z_ai/mcp-server")
    assert extra["Z_AI_API_KEY"] == "config-key"
    assert extra["Z_AI_MODE"] == "ZAI"
    quoted = extra_env_for_mcp_launch(discovered, command="npx -y '@z_ai/mcp-server'")
    assert quoted["Z_AI_API_KEY"] == "config-key"


def test_conflicting_harness_env_is_not_forwarded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("Z_AI_API_KEY", raising=False)
    detections = (
        _detection(
            "opencode",
            _artifact(
                harness="opencode",
                name="zai-mcp-server",
                command="npx",
                args=("-y", "@z_ai/mcp-server"),
                env={"Z_AI_API_KEY": "opencode-secret"},
            ),
        ),
        _detection(
            "codex",
            _artifact(
                harness="codex",
                name="zai-mcp-server",
                command="npx",
                args=("-y", "@z_ai/mcp-server"),
                env={"Z_AI_API_KEY": "codex-secret"},
            ),
        ),
    )
    discovered = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path,
        detections=detections,
    )
    extra = extra_env_for_mcp_launch(discovered, command="npx -y @z_ai/mcp-server")
    assert extra.get("Z_AI_API_KEY") not in {"opencode-secret", "codex-secret"}


def test_unresolved_harness_env_falls_back_to_process(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("Z_AI_API_KEY", "process-key")
    detections = (
        _detection(
            "opencode",
            _artifact(
                harness="opencode",
                name="zai-mcp-server",
                command="npx",
                args=("-y", "@z_ai/mcp-server"),
                env={"Z_AI_API_KEY": "${Z_AI_API_KEY}"},
            ),
        ),
    )
    discovered = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path,
        detections=detections,
    )
    extra = extra_env_for_mcp_launch(discovered, command=discovered[0].launch_command)
    assert extra["Z_AI_API_KEY"] == "process-key"


def test_recognize_forwards_harness_env_to_probe(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    detection = _detection(
        "opencode",
        _artifact(
            harness="opencode",
            name="zai-mcp-server",
            command="npx",
            args=("-y", "@z_ai/mcp-server"),
            env={"Z_AI_API_KEY": "config-key"},
        ),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: discover_harness_mcp_servers(
            home_dir=home,
            guard_home=home,
            detections=(detection,),
        ),
    )
    captured: dict[str, object] = {}

    def _probe(command: str, **kwargs):
        captured["extra_env"] = kwargs.get("extra_env")
        identity = build_mcp_server_identity(
            config_path="",
            command="npx",
            args=("-y", "@z_ai/mcp-server"),
            transport="stdio",
            env={"Z_AI_API_KEY": "config-key"},
        )
        return McpProbeResult(
            identity=UnlistedCliIdentity(
                cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
                name="zai-mcp-server",
                kind="executable",
                identity_hash=identity.identity_hash,
                example_label="npx -y @z_ai/mcp-server",
            ),
            server_identity=identity,
            tools=(
                LocalCliCommand("ui_to_artifact", "ui_to_artifact", "ui_to_artifact", "Convert UI"),
                LocalCliCommand(OTHER_COMMAND_ID, "Other tools", "zai-mcp-server …", "other"),
            ),
            status="ok",
            argv=("npx", "-y", "@z_ai/mcp-server"),
        )

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        _probe,
    )
    service = LocalCliApiService(store=GuardStore(home))
    recognized = service.recognize({"command": "npx -y @z_ai/mcp-server"})
    extra = captured.get("extra_env")
    assert isinstance(extra, dict)
    assert extra.get("Z_AI_API_KEY") == "config-key"
    item = recognized["item"]
    assert isinstance(item, dict)
    assert recognized["help_status"] == "ok"
    assert item["name"] == "zai-mcp-server"
