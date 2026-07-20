"""OpenClaw MCP inventory precedence and artifact regressions."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.openclaw import OpenClawHarnessAdapter
from codex_plugin_scanner.guard.risk import artifact_risk_signals


def _context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir(parents=True)
    workspace_dir.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)


def _write_config(context: HarnessContext, payload: dict[str, object]) -> None:
    path = context.home_dir / ".openclaw" / "openclaw.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _mcp_artifact(detection, name: str):
    return next(
        artifact for artifact in detection.artifacts if artifact.artifact_type == "mcp_server" and artifact.name == name
    )


def test_openclaw_flags_open_dm_policy_and_remote_mcp(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _write_config(
        context,
        {
            "channels": {"telegram": {"dmPolicy": "open", "allowFrom": ["*"]}},
            "mcp": {"servers": {"remote": {"url": "https://evil.example/mcp"}}},
        },
    )

    detection = OpenClawHarnessAdapter().detect(context)
    channel = next(artifact for artifact in detection.artifacts if artifact.artifact_id == "openclaw:channel:telegram")
    mcp = _mcp_artifact(detection, "remote")

    assert any("network traffic" in signal for signal in artifact_risk_signals(channel))
    assert any("remote server" in signal for signal in artifact_risk_signals(mcp))


def test_openclaw_checks_fallback_mcp_maps_after_disabled_servers(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _write_config(
        context,
        {
            "mcp": {
                "servers": {"disabled": {"enabled": False, "url": "https://disabled.example/mcp"}},
                "mcpServers": {"remote": {"url": "https://remote.example/mcp"}},
            }
        },
    )

    mcp = _mcp_artifact(OpenClawHarnessAdapter().detect(context), "remote")

    assert any("remote server" in signal for signal in artifact_risk_signals(mcp))


def test_openclaw_inventories_unique_servers_from_every_supported_map(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _write_config(
        context,
        {
            "mcp": {
                "servers": {"canonical": {"command": "canonical-server"}},
                "mcpServers": {"nested_compat": {"command": "nested-server"}},
            },
            "mcpServers": {"top_compat": {"url": "https://top.example/mcp"}},
        },
    )

    detection = OpenClawHarnessAdapter().detect(context)
    gateway = next(artifact for artifact in detection.artifacts if artifact.artifact_type == "gateway_config")

    assert gateway.metadata["mcp_server_names"] == ["canonical", "nested_compat", "top_compat"]
    assert gateway.metadata["mcp_server_sources"] == {
        "canonical": "mcp.servers",
        "nested_compat": "mcp.mcpServers",
        "top_compat": "mcpServers",
    }
    assert _mcp_artifact(detection, "canonical").metadata["source_scope"] == "mcp.servers"
    assert _mcp_artifact(detection, "nested_compat").metadata["source_scope"] == "mcp.mcpServers"
    assert _mcp_artifact(detection, "top_compat").metadata["source_scope"] == "mcpServers"


def test_openclaw_preserves_explicit_mcp_transport(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _write_config(
        context,
        {
            "mcp": {
                "servers": {
                    "events": {
                        "url": "https://events.example/sse",
                        "transport": "SSE",
                    }
                }
            }
        },
    )

    events = _mcp_artifact(OpenClawHarnessAdapter().detect(context), "events")

    assert events.transport == "sse"


def test_openclaw_duplicate_active_names_use_canonical_precedence_and_retain_conflicts(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _write_config(
        context,
        {
            "mcp": {
                "servers": {"shared": {"command": "canonical-server", "args": ["--safe"]}},
                "mcpServers": {"shared": {"command": "shadow-server", "args": ["--other"]}},
            },
            "mcpServers": {"shared": {"enabled": False, "command": "disabled-server"}},
        },
    )

    detection = OpenClawHarnessAdapter().detect(context)
    shared = _mcp_artifact(detection, "shared")
    gateway = next(artifact for artifact in detection.artifacts if artifact.artifact_type == "gateway_config")

    assert shared.command == "canonical-server"
    assert shared.args == ("--safe",)
    assert shared.metadata["source_key"] == "mcp.servers.shared"
    assert shared.metadata["definition_count"] == 3
    assert shared.metadata["active_definition_count"] == 2
    assert shared.metadata["conflicting_active_definitions"] is True
    assert [item["source_scope"] for item in shared.metadata["shadowed_definitions"]] == [
        "mcp.mcpServers",
        "mcpServers",
    ]
    assert [item["enabled"] for item in shared.metadata["shadowed_definitions"]] == [True, False]
    assert any(
        warning["reason"] == "conflicting_mcp_server_definitions"
        for warning in gateway.metadata["mcp_inventory_warnings"]
    )


def test_openclaw_disabled_higher_precedence_definition_does_not_hide_active_fallback(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _write_config(
        context,
        {
            "mcp": {
                "servers": {"shared": {"enabled": False, "command": "disabled-canonical"}},
                "mcpServers": {"shared": {"command": "active-fallback"}},
            }
        },
    )

    shared = _mcp_artifact(OpenClawHarnessAdapter().detect(context), "shared")

    assert shared.command == "active-fallback"
    assert shared.metadata["source_scope"] == "mcp.mcpServers"
    assert shared.metadata["definition_count"] == 2
    assert shared.metadata["active_definition_count"] == 1
    assert shared.metadata["shadowed_definitions"][0]["enabled"] is False


def test_openclaw_identical_duplicate_definitions_are_visible_without_false_conflict(tmp_path: Path) -> None:
    context = _context(tmp_path)
    definition = {"command": "same-server", "args": ["--stdio"], "env": {"TOKEN": "secret-one"}}
    _write_config(
        context,
        {"mcp": {"servers": {"shared": definition}}, "mcpServers": {"shared": definition}},
    )

    detection = OpenClawHarnessAdapter().detect(context)
    shared = _mcp_artifact(detection, "shared")
    gateway = next(artifact for artifact in detection.artifacts if artifact.artifact_type == "gateway_config")

    assert shared.metadata["conflicting_active_definitions"] is False
    assert shared.metadata["shadowed_definitions"][0]["same_config_as_effective"] is True
    assert any(
        warning["reason"] == "shadowed_mcp_server_definition" for warning in gateway.metadata["mcp_inventory_warnings"]
    )
    assert "secret-one" not in json.dumps(shared.to_dict(), sort_keys=True)
