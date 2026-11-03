from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    configured_mcp_server_names,
    discover_harness_mcp_servers,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import ObservedMcpTool, discover_observed_mcp_tools
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .observed_mcp_history_rows import seed_observed_mcp_history


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _names(home: Path, tmp_path: Path) -> dict[str, tuple[str, ...]]:
    servers = discover_harness_mcp_servers(home_dir=home, guard_home=tmp_path / "guard")
    grouped: dict[str, list[str]] = {}
    for server in servers:
        grouped.setdefault(server.harness, []).append(server.identity.name)
    return {harness: tuple(sorted(found)) for harness, found in grouped.items()}


def test_oh_my_pi_mcp_json_server_with_dashed_name_is_discovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    _write_json(
        home / ".omp" / "agent" / "mcp.json",
        {"mcpServers": {"truenas-pilot": {"command": "node", "args": ["server.js"]}}},
    )

    assert _names(home, tmp_path).get("omp") == ("truenas-pilot",)


def test_claude_code_user_scope_server_in_dot_claude_json_is_discovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    _write_json(home / ".claude.json", {"mcpServers": {"user-scope-server": {"command": "node", "args": ["a.js"]}}})

    assert _names(home, tmp_path).get("claude-code") == ("user-scope-server",)


def test_configured_server_names_cover_stdio_and_remote_servers_per_harness() -> None:
    def artifact(harness: str, name: str, **kwargs: object) -> GuardArtifact:
        return GuardArtifact(
            artifact_id=f"{harness}:{name}",
            name=name,
            harness=harness,
            artifact_type="mcp_server",
            source_scope="global",
            config_path="mcp.json",
            **kwargs,  # type: ignore[arg-type]
        )

    detection = HarnessDetection(
        harness="omp",
        installed=True,
        command_available=False,
        config_paths=("mcp.json",),
        artifacts=(
            artifact("omp", "truenas-pilot", command="node"),
            artifact("omp", "remote-docs", url="https://example.com/mcp"),
            artifact("omp", "truenas-pilot", command="node"),
        ),
    )

    assert configured_mcp_server_names([detection]) == {"omp": ("truenas-pilot", "remote-docs")}


def test_omp_flattened_name_shares_a_connector_with_its_configured_remote_server(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.harness_mcp_remote import _remote_server

    remote = _remote_server(
        GuardArtifact(
            artifact_id="omp:mcp:truenas-pilot",
            name="truenas-pilot",
            harness="omp",
            artifact_type="mcp_server",
            source_scope="global",
            config_path="mcp.json",
            url="https://pilot.example.com/mcp",
        ),
        "https://pilot.example.com/mcp",
    )
    store = GuardStore(tmp_path / "guard-home")
    seed_observed_mcp_history(
        store, receipts=[{"harness": "omp", "raw_command_text": "tool:mcp__truenas_pilot_status"}]
    )

    (connector,) = store.observed_mcp_discovery(configured_servers={"omp": ["truenas-pilot"]})
    observed = ObservedMcpTool(
        harness=connector["harness"],
        namespace=connector["namespace"],
        name=connector["tools"][0]["name"],
        qualified_name=connector["tools"][0]["qualified_name"],
        server_name=connector["server_name"],
    )

    assert remote is not None
    assert (observed.server_name, observed.name) == ("truenas-pilot", "status")
    assert remote.tool.namespace == observed.namespace
    assert remote.tool.identity.cli_id == observed.identity.cli_id


def test_discovery_lists_omp_connector_when_its_server_is_configured(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    seed_observed_mcp_history(
        store,
        receipts=[
            {"harness": "omp", "raw_command_text": "tool:mcp__truenas_pilot_status"},
            {"harness": "omp", "raw_command_text": "tool:mcp__truenas_pilot_apps"},
        ],
    )

    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:00Z")
    assert store.list_local_cli_items() == []

    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:01Z", configured_servers={"omp": ("truenas-pilot",)})
    items = store.list_local_cli_items()
    assert [item["name"] for item in items] == ["truenas-pilot"]
    catalog = store.read_local_cli_command_catalog(str(items[0]["cli_id"]))
    assert {command.name for command in catalog} == {"status", "apps"}
