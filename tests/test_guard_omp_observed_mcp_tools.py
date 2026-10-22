from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    configured_mcp_server_names,
    discover_harness_mcp_servers,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import (
    discover_observed_mcp_tools,
    observed_mcp_tool,
    tools_from_receipts,
)
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401


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


def test_omp_flattened_name_splits_against_configured_server() -> None:
    tool = observed_mcp_tool("omp", "mcp__truenas_pilot_status", ["truenas-pilot"])

    assert tool is not None
    assert (tool.server_name, tool.name) == ("truenas-pilot", "status")
    assert tool.harness == "omp"
    assert tool.namespace == "mcp__truenas-pilot__"
    assert tool.qualified_name == "mcp__truenas_pilot_status"


def test_omp_flattened_name_keeps_underscores_in_the_tool_name() -> None:
    tool = observed_mcp_tool("oh-my-pi", "mcp__truenas_pilot_list_apps", ["truenas-pilot"])

    assert tool is not None
    assert (tool.server_name, tool.name) == ("truenas-pilot", "list_apps")


@pytest.mark.parametrize("configured", [[], ["other-server"], ["pilot"]])
def test_omp_flattened_name_without_matching_server_is_skipped(configured: list[str]) -> None:
    assert observed_mcp_tool("omp", "mcp__truenas_pilot_status", configured) is None
    assert observed_mcp_tool("omp", "mcp__truenas_pilot_status") is None


def test_omp_flattened_name_needs_a_tool_after_the_server() -> None:
    assert observed_mcp_tool("omp", "mcp__truenas_pilot", ["truenas-pilot"]) is None
    assert observed_mcp_tool("omp", "mcp__truenas_pilot_", ["truenas-pilot"]) is None


def test_omp_flattened_name_prefers_the_longest_configured_server() -> None:
    servers = ["truenas", "truenas-pilot"]

    long_match = observed_mcp_tool("omp", "mcp__truenas_pilot_status", servers)
    short_match = observed_mcp_tool("omp", "mcp__truenas_status", servers)

    assert long_match is not None
    assert (long_match.server_name, long_match.name) == ("truenas-pilot", "status")
    assert short_match is not None
    assert (short_match.server_name, short_match.name) == ("truenas", "status")
    assert long_match.namespace != short_match.namespace


def test_omp_double_underscore_name_still_splits_as_before() -> None:
    tool = observed_mcp_tool("omp", "mcp__truenas__status", ["truenas"])

    assert tool is not None
    assert (tool.server_name, tool.name) == ("truenas", "status")
    assert tool.namespace == "mcp__truenas__"


def test_omp_double_underscore_name_is_not_taken_by_a_shorter_configured_server() -> None:
    tool = observed_mcp_tool("omp", "mcp__truenas_pilot__status", ["truenas"])

    assert tool is not None
    assert (tool.server_name, tool.name, tool.namespace) == ("truenas_pilot", "status", "mcp__truenas_pilot__")


def test_omp_server_ending_in_underscore_does_not_capture_double_underscore_names() -> None:
    tool = observed_mcp_tool("omp", "mcp__foo__tool", ["foo_"])

    assert tool is not None
    assert (tool.server_name, tool.namespace) == ("foo", "mcp__foo__")
    assert observed_mcp_tool("omp", "mcp__foo_tool", ["foo_"]) is None


def test_omp_names_that_flatten_alike_belong_to_neither_server() -> None:
    assert observed_mcp_tool("omp", "mcp__foo_bar_tool", ["foo-bar", "foo_bar"]) is None


def test_omp_flattened_name_shares_a_connector_with_its_configured_remote_server() -> None:
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
        )
    )
    observed = observed_mcp_tool("omp", "mcp__truenas_pilot_status", ["truenas-pilot"])

    assert remote is not None and observed is not None
    assert remote.tool.namespace == observed.namespace
    assert remote.tool.identity.cli_id == observed.identity.cli_id


def test_other_harnesses_never_use_configured_servers_to_split() -> None:
    assert observed_mcp_tool("claude-code", "mcp__truenas_pilot_status", ["truenas-pilot"]) is None
    assert observed_mcp_tool("opencode", "mcp__truenas_pilot_status", ["truenas-pilot"]) is None


def test_receipts_split_omp_names_per_harness_and_skip_unconfigured() -> None:
    receipts = [
        {"harness": "omp", "raw_command_text": "tool:mcp__truenas_pilot_status"},
        {"harness": "omp", "raw_command_text": "tool:mcp__stranger_status"},
        {"harness": "claude-code", "raw_command_text": "tool:mcp__truenas_pilot_apps"},
    ]

    tools = tools_from_receipts(receipts, {"omp": ("truenas-pilot",)})

    assert [(tool.harness, tool.server_name, tool.name) for tool in tools] == [("omp", "truenas-pilot", "status")]
    assert tools_from_receipts(receipts) == ()


def test_discovery_lists_omp_connector_when_its_server_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    receipts = [
        {"harness": "omp", "raw_command_text": "tool:mcp__truenas_pilot_status"},
        {"harness": "omp", "raw_command_text": "tool:mcp__truenas_pilot_apps"},
    ]
    monkeypatch.setattr(store, "observed_mcp_history", lambda *, limit: ([], receipts))
    tool = observed_mcp_tool("omp", "mcp__truenas_pilot_status", ["truenas-pilot"])
    assert tool is not None

    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:00Z")
    assert store.list_local_cli_items() == []

    discover_observed_mcp_tools(store, seen_at="2026-01-01T00:00:01Z", configured_servers={"omp": ("truenas-pilot",)})
    assert [item["name"] for item in store.list_local_cli_items()] == ["truenas-pilot"]
    catalog = store.read_local_cli_command_catalog(tool.identity.cli_id)
    assert {command.name for command in catalog} == {"status", "apps"}
