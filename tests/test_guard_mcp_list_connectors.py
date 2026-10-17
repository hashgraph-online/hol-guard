"""``hol-guard mcp list``, status and doctor read the connector store Protect reads."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    discover_remote_mcp_servers,
    persist_discovered_harness_mcp_servers,
    remote_mcp_origin,
)
from codex_plugin_scanner.guard.cli.inventory_list_commands import mcp_list_payload
from codex_plugin_scanner.guard.cli.render_connectors import connector_setup_line
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.connector_setup_items import connector_setup_href, connector_setup_status
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = [pytest.mark.usefixtures("native_hook_force")]

_NOW = "2026-10-17T12:00:00Z"


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    rc = main(["guard", *argv])
    return rc, capsys.readouterr().out


def _observe(store: GuardStore, harness: str, server: str) -> str:
    tool = observed_mcp_tool(harness, f"mcp__{server}__read")
    assert tool is not None
    identity = tool.server_identity
    return store.ensure_local_mcp_observation(
        tool.identity,
        seen_at=_NOW,
        server_identity_hash=identity.identity_hash,
        server_command=identity.command,
        server_args_hash=identity.args_hash,
        source_label="Codex · observed tools",
    )


def _set_state(store: GuardStore, harness: str, server: str, state: str) -> None:
    tool = observed_mcp_tool(harness, f"mcp__{server}__read")
    assert tool is not None
    store.upsert_local_cli_grant(
        identity=tool.identity,
        state=state,
        expected_revision=store.read_local_cli_revision(),
        updated_at=_NOW,
    )


def _remote_detection(harness: str, name: str, url: str) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(
            GuardArtifact(
                artifact_id=f"{harness}:global:mcp_server:{name}",
                name=name,
                harness=harness,
                artifact_type="mcp_server",
                source_scope="global",
                config_path="/home/user/.config/harness.json",
                url=url,
                transport="http",
            ),
        ),
    )


def test_remote_origin_keeps_scheme_host_and_path_only() -> None:
    assert remote_mcp_origin("HTTPS://user:pw@MCP.Example.Test:8443/v1/mcp?key=secret#frag") == (
        "https://mcp.example.test:8443/v1/mcp"
    )
    assert remote_mcp_origin("https://mcp.example.test/mcp") == "https://mcp.example.test/mcp"
    for rejected in ("${MCP_URL}", "file:///tmp/sock", "ftp://mcp.example.test/", "https:///path", ""):
        assert remote_mcp_origin(rejected) is None


def test_remote_origin_masks_path_segments_that_look_like_keys() -> None:
    assert remote_mcp_origin("https://mcp.example.test/api/mcp/s/a1b2c3d4e5/mcp") == (
        "https://mcp.example.test/api/mcp/s/[masked]/mcp"
    )
    assert remote_mcp_origin("https://mcp.example.test/v1/" + "k" * 24) == "https://mcp.example.test/v1/[masked]"
    assert remote_mcp_origin("https://mcp.example.test/2025-06-18/mcp") == "https://mcp.example.test/2025-06-18/mcp"


def test_a_server_name_is_read_as_the_namespace_its_calls_carry(tmp_path: Path) -> None:
    detections = (
        _remote_detection("claude-code", "echo mcp", "https://mcp.example.test/mcp"),
        _remote_detection("codex", "codex_apps", "https://mcp.example.test/apps"),
    )

    remote = discover_remote_mcp_servers(home_dir=tmp_path, guard_home=tmp_path / "home", detections=detections)

    assert [server.tool.namespace for server in remote] == ["mcp__echo_mcp__"]


def test_configured_remote_server_shares_the_record_its_tool_calls_use(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    observed = _observe(store, "codex", "echo-mcp")
    remote = discover_remote_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path / "home",
        detections=(_remote_detection("codex", "echo-mcp", "https://mcp.example.test/mcp?token=abc"),),
    )
    assert len(remote) == 1

    labels = persist_discovered_harness_mcp_servers(store, (), seen_at=_NOW, remote=remote)

    assert list(labels) == [observed]
    items = [item for item in store.list_local_cli_items() if item["surface"] == "mcp"]
    assert len(items) == 1
    assert items[0]["remote_origin"] == "https://mcp.example.test/mcp"
    assert items[0]["declared_sources"] == ["codex:remote"]
    assert items[0]["source_label"] == "Codex · configured server"
    assert "token" not in json.dumps(items)


def test_declared_sources_merge_without_duplicates(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    detection = _remote_detection("codex", "echo-mcp", "https://mcp.example.test/mcp")
    remote = discover_remote_mcp_servers(home_dir=tmp_path, guard_home=tmp_path / "home", detections=(detection,))

    persist_discovered_harness_mcp_servers(store, (), seen_at=_NOW, remote=remote)
    persist_discovered_harness_mcp_servers(store, (), seen_at=_NOW, remote=remote)

    (item,) = [item for item in store.list_local_cli_items() if item["surface"] == "mcp"]
    assert item["declared_sources"] == ["codex:remote"]


def test_mcp_list_groups_connectors_by_what_they_need(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    store = GuardStore(home)
    for server in ("alpha", "bravo", "charlie"):
        _observe(store, "codex", server)
    _set_state(store, "codex", "bravo", "blocked")
    _set_state(store, "codex", "charlie", "allowed")

    rc, out = _run(capsys, "mcp", "list", "--home", str(home), "--json")
    payload = json.loads(out)

    assert rc == 0
    assert payload["kind"] == "mcp"
    assert [(item["name"], item["status"]) for item in payload["items"]] == [
        ("alpha", "needs_setup"),
        ("charlie", "allowed"),
        ("bravo", "blocked"),
    ]
    assert payload["counts"] == {"needs_setup": 1, "allowed": 1, "blocked": 1}
    # No local dashboard is running for this home, so there is no link to print.
    assert payload["protect_url"] is None
    assert all(item["setup_url"] is None for item in payload["items"])

    rc, out = _run(capsys, "mcp", "list", "--home", str(home))
    assert rc == 0
    assert "1 needing setup" in out
    assert "local Guard inventory" not in out
    assert "hol-guard dashboard" in out


def test_mcp_list_matches_the_protect_list(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    _observe(store, "codex", "alpha")
    _observe(store, "claude-code", "bravo")
    _set_state(store, "codex", "alpha", "allowed")

    protect = [
        item["cli_id"]
        for item in LocalCliApiService(store=store)._listed_public_items()
        if item["surface"] == "mcp" and (item["state"] != "unset" or item["suggestable"])
    ]
    listed = [item["cli_id"] for item in mcp_list_payload(store, generated_at=_NOW, dashboard_url=None)["items"]]

    assert sorted(listed) == sorted(protect)
    assert len(listed) == 2


def test_setup_links_point_at_the_protect_page(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    cli_id = _observe(store, "codex", "alpha")

    payload = mcp_list_payload(store, generated_at=_NOW, dashboard_url="http://127.0.0.1:4781/")

    assert payload["protect_url"] == "http://127.0.0.1:4781/extensions"
    assert payload["items"][0]["setup_url"] == f"http://127.0.0.1:4781/extensions/local-cli/{cli_id}"
    assert connector_setup_href(None, cli_id) is None


def test_status_line_counts_connectors_needing_setup(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    _observe(store, "codex", "alpha")
    _observe(store, "codex", "bravo")

    status = connector_setup_status(store, "http://127.0.0.1:4781")

    assert status == {
        "needing_setup": 2,
        "mcp_servers": 2,
        "local_clis": 0,
        "url": "http://127.0.0.1:4781/extensions",
    }
    assert connector_setup_line(status) == (
        "Connectors needing setup: 2 (2 MCP servers, 0 local CLIs) → http://127.0.0.1:4781/extensions"
    )
    assert connector_setup_line({**status, "url": None}).endswith("→ hol-guard dashboard")
    assert connector_setup_line({**status, "needing_setup": 0}) is None
    assert connector_setup_line(None) is None


def test_status_json_carries_the_connector_count(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _observe(GuardStore(home), "codex", "alpha")

    rc, out = _run(capsys, "status", "--home", str(home), "--json")

    assert rc == 0
    assert json.loads(out)["connector_setup"]["mcp_servers"] == 1


def test_mcp_list_shows_markup_in_names_literally(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    store = GuardStore(home)
    cli_id = _observe(store, "codex", "alpha")
    with store._connect() as connection:
        connection.execute("update local_cli_observation set name = ? where cli_id = ?", ("[bold]loud[/bold]", cli_id))

    rc, out = _run(capsys, "mcp", "list", "--home", str(home))

    assert rc == 0
    assert "[bold" in out


def test_mcp_list_json_keeps_the_configs_that_declare_a_server(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    store = GuardStore(home)
    _observe(store, "codex", "echo-mcp")
    detection = _remote_detection("codex", "echo-mcp", "https://mcp.example.test/mcp")
    remote = discover_remote_mcp_servers(home_dir=tmp_path, guard_home=home, detections=(detection,))
    persist_discovered_harness_mcp_servers(store, (), seen_at=_NOW, remote=remote)
    _observe(store, "codex", "echo-mcp")

    rc, out = _run(capsys, "mcp", "list", "--home", str(home), "--json")

    assert rc == 0
    (item,) = json.loads(out)["items"]
    assert item["declared_sources"] == ["codex:remote"]
