from __future__ import annotations

import json
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.daemon.local_cli_api as local_cli_api_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import discover_harness_mcp_servers
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.store import GuardStore


def test_configured_inventory_retains_one_hundred_servers_without_probing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    config_dir = home / ".cursor"
    config_dir.mkdir(parents=True)
    names = {f"server-{index:03d}" for index in range(100)}
    (config_dir / "mcp.json").write_text(
        json.dumps({"mcpServers": {name: {"command": "node", "args": [f"{name}.js"]} for name in names}}),
        encoding="utf-8",
    )
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)
    detection = CursorHarnessAdapter().detect(context)
    assert len(detection.artifacts) == 100
    monkeypatch.setattr(local_cli_api_module.Path, "home", staticmethod(lambda: home))

    def _discover(**_kwargs):
        return discover_harness_mcp_servers(home_dir=home, guard_home=guard_home, detections=(detection,))

    def _unexpected_probe(*_args, **_kwargs):
        pytest.fail("Configured inventory must not launch an MCP probe")

    monkeypatch.setattr(local_cli_api_module, "discover_harness_mcp_servers", _discover)
    monkeypatch.setattr(local_cli_api_module, "probe_stdio_mcp_server", _unexpected_probe)
    service = LocalCliApiService(store=GuardStore(guard_home))
    assert service.list_items()["items"] == []
    service._observe_harness_mcp_servers()
    first = service.list_items()["items"]
    assert isinstance(first, list)
    assert {item["name"] for item in first} == names
    assert len({item["identity_hash"] for item in first}) == 100
    service._observe_harness_mcp_servers()
    restarted = LocalCliApiService(store=GuardStore(guard_home))
    for inventory in (service.list_items()["items"], restarted.list_items()["items"]):
        assert isinstance(inventory, list)
        assert {item["name"] for item in inventory} == names
        assert all(
            item["surface"] == "mcp"
            and item["state"] == "unset"
            and item["source_label"] == "Cursor"
            and item["observed_count"] == 1
            and item["help_status"] is None
            and item["commands"] == []
            for item in inventory
        )
