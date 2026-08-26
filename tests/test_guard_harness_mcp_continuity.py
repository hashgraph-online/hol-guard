from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import discover_harness_mcp_servers
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_FIELD,
    CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
    apply_verified_custom_extension_continuity,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_harness_mcp_discovery import _artifact, _detection


def test_production_list_discovers_ensures_and_matches_mcp_continuity_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    servers = discover_harness_mcp_servers(
        home_dir=tmp_path,
        guard_home=tmp_path,
        detections=(
            _detection(
                "codex",
                _artifact(
                    harness="codex",
                    name="release-mcp",
                    command="uvx",
                    args=("release-mcp-server",),
                ),
            ),
        ),
    )
    assert len(servers) == 1
    service = LocalCliApiService(store=store)
    monkeypatch.setattr(service, "_discovered_servers", lambda: servers)
    _ = service._observe_harness_mcp_servers()
    first_list = service.list_items()
    item = first_list["items"][0]
    assert (item["cli_id"], item["identity_hash"], item["server_identity_hash"], item["surface"]) == (
        servers[0].identity.cli_id,
        servers[0].identity.identity_hash,
        servers[0].server_identity.identity_hash,
        "mcp",
    )
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
    ):
        monkeypatch.setenv(name, "true")
    apply_verified_custom_extension_continuity(
        store,
        {
            "payload": {
                CUSTOM_EXTENSION_CONTINUITY_FIELD: {
                    "schemaVersion": CUSTOM_EXTENSION_CONTINUITY_SCHEMA,
                    "revision": 1,
                    "observedAt": "2026-08-25T15:00:00Z",
                    "expiresAt": "2030-08-25T15:00:00Z",
                    "items": [
                        {
                            "cliId": servers[0].identity.cli_id,
                            "identityHash": servers[0].identity.identity_hash,
                            "settings": {"state": "blocked", "commands": {}},
                        }
                    ],
                }
            }
        },
        now="2026-08-25T16:00:00Z",
    )
    second_list = service.list_items()
    matched = next(entry for entry in second_list["items"] if entry["cli_id"] == item["cli_id"])
    assert (matched["state"], matched["continuity"]["status"]) == ("blocked", "applied")
