from __future__ import annotations

import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    discover_harness_mcp_servers,
    persist_discovered_harness_mcp_servers,
)
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.daemon.local_cli_mcp_store import stored_mcp_recognition
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


def _artifact(
    *,
    harness: str,
    name: str,
    command: str,
    args: tuple[str, ...],
) -> GuardArtifact:
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
        metadata={},
    )


def _detection(harness: str, *artifacts: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(f"{harness}/mcp.json",),
        artifacts=artifacts,
    )


def test_recognize_keeps_stored_mcp_when_live_probe_fails(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    detection = _detection(
        "cursor",
        _artifact(
            harness="cursor",
            name="filesystem",
            command="npx",
            args=("-y", "@modelcontextprotocol/server-filesystem"),
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
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        lambda *_args, **_kwargs: None,
    )
    service = LocalCliApiService(store=GuardStore(home))
    _ = service._observe_harness_mcp_servers()
    listed = service.list_items()["items"][0]
    assert isinstance(listed, dict)
    recognized = service.recognize(
        {
            "command": str(listed["example_label"]),
            "cli_id": str(listed["cli_id"]),
        }
    )
    item = recognized["item"]
    assert isinstance(item, dict)
    assert item["cli_id"] == listed["cli_id"]
    assert item["name"] == "filesystem"
    assert item["surface"] == "mcp"


def test_recognize_survives_discovery_store_lock(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    detection = _detection(
        "cursor",
        _artifact(
            harness="cursor",
            name="filesystem",
            command="npx",
            args=("-y", "@modelcontextprotocol/server-filesystem"),
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
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.probe_stdio_mcp_server",
        lambda *_args, **_kwargs: None,
    )

    def boom(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.persist_discovered_harness_mcp_servers",
        boom,
    )
    service = LocalCliApiService(store=GuardStore(home))
    _ = persist_discovered_harness_mcp_servers(
        service._store,
        discover_harness_mcp_servers(home_dir=home, guard_home=home, detections=(detection,)),
        seen_at=utc_now(),
    )
    listed = service.list_items()["items"][0]
    assert isinstance(listed, dict)
    recognized = service.recognize(
        {
            "command": str(listed["example_label"]),
            "cli_id": str(listed["cli_id"]),
        }
    )
    item = recognized["item"]
    assert isinstance(item, dict)
    assert item["cli_id"] == listed["cli_id"]
    assert item["surface"] == "mcp"


def test_stored_mcp_recognition_returns_none_on_sqlite_error() -> None:
    class LockedStore:
        def find_local_mcp_observation(self, **_kwargs: object) -> dict[str, object]:
            raise sqlite3.OperationalError("database is locked")

    recognized = stored_mcp_recognition(
        LockedStore(),
        "npx -y chrome-devtools-mcp@latest",
        cli_id="local-cli.mcp-12345678",
        recognize_payload=lambda *_args, **_kwargs: {"item": {}},
        recognize_summary=lambda *_args, **_kwargs: "",
    )
    assert recognized is None
