from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from shutil import which

from codex_plugin_scanner.guard.adapters.harness_mcp_discovery import (
    discover_harness_mcp_servers,
    persist_discovered_harness_mcp_servers,
)
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.daemon.local_cli_http import (
    _RECOGNIZE_SOCKET_TIMEOUT_SECONDS,
    handle_local_cli_post,
)
from codex_plugin_scanner.guard.daemon.local_cli_mcp_store import stored_mcp_recognition
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import probe_search_path
from codex_plugin_scanner.guard.store import GuardStore

_FAKE_NPX_MCP = """#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "real"}},
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "list_pages", "description": "List"}]},
        }), flush=True)
        break
"""


def _shim_first_npx_path(tmp_path: Path, monkeypatch) -> Path:
    shim_dir = tmp_path / "package-shims" / "bin"
    real_dir = tmp_path / "real"
    shim_dir.mkdir(parents=True)
    real_dir.mkdir()
    shim = shim_dir / "npx"
    shim.write_text("#!/bin/sh\nsleep 20\nexit 1\n", encoding="utf-8")
    shim.chmod(0o755)
    real = real_dir / "npx"
    real.write_text(_FAKE_NPX_MCP, encoding="utf-8")
    real.chmod(0o755)
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join((str(shim_dir), str(real_dir), "/usr/bin", "/bin")),
    )
    return real


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


def test_recognize_skips_package_shim_npx(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    real_npx = _shim_first_npx_path(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    service = LocalCliApiService(store=GuardStore(home))
    recognized = service.recognize({"command": "npx -y chrome-devtools-mcp@latest"})
    item = recognized["item"]
    assert isinstance(item, dict)
    assert item["surface"] == "mcp"
    assert item["help_status"] == "ok"
    commands = item["commands"]
    assert isinstance(commands, list)
    assert any(isinstance(entry, dict) and entry.get("name") == "list_pages" for entry in commands)
    assert which("npx", path=probe_search_path()) == str(real_npx)


def test_recognize_retry_lists_tools_after_failed_store(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _shim_first_npx_path(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    detection = _detection(
        "cursor",
        _artifact(
            harness="cursor",
            name="chrome-devtools",
            command="npx",
            args=("-y", "chrome-devtools-mcp@latest"),
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
    service = LocalCliApiService(store=GuardStore(home))
    _ = persist_discovered_harness_mcp_servers(
        service._store,
        discover_harness_mcp_servers(home_dir=home, guard_home=home, detections=(detection,)),
        seen_at=utc_now(),
    )
    listed = service.list_items()["items"][0]
    assert isinstance(listed, dict)
    assert listed["commands"] == []
    recognized = service.recognize(
        {
            "command": str(listed["example_label"]),
            "cli_id": str(listed["cli_id"]),
        }
    )
    item = recognized["item"]
    assert isinstance(item, dict)
    assert item["cli_id"] == listed["cli_id"]
    assert item["help_status"] == "ok"
    commands = item["commands"]
    assert isinstance(commands, list)
    assert any(isinstance(entry, dict) and entry.get("name") == "list_pages" for entry in commands)


def test_handle_local_cli_post_extends_recognize_timeout() -> None:
    class FakeConnection:
        def __init__(self) -> None:
            self.timeout: float | None = None

        def settimeout(self, value: float) -> None:
            self.timeout = value

    class FakeApi:
        def recognize(self, payload: dict[str, object]) -> dict[str, object]:
            return {"ok": True, "command": payload["command"]}

        def apply(self, payload: dict[str, object]) -> dict[str, object]:
            raise AssertionError("apply")

        def discover_items(self) -> dict[str, object]:
            raise AssertionError("discover")

        def preview(self, payload: dict[str, object]) -> dict[str, object]:
            raise AssertionError("preview")

    class FakeHandler:
        def __init__(self) -> None:
            self.connection = FakeConnection()
            self.written: dict[str, object] | None = None
            self.status: int | None = None

        def _daemon_server(self) -> object:
            return type("Daemon", (), {"local_cli_api": FakeApi()})()

        def _write_json(
            self,
            payload: dict[str, object],
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.written = payload
            self.status = status

    handler = FakeHandler()
    handle_local_cli_post(
        handler,
        "/v1/local-clis/recognize",
        {"command": "npx -y chrome-devtools-mcp@latest"},
    )
    assert handler.connection.timeout == _RECOGNIZE_SOCKET_TIMEOUT_SECONDS
    assert handler.status == 200
    assert handler.written == {"ok": True, "command": "npx -y chrome-devtools-mcp@latest"}


def test_handle_local_cli_post_writes_unavailable_without_api() -> None:
    class Handler:
        written: dict[str, object] | None = None
        status: int | None = None

        def _daemon_server(self) -> object:
            return type("Daemon", (), {"local_cli_api": None})()

        def _write_json(
            self,
            payload: dict[str, object],
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.written = payload
            self.status = status

    handler = Handler()
    handle_local_cli_post(handler, "/v1/local-clis/discover", {})
    assert handler.status == 500
    assert handler.written is not None
    assert handler.written["error"] == "local_cli_unavailable"


def test_handle_local_cli_post_maps_api_error() -> None:
    class Api:
        def recognize(self, payload: dict[str, object]) -> dict[str, object]:
            raise LocalCliApiError(400, "missing_package_json", "missing")

        def apply(self, payload: dict[str, object]) -> dict[str, object]:
            raise AssertionError("apply")

        def discover_items(self) -> dict[str, object]:
            raise AssertionError("discover")

        def preview(self, payload: dict[str, object]) -> dict[str, object]:
            raise AssertionError("preview")

    class Handler:
        written: dict[str, object] | None = None
        status: int | None = None

        def _daemon_server(self) -> object:
            return type("Daemon", (), {"local_cli_api": Api()})()

        def _write_json(
            self,
            payload: dict[str, object],
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.written = payload
            self.status = status

    handler = Handler()
    handle_local_cli_post(handler, "/v1/local-clis/recognize", {"command": "npx"})
    assert handler.status == 400
    assert handler.written == {"error": "missing_package_json", "message": "missing"}


def test_handle_local_cli_post_rejects_non_dict_response() -> None:
    class Api:
        def discover_items(self) -> object:
            return ["not-a-dict"]

        def recognize(self, payload: dict[str, object]) -> dict[str, object]:
            raise AssertionError("recognize")

        def apply(self, payload: dict[str, object]) -> dict[str, object]:
            raise AssertionError("apply")

        def preview(self, payload: dict[str, object]) -> dict[str, object]:
            raise AssertionError("preview")

    class Handler:
        written: dict[str, object] | None = None
        status: int | None = None

        def _daemon_server(self) -> object:
            return type("Daemon", (), {"local_cli_api": Api()})()

        def _write_json(
            self,
            payload: dict[str, object],
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.written = payload
            self.status = status

    handler = Handler()
    handle_local_cli_post(handler, "/v1/local-clis/discover", {})
    assert handler.status == 500
    assert handler.written is not None
    assert handler.written["error"] == "local_cli_unavailable"


def test_handle_local_cli_post_ignores_incomplete_handler() -> None:
    handle_local_cli_post(object(), "/v1/local-clis/recognize", {"command": "npx"})
