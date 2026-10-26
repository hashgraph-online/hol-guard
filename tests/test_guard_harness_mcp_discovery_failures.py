"""Failure isolation and identity collision regressions for MCP host discovery."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore


def test_recognize_cli_id_survives_discovery_failure(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("detect failed")),
    )
    service = LocalCliApiService(store=GuardStore(home))
    try:
        service.recognize({"command": "python3 missing.py", "cli_id": "local-cli.mcp-aaaaaaaa"})
    except LocalCliApiError as exc:
        assert exc.code
    else:
        raise AssertionError("expected recognition to fail closed without crashing")


def test_list_items_survives_discovery_failure(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("detect failed")),
    )
    service = LocalCliApiService(store=GuardStore(home))
    payload = service.list_items()
    assert payload["items"] == []


def test_cli_id_collision_keeps_both_servers(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = UnlistedCliIdentity(
        cli_id="local-cli.mcp-aaaaaaaa",
        name="one",
        kind="executable",
        identity_hash="a" * 64,
        example_label="npx one",
    )
    second = UnlistedCliIdentity(
        cli_id="local-cli.mcp-aaaaaaaa",
        name="two",
        kind="executable",
        identity_hash="b" * 64,
        example_label="npx two",
    )
    first_id = store.ensure_local_mcp_observation(
        first,
        seen_at=utc_now(),
        server_identity_hash="a" * 64,
        server_command="npx",
        server_args_hash="1" * 64,
        source_label="Cursor",
    )
    second_id = store.ensure_local_mcp_observation(
        second,
        seen_at=utc_now(),
        server_identity_hash="b" * 64,
        server_command="uvx",
        server_args_hash="2" * 64,
        source_label="Codex",
    )
    assert first_id == "local-cli.mcp-aaaaaaaa"
    assert second_id != first_id
    assert second_id.startswith("local-cli.mcp-")
    listed = {str(item["name"]): item.get("source_label") for item in store.list_local_cli_items()}
    assert listed == {"one": "Cursor", "two": "Codex"}


def _recording_service(home: Path) -> tuple[LocalCliApiService, list[tuple[str, str | None]]]:
    recorded: list[tuple[str, str | None]] = []

    def record(event: str, *, detail: str | None = None, exc_info: object = None) -> bool:
        # Mirrors `DaemonDiagnostics.record_exception`, whose `exc_info=False`
        # asks for a record with no traceback.
        recorded.append((event, detail))
        return True

    return LocalCliApiService(store=GuardStore(home), record_exception=record), recorded


def test_observed_discovery_failure_reaches_the_daemon_log(tmp_path: Path, monkeypatch) -> None:
    # A Desktop-launched daemon sends stderr to /dev/null, so the failure must
    # reach the daemon.log recorder, naming the exception it raised.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.local_cli_api.Path.home", staticmethod(lambda: home))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_observed_mcp_tools",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("native_local_mcp_observation_invalid")),
    )
    service, recorded = _recording_service(home)
    payload = service.discover_items()
    assert payload.get("discovery_issue") == "observed_provider_scan_failed"
    assert ("local_cli_observed_discovery_failed", "ValueError") in recorded


def test_configured_discovery_failure_reaches_the_daemon_log(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.local_cli_api.Path.home", staticmethod(lambda: home))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("detect failed")),
    )
    service, recorded = _recording_service(home)
    payload = service.discover_items()
    assert payload.get("discovery_issue") == "configured_host_scan_failed"
    # Each failed scan names its cause, never the stage error that wraps it.
    assert recorded
    assert set(recorded) == {("local_cli_configured_discovery_failed", "RuntimeError")}


def test_the_daemon_wires_its_log_recorder_into_discovery(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import GuardDaemonServer

    daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    daemon.start()
    try:
        server = daemon._server
        assert server.local_cli_api._record_exception == server.diagnostics.record_exception
    finally:
        daemon.stop()
