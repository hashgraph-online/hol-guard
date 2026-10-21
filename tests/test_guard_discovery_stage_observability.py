"""A failed connector scan must leave a record, and one bad harness must not hide the rest.

The Extensions page answered a failed host scan with one generic banner while
``daemon.log`` held nothing at all, so a support bundle could not say which of
the configured-connections stages aborted. These tests pin the record, the
sanitation of its detail line, and the isolation that keeps one unreadable
harness from emptying every other harness's connections.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters import harness_mcp_discovery
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer
from codex_plugin_scanner.guard.daemon import background_diagnostics
from codex_plugin_scanner.guard.daemon.local_cli_api import (
    DISCOVERY_STAGE_FAILED_EVENT,
    LocalCliApiService,
)
from codex_plugin_scanner.guard.daemon.mcp_discovery_jobs import (
    DISCOVERY_JOB_FAILED_EVENT,
    DiscoveryStageError,
    McpDiscoveryJobs,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def recorded():
    """Collect background diagnostics for one test and release the sink after."""

    events: list[tuple[str, str]] = []

    def sink(event: str, detail: str) -> None:
        events.append((event, detail))

    background_diagnostics.install_sink(sink)
    try:
        yield events
    finally:
        background_diagnostics.release_sink(sink)


def _service(tmp_path: Path, monkeypatch) -> LocalCliApiService:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.Path.home",
        staticmethod(lambda: home),
    )
    return LocalCliApiService(store=GuardStore(home))


def test_strict_host_scan_failure_is_recorded(tmp_path: Path, monkeypatch, recorded) -> None:
    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.configured_harness_detections",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("unreadable config")),
    )

    with pytest.raises(DiscoveryStageError) as caught:
        service._observe_harness_mcp_servers(strict=True, fresh=True)

    assert caught.value.code == "configured_host_scan_failed"
    stage_events = [detail for event, detail in recorded if event == DISCOVERY_STAGE_FAILED_EVENT]
    assert stage_events, "a strict host scan failure must leave a record"
    assert "stage=configured_host_scan_failed" in stage_events[0]
    assert "error=ValueError" in stage_events[0]


def test_recorded_detail_keeps_paths_out_of_the_log(tmp_path: Path, monkeypatch, recorded) -> None:
    service = _service(tmp_path, monkeypatch)
    secret_path = "/Users/someone/.cursor/mcp.json"
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.configured_harness_detections",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(13, "Permission denied", secret_path)),
    )

    with pytest.raises(DiscoveryStageError):
        service._observe_harness_mcp_servers(strict=True, fresh=True)

    detail = next(detail for event, detail in recorded if event == DISCOVERY_STAGE_FAILED_EVENT)
    # ``OSError(13, ...)`` arrives as PermissionError; the class is what a
    # support bundle needs, and it must arrive without the file it was reading.
    assert "error=PermissionError" in detail
    assert secret_path not in detail
    assert "someone" not in detail


def test_non_strict_host_scan_failure_stays_silent(tmp_path: Path, monkeypatch, recorded) -> None:
    """A best-effort scan returns nothing and must not fill the log on every poll."""

    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.configured_harness_detections",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("unreadable config")),
    )

    assert service._observe_harness_mcp_servers() == {}
    assert [event for event, _ in recorded if event == DISCOVERY_STAGE_FAILED_EVENT] == []


def _detection(harness: str, *artifacts: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=artifacts,
    )


def _stdio_artifact(harness: str, name: str) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"{harness}:mcp:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope="user",
        config_path=f"{harness}.json",
        command="npx",
        args=("-y", f"{name}-server"),
    )


def test_one_unreadable_harness_keeps_the_other_connections(monkeypatch) -> None:
    """A harness Guard cannot turn into identities must not empty the whole list."""

    broken = _detection("cursor", _stdio_artifact("cursor", "broken"))
    healthy = _detection("codex", _stdio_artifact("codex", "healthy"))

    def servers_for(detection: HarnessDetection) -> tuple[ManagedMcpServer, ...]:
        if detection.harness == "cursor":
            raise ValueError("malformed MCP entry")
        artifact = detection.artifacts[0]
        return (
            ManagedMcpServer(
                harness=detection.harness,
                name=artifact.name,
                source_scope=artifact.source_scope,
                config_path=artifact.config_path,
                command=artifact.command or "",
                args=tuple(artifact.args or ()),
                transport="stdio",
                env={},
                enabled=True,
            ),
        )

    def identity_for(server: ManagedMcpServer):
        # Identity building needs the native runtime, which this test does not
        # exercise; the contract under test is that one harness failing above
        # does not take the rest of the inventory with it.
        return (
            SimpleNamespace(identity_hash=f"hash-{server.harness}", name=server.name),
            SimpleNamespace(command=server.command, args_hash="args"),
            None,
        )

    monkeypatch.setattr(harness_mcp_discovery, "observable_stdio_servers_with_proxy", servers_for)
    monkeypatch.setattr(harness_mcp_discovery, "_identity_for", identity_for)

    found = harness_mcp_discovery.discover_harness_mcp_servers(
        home_dir=Path("/nonexistent-home"),
        guard_home=Path("/nonexistent-guard-home"),
        detections=[broken, healthy],
    )

    assert [server.harness for server in found] == ["codex"]


def test_persist_failure_is_named_apart_from_the_scan(tmp_path: Path, monkeypatch, recorded) -> None:
    """Saving a good scan is its own failure; the banner must not blame the config."""

    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.configured_harness_detections",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(service, "_remote_scan", lambda: ((), None))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.persist_discovered_harness_mcp_servers",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("disk is full")),
    )

    with pytest.raises(DiscoveryStageError) as caught:
        service._observe_harness_mcp_servers(strict=True, fresh=True)

    assert caught.value.code == "configured_host_persist_failed"
    detail = next(detail for event, detail in recorded if event == DISCOVERY_STAGE_FAILED_EVENT)
    assert "stage=configured_host_persist_failed" in detail
    assert "error=OperationalError" in detail


def test_codex_host_failure_keeps_the_reason_the_reader_can_act_on(tmp_path: Path, monkeypatch, recorded) -> None:
    """A named host failure reaches the client as itself, not as a generic failure."""

    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(
        service._codex_host_inventory,
        "refresh",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("codex_host_untrusted")),
    )

    with pytest.raises(DiscoveryStageError) as caught:
        service._refresh_codex_host_inventory(threading.Event())

    assert caught.value.code == "codex_host_untrusted"
    detail = next(detail for event, detail in recorded if event == DISCOVERY_STAGE_FAILED_EVENT)
    assert "stage=codex_host_untrusted" in detail


def test_unnamed_codex_host_failure_still_reaches_the_log(tmp_path: Path, monkeypatch, recorded) -> None:
    """An unexpected read failure is recorded rather than dropped on the floor."""

    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(
        service._codex_host_inventory,
        "refresh",
        lambda **_kwargs: (_ for _ in ()).throw(OSError(13, "Permission denied", "/Users/x/.codex")),
    )

    with pytest.raises(DiscoveryStageError) as caught:
        service._refresh_codex_host_inventory(threading.Event())

    assert caught.value.code == "codex_host_unavailable"
    detail = next(detail for event, detail in recorded if event == DISCOVERY_STAGE_FAILED_EVENT)
    assert "error=PermissionError" in detail
    assert "/Users/x/.codex" not in detail


def test_a_failed_discovery_job_leaves_a_record(recorded) -> None:
    """Every failed job is in the log, so the banner's promise of a record holds."""

    pool = McpDiscoveryJobs()
    try:
        job = pool.start(
            "configured-connections",
            lambda _cancel: (_ for _ in ()).throw(RuntimeError("worker exploded")),
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if pool.read(str(job["job_id"]))["state"] not in {"running", "cancelling"}:
                break
            time.sleep(0.01)
    finally:
        pool.close()

    detail = next(detail for event, detail in recorded if event == DISCOVERY_JOB_FAILED_EVENT)
    assert "code=discovery_failed" in detail
    assert "error=RuntimeError" in detail
    # The message of an uncaught provider exception is unbounded text no
    # redactor can clean, and daemon.log is handed to support.
    assert "worker exploded" not in detail


def test_a_failed_configured_scan_logs_no_path(tmp_path: Path, monkeypatch) -> None:
    """The daemon's own record names the exception class and nothing it read.

    `record_exception` falls back to `sys.exc_info()`, and the daemon log
    formatter writes that traceback out whole. An `OSError` carries the
    absolute path it could not open, so the fallback used to put the reader's
    home directory and username into the support artifact.
    """

    import json

    from codex_plugin_scanner.guard.daemon.diagnostics import DaemonDiagnostics

    home = tmp_path / "home"
    home.mkdir()
    secret = home / ".codex" / "config.toml"
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.local_cli_api.Path.home", staticmethod(lambda: home))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers",
        lambda **_kwargs: (_ for _ in ()).throw(PermissionError(13, "Permission denied", str(secret))),
    )
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home")
    try:
        service = LocalCliApiService(store=GuardStore(home), record_exception=diagnostics.record_exception)
        assert service.discover_items().get("discovery_issue") == "configured_host_scan_failed"
    finally:
        assert diagnostics.close(timeout_seconds=1.0) is True

    written = diagnostics.log_path.read_text(encoding="utf-8")
    failure = next(
        json.loads(line)
        for line in written.splitlines()
        if json.loads(line)["event"] == "local_cli_configured_discovery_failed"
    )
    assert failure["detail"] == "PermissionError"
    assert "exception" not in failure
    assert str(secret) not in written
    assert str(home) not in written
