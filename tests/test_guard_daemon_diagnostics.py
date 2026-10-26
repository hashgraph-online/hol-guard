from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.diagnostics import DaemonDiagnostics, cleanup_expired_daemon_logs
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime_artifact_reconciliation import RuntimeArtifactReconciliation
from codex_plugin_scanner.guard.store import GuardStore
from tests.coverage_ci import under_coverage_scale


def test_daemon_diagnostics_writes_json_records_on_a_background_worker(tmp_path: Path) -> None:
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home")

    assert diagnostics.record("daemon_ready") is True
    assert diagnostics.close(timeout_seconds=1.0) is True

    lines = diagnostics.log_path.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["event"] == "daemon_ready"
    if os.name != "nt":
        assert diagnostics.log_path.stat().st_mode & 0o777 == 0o600
        assert diagnostics.log_directory.stat().st_mode & 0o777 == 0o700


def test_daemon_diagnostics_records_exception_tracebacks(tmp_path: Path) -> None:
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home")

    try:
        raise RuntimeError("diagnostic failure")
    except RuntimeError:
        assert diagnostics.record_exception("daemon_serve_failed") is True
    assert diagnostics.close(timeout_seconds=1.0) is True

    payload = json.loads(diagnostics.log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert payload["event"] == "daemon_serve_failed"
    assert "RuntimeError: diagnostic failure" in payload["exception"]


def test_daemon_diagnostics_without_a_worker_writes_queued_records_on_close(tmp_path: Path) -> None:
    # One-shot callers (CLI hooks) have no worker thread to drain the queue, so
    # close must write the pending records instead of discarding them.
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home", start_worker=False)

    try:
        raise RuntimeError("one shot failure")
    except RuntimeError:
        assert diagnostics.record_exception("native_hook_worker_exception", detail="harness=codex") is True
    assert diagnostics.close(timeout_seconds=1.0) is True

    payload = json.loads(diagnostics.log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert payload["event"] == "native_hook_worker_exception"
    assert payload["detail"] == "harness=codex"
    assert "one shot failure" in payload["exception"]


def test_one_shot_diagnostics_append_without_rotating_the_daemon_log(tmp_path: Path) -> None:
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home", start_worker=False, rotate=False)

    assert type(diagnostics._handler) is logging.FileHandler
    try:
        raise RuntimeError("hook failure")
    except RuntimeError:
        assert diagnostics.record_exception("native_hook_worker_exception") is True
    assert diagnostics.close(timeout_seconds=1.0) is True
    assert list(diagnostics.log_directory.glob("daemon.log.*")) == []
    payload = json.loads(diagnostics.log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert "hook failure" in payload["exception"]


def test_one_shot_diagnostics_leave_log_retention_to_the_daemon(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    log_directory = home / "logs"
    log_directory.mkdir(parents=True)
    old_log = log_directory / "daemon.log.2026-01-01"
    old_log.write_text("old\n", encoding="utf-8")
    expired = time.time() - 8 * 24 * 60 * 60
    os.utime(old_log, (expired, expired))

    one_shot = DaemonDiagnostics(home, start_worker=False, rotate=False)
    assert one_shot.record("native_hook_worker_exception") is True
    assert one_shot.close(timeout_seconds=1.0) is True
    assert old_log.exists() is True

    rotating = DaemonDiagnostics(home, start_worker=False, rotate=True)
    try:
        assert old_log.exists() is False
    finally:
        rotating.close(timeout_seconds=1.0)


def test_one_shot_close_returns_when_the_log_write_stalls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home", start_worker=False, rotate=False)
    assert diagnostics.record("native_hook_worker_exception") is True
    handler = diagnostics._handler
    assert handler is not None

    def stall(_record: logging.LogRecord) -> None:
        time.sleep(2)

    monkeypatch.setattr(handler, "emit", stall)
    started_at = time.monotonic()
    finished = diagnostics.close(timeout_seconds=0.25)
    elapsed = time.monotonic() - started_at

    assert finished is False
    assert elapsed < 1.0


def test_daemon_diagnostics_drops_records_when_the_queue_is_full_without_waiting(tmp_path: Path) -> None:
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home", queue_capacity=1, start_worker=False)

    assert diagnostics.record("first") is True
    started_at = time.monotonic()
    assert diagnostics.record("second") is False
    assert time.monotonic() - started_at < 0.05 * under_coverage_scale(4.0)
    assert diagnostics.close() is True


def test_daemon_diagnostics_removes_rotated_logs_older_than_seven_days(tmp_path: Path) -> None:
    log_directory = tmp_path / "logs"
    log_directory.mkdir()
    old_log = log_directory / "daemon.log.2026-01-01"
    retained_log = log_directory / "daemon.log.2026-01-02"
    unrelated_log = log_directory / "other.log.2026-01-01"
    for path in (old_log, retained_log, unrelated_log):
        path.write_text("diagnostic\n", encoding="utf-8")
    now = 1_800_000_000.0
    os.utime(old_log, (now - 8 * 24 * 60 * 60, now - 8 * 24 * 60 * 60))
    os.utime(retained_log, (now - 6 * 24 * 60 * 60, now - 6 * 24 * 60 * 60))

    cleanup_expired_daemon_logs(log_directory, now=now)

    assert old_log.exists() is False
    assert retained_log.exists() is True
    assert unrelated_log.exists() is True


def test_daemon_diagnostics_rotates_daily_with_seven_backups(tmp_path: Path) -> None:
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home")

    assert diagnostics.record("before_rotation") is True
    handler = diagnostics._handler
    assert handler is not None
    assert handler.backupCount == 7
    assert handler.utc is True
    handler.rolloverAt = 0
    assert diagnostics.record("after_rotation") is True
    assert diagnostics.close(timeout_seconds=1.0) is True

    assert list(diagnostics.log_directory.glob("daemon.log.*"))


def test_daemon_lifecycle_writes_diagnostics(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)

    daemon.start()
    daemon.stop()

    records = [json.loads(line) for line in (store.guard_home / "logs" / "daemon.log").read_text().splitlines()]
    events = [record["event"] for record in records]
    assert "daemon_ready" in events
    assert "daemon_shutdown_requested" in events


def test_daemon_reconciles_managed_artifacts_before_reporting_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    configured_home = tmp_path / "configured-home"
    observed: list[str] = []

    def reconcile(
        _store: GuardStore,
        *,
        home_dir: Path | None = None,
    ) -> RuntimeArtifactReconciliation:
        observed.append("reconciled")
        assert home_dir == configured_home
        return RuntimeArtifactReconciliation(
            refreshed_launchers=("codex",),
            repaired_harnesses=("codex",),
            repaired_package_managers=("npm",),
            failed_harnesses=(),
            errors=(),
        )

    monkeypatch.setattr(daemon_server_module, "reconcile_runtime_artifacts", reconcile)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=configured_home)

    daemon.start()
    observed.append("started")
    daemon.stop()

    records = [json.loads(line) for line in (store.guard_home / "logs" / "daemon.log").read_text().splitlines()]
    events = [record["event"] for record in records]
    assert observed == ["reconciled", "started"]
    assert events.index("runtime_artifact_reconciliation_completed") < events.index("daemon_ready")


@pytest.fixture
def clean_startup_phases():
    from codex_plugin_scanner.guard.daemon import startup_phase

    startup_phase._pending.clear()  # pyright: ignore[reportPrivateUsage]
    startup_phase._default_sink = None  # pyright: ignore[reportPrivateUsage]
    yield startup_phase
    startup_phase._pending.clear()  # pyright: ignore[reportPrivateUsage]
    startup_phase._default_sink = None  # pyright: ignore[reportPrivateUsage]


def test_startup_phase_records_elapsed_milliseconds_and_buffers_until_a_sink_exists(clean_startup_phases) -> None:
    startup_phase = clean_startup_phases
    with startup_phase.timed_phase("store_open"):
        pass
    events: list[tuple[str, str]] = []
    startup_phase.flush_pending_phases(lambda event, detail: events.append((event, detail)))
    with startup_phase.timed_phase("serve_thread_start", lambda event, detail: events.append((event, detail))):
        pass

    assert [event for event, _ in events] == ["startup_phase", "startup_phase"]
    assert events[0][1].startswith("phase=store_open elapsed_ms=")
    assert events[1][1].startswith("phase=serve_thread_start elapsed_ms=")
    assert "since_first_import_ms=" in events[1][1]
    startup_phase.flush_pending_phases(lambda event, detail: events.append((event, detail)))
    assert len(events) == 2


def test_startup_phase_flush_installs_the_default_sink(clean_startup_phases) -> None:
    startup_phase = clean_startup_phases
    events: list[tuple[str, str]] = []
    startup_phase.flush_pending_phases(lambda event, detail: events.append((event, detail)))
    with startup_phase.timed_phase("acquire_owner_lock"):
        pass
    startup_phase.record_phase_since("init_http_server", time.monotonic() - 1.5)

    assert events[0][1].startswith("phase=acquire_owner_lock elapsed_ms=")
    assert events[1][1].startswith("phase=init_http_server elapsed_ms=")
    assert int(events[1][1].split("elapsed_ms=")[1].split()[0]) >= 1500
    assert not startup_phase._pending  # pyright: ignore[reportPrivateUsage]


def test_startup_phase_buffer_is_bounded(clean_startup_phases) -> None:
    startup_phase = clean_startup_phases
    for _ in range(startup_phase._MAX_PENDING + 10):  # pyright: ignore[reportPrivateUsage]
        with startup_phase.timed_phase("x"):
            pass
    assert len(startup_phase._pending) == startup_phase._MAX_PENDING  # pyright: ignore[reportPrivateUsage]


def test_releasing_the_default_sink_buffers_phases_for_the_next_daemon(clean_startup_phases) -> None:
    startup_phase = clean_startup_phases
    closed: list[tuple[str, str]] = []
    newer: list[tuple[str, str]] = []

    def closed_sink(event: str, detail: str) -> None:
        closed.append((event, detail))

    def newer_sink(event: str, detail: str) -> None:
        newer.append((event, detail))

    startup_phase.flush_pending_phases(closed_sink)
    startup_phase.release_default_sink(closed_sink)
    with startup_phase.timed_phase("import_modules"):
        pass
    assert not closed
    assert len(startup_phase._pending) == 1  # pyright: ignore[reportPrivateUsage]

    startup_phase.flush_pending_phases(newer_sink)
    startup_phase.release_default_sink(closed_sink)
    with startup_phase.timed_phase("store_open"):
        pass
    assert [detail.split()[0] for _event, detail in newer] == ["phase=import_modules", "phase=store_open"]
