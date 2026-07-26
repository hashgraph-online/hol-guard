from __future__ import annotations

import json
import os
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon.diagnostics import DaemonDiagnostics, cleanup_expired_daemon_logs
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


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


def test_daemon_diagnostics_drops_records_when_the_queue_is_full_without_waiting(tmp_path: Path) -> None:
    diagnostics = DaemonDiagnostics(tmp_path / "guard-home", queue_capacity=1, start_worker=False)

    assert diagnostics.record("first") is True
    started_at = time.monotonic()
    assert diagnostics.record("second") is False
    assert time.monotonic() - started_at < 0.05
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
