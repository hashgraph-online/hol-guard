from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.lifecycle_journal import (
    load_bounded_incident_lifecycle_events,
    load_daemon_lifecycle_events,
    record_daemon_lifecycle_event,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_lifecycle_journal_is_bounded_private_and_storage_independent(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    for index in range(140):
        record_daemon_lifecycle_event(
            guard_home,
            event="ready",
            session_id=f"session-{index}",
            port=4700 + index,
        )

    journal_dir = guard_home / "daemon-lifecycle"
    entries = sorted(journal_dir.glob("*.json"))
    events = load_daemon_lifecycle_events(guard_home, limit=200)

    assert len(entries) == 128
    assert len(events) == 128
    assert events[0].get("session_id") == "session-12"
    assert events[-1].get("session_id") == "session-139"
    assert not (guard_home / "guard.db").exists()
    if os.name != "nt":
        assert stat.S_IMODE(journal_dir.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in entries)


def test_lifecycle_journal_rejects_unbounded_or_sensitive_labels(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="safe label"):
        record_daemon_lifecycle_event(
            tmp_path,
            event="failed: /private/user/workspace",
        )
    with pytest.raises(ValueError, match="safe label"):
        record_daemon_lifecycle_event(
            tmp_path,
            event="stopped",
            reason="database locked: command text",
        )
    with pytest.raises(ValueError, match="safe identifier"):
        record_daemon_lifecycle_event(
            tmp_path,
            event="ready",
            session_id="../foreign-state",
        )


def test_lifecycle_journal_rejects_symbolic_link_directory(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("Symbolic-link permissions vary on Windows.")
    target = tmp_path / "target"
    target.mkdir()
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-lifecycle").symlink_to(target, target_is_directory=True)

    with pytest.raises(OSError, match="symbolic links"):
        record_daemon_lifecycle_event(guard_home, event="ready")


def test_lifecycle_reader_skips_invalid_records(tmp_path: Path) -> None:
    journal_dir = tmp_path / "daemon-lifecycle"
    journal_dir.mkdir()
    _ = (journal_dir / "00000000000000000001-invalid.json").write_text(
        json.dumps({"version": 1, "event": "ready", "recorded_at_ns": 1, "pid": "not-an-int"}),
        encoding="utf-8",
    )
    record_daemon_lifecycle_event(tmp_path, event="ready", session_id="valid")

    events = load_daemon_lifecycle_events(tmp_path)

    assert [event.get("session_id") for event in events] == ["valid"]


def test_lifecycle_reader_skips_oversized_record(tmp_path: Path) -> None:
    journal_dir = tmp_path / "daemon-lifecycle"
    journal_dir.mkdir()
    oversized = journal_dir / "99999999999999999999-oversized.json"
    oversized.write_bytes(b" " * 2049)
    oversized.chmod(0o600)
    record_daemon_lifecycle_event(tmp_path, event="ready", session_id="valid")

    events = load_daemon_lifecycle_events(tmp_path)

    assert [event.get("session_id") for event in events] == ["valid"]


def test_incident_reader_reports_scan_limit_instead_of_empty_history(tmp_path: Path) -> None:
    journal_dir = tmp_path / "daemon-lifecycle"
    journal_dir.mkdir()
    for index in range(257):
        (journal_dir / f"{index:020d}.tmp").touch()

    events, status = load_bounded_incident_lifecycle_events(tmp_path)

    assert events == []
    assert status == "journal_scan_limit"


def test_incident_reader_omits_symlinked_records(tmp_path: Path) -> None:
    journal_dir = tmp_path / "daemon-lifecycle"
    journal_dir.mkdir()
    target = tmp_path / "outside.json"
    target.write_text('{"event":"ready","version":1,"recorded_at_ns":1,"pid":1}', encoding="utf-8")
    (journal_dir / "99999999999999999999-linked.json").symlink_to(target)

    events, status = load_bounded_incident_lifecycle_events(tmp_path)

    assert events == []
    assert status == "invalid_entries_omitted"


def test_incident_reader_omits_read_time_io_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record_daemon_lifecycle_event(tmp_path, event="ready")

    def fail_read(_path: Path, *, max_bytes: int) -> str:
        del max_bytes
        raise OSError("private incident detail")

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.lifecycle_journal.read_private_regular_text", fail_read)

    events, status = load_bounded_incident_lifecycle_events(tmp_path)

    assert events == []
    assert status == "invalid_entries_omitted"
    assert load_daemon_lifecycle_events(tmp_path) == []


def test_daemon_records_ready_and_clean_stop_without_sqlite_dependency(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)

    daemon.start()
    daemon.stop()

    deadline = time.monotonic() + 2.0
    while True:
        events = load_daemon_lifecycle_events(store.guard_home)
        lifecycle = [(event["event"], event.get("reason")) for event in events]
        if lifecycle[-1:] == [("stopped", "requested_shutdown")] or time.monotonic() >= deadline:
            break
        time.sleep(0.01)

    assert lifecycle == [
        ("start_requested", None),
        ("ready", None),
        ("shutdown_requested", "explicit_stop"),
        ("stopped", "requested_shutdown"),
    ]
    session_ids = {event.get("session_id") for event in events}
    assert len(session_ids) == 1
    assert None not in session_ids


def test_daemon_classifies_requested_sigint_as_clean_shutdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    monkeypatch.setattr(daemon._server, "serve_forever", lambda: (_ for _ in ()).throw(KeyboardInterrupt()))

    daemon._serve_forever()

    lifecycle = [(event["event"], event.get("reason")) for event in load_daemon_lifecycle_events(store.guard_home)]
    assert ("serve_failed", "unexpected_exception") not in lifecycle
    assert lifecycle[-1] == ("stopped", "requested_shutdown")
