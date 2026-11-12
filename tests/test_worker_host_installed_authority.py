"""The daemon's worker host admits the installed release before it publishes policy.

A runtime upgrade changes the command engine. The resident refuses any policy
snapshot bound to packs an older engine compiled, so if nothing migrates the
active packs, every hook fails closed. The Python daemon migrated at startup;
these tests hold the worker host that replaced it to the same order.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime_health import background_diagnostics
from codex_plugin_scanner.guard.runtime_health.diagnostics import BackgroundLogWriter
from codex_plugin_scanner.guard.workers import host as worker_host


class _StopError(Exception):
    """Ends ``WorkerHost.start`` once the step under test has run."""


class _Store:
    def __init__(self, guard_home: Path, failures: int = 0) -> None:
        self.guard_home = guard_home
        self.failures = failures
        self.calls: list[str] = []

    def migrate_installed_command_pack_authority(self) -> None:
        self.calls.append("migrate")
        if self.failures:
            self.failures -= 1
            raise RuntimeError("native runtime did not answer")


def test_worker_host_migrates_installed_release_before_first_publication(tmp_path, monkeypatch):
    store = _Store(tmp_path)

    def publish(self):
        store.calls.append("publish")
        raise _StopError

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", publish)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    with pytest.raises(_StopError):
        host.start()

    assert store.calls == ["migrate", "publish"]


def test_worker_host_retries_a_failed_migration_until_it_lands(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.runtime import approval_attention

    store = _Store(tmp_path, failures=2)
    loops: dict[str, object] = {}

    def attention(**_kwargs):
        raise _StopError

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_loop", lambda self, name, body, interval: loops.update({name: body}))
    monkeypatch.setattr(approval_attention, "ApprovalAttentionCoordinator", attention)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    with pytest.raises(_StopError):
        host.start()

    retry = loops["installed-authority"]
    assert callable(retry)
    retry()
    assert store.calls == ["migrate", "migrate"]
    retry()
    retry()
    # Once admitted the loop stops asking.
    assert store.calls == ["migrate", "migrate", "migrate"]


def test_worker_host_starts_no_retry_when_the_migration_landed(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.runtime import approval_attention

    store = _Store(tmp_path)
    loops: list[str] = []

    def attention(**_kwargs):
        raise _StopError

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_loop", lambda self, name, body, interval: loops.append(name))
    monkeypatch.setattr(approval_attention, "ApprovalAttentionCoordinator", attention)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    with pytest.raises(_StopError):
        host.start()

    assert "installed-authority" not in loops


def _read_log_lines(path: Path, *, deadline_seconds: float = 5.0) -> list[str]:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if path.is_file() and (lines := path.read_text(encoding="utf-8").splitlines()):
            return lines
        time.sleep(0.02)
    return []


def test_failed_migration_reaches_daemon_log_while_the_process_runs(tmp_path):
    from codex_plugin_scanner.guard.extension_control_host import migrate_installed_authority

    writer = BackgroundLogWriter(tmp_path)
    background_diagnostics.install_sink(writer.error, notice=writer.notice)
    try:
        assert migrate_installed_authority(_Store(tmp_path, failures=1)) is False  # pyright: ignore[reportArgumentType]
        # Written while the writer is still open, not held until the process shuts down.
        lines = _read_log_lines(tmp_path / "logs" / "daemon.log")
    finally:
        background_diagnostics.release_sink(writer.error)
        writer.close()

    records = [json.loads(line) for line in lines]
    assert [record["event"] for record in records] == ["installed_authority_migration_failed"]
    assert records[0]["level"] == "error"
    assert "RuntimeError" in records[0]["detail"]


def test_a_stalled_log_write_does_not_hold_the_reporting_thread(tmp_path, monkeypatch):
    released = threading.Event()
    written: list[str] = []

    def stalled_write(self, records):
        released.wait(timeout=10)
        written.extend(event for _notice, event, _detail in records)

    monkeypatch.setattr(BackgroundLogWriter, "_write", stalled_write)
    writer = BackgroundLogWriter(tmp_path)
    try:
        started = time.monotonic()
        assert writer.error("first_failure", "error=RuntimeError") is True
        assert writer.notice("second_notice", "state=waiting") is True
        # The sinks only enqueue; the stalled write runs on the writer thread.
        assert time.monotonic() - started < 0.5
    finally:
        released.set()
        assert writer.close(timeout_seconds=5.0) is True

    assert written == ["first_failure", "second_notice"]
    assert writer.error("after_close", "error=RuntimeError") is False
