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


@pytest.fixture(autouse=True)
def _no_real_hook_worker(monkeypatch):
    """Keeps the real hook worker out of these tests; a test can set its own build."""

    monkeypatch.setattr(worker_host.WorkerHost, "_build_hook_worker", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_start_private_state_resident", lambda self: None)


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


def test_worker_host_reports_each_start_step_it_finishes(tmp_path, monkeypatch):
    store = _Store(tmp_path)
    steps: list[str] = []

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: steps.append("<publish>"))
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start(on_phase=steps.append)

    assert steps == ["bundle_checked", "turn_held", "admitted", "<publish>", "publishing"]


class _SteppingStore(_Store):
    """Reports the migration's own steps, as the real store does."""

    def migrate_installed_command_pack_authority(self) -> None:
        from codex_plugin_scanner.guard.catalog_delivery.installed_upgrade import report_migration_step

        super().migrate_installed_command_pack_authority()
        report_migration_step("candidate_prepared")
        report_migration_step("catalog_migrated")


def test_worker_host_reports_the_migration_steps_inside_the_turn(tmp_path, monkeypatch):
    # The daemon timestamps each reported step, so a slow startup shows which
    # part of the migration spent the time.
    store = _SteppingStore(tmp_path)
    steps: list[str] = []

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: steps.append("<publish>"))
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start(on_phase=steps.append)

    assert steps == [
        "bundle_checked",
        "turn_held",
        "candidate_prepared",
        "catalog_migrated",
        "admitted",
        "<publish>",
        "publishing",
    ]


def test_a_migration_retry_reports_no_steps_after_the_daemon_stopped_reading(tmp_path, monkeypatch):
    # Only the first attempt reports; the daemon reads steps until ready.
    store = _SteppingStore(tmp_path, failures=1)
    steps: list[str] = []
    loops: dict[str, object] = {}

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_loop", lambda self, name, body, interval: loops.update({name: body}))
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start(on_phase=steps.append)
    retry = loops["installed-authority"]
    assert callable(retry)
    retry()

    assert store.calls == ["migrate", "migrate"]
    assert steps == ["bundle_checked", "turn_held", "admitted", "publishing"]


def test_worker_host_retries_a_failed_migration_until_it_lands(tmp_path, monkeypatch):
    store = _Store(tmp_path, failures=2)
    loops: dict[str, object] = {}

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_loop", lambda self, name, body, interval: loops.update({name: body}))
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

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
    store = _Store(tmp_path)
    loops: list[str] = []

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_loop", lambda self, name, body, interval: loops.append(name))
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

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


def test_the_writer_thread_appends_each_batch_itself(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.runtime_health import diagnostics

    writers: list[str] = []
    finish = diagnostics.DaemonDiagnostics._finish_pending  # pyright: ignore[reportPrivateUsage]

    def finish_pending(self):
        writers.append(threading.current_thread().name)
        finish(self)

    monkeypatch.setattr(diagnostics.DaemonDiagnostics, "_finish_pending", finish_pending)
    writer = BackgroundLogWriter(tmp_path)
    try:
        assert writer.error("first_failure", "error=RuntimeError") is True
        assert _read_log_lines(tmp_path / "logs" / "daemon.log")
        assert writer.error("second_failure", "error=RuntimeError") is True
    finally:
        assert writer.close(timeout_seconds=5.0) is True

    # A drain on its own thread would outlive a stalled append and let the next
    # batch start a second writer beside it.
    assert writers
    assert set(writers) == {"guard-background-log-writer"}
    events = [json.loads(line)["event"] for line in (tmp_path / "logs" / "daemon.log").read_text().splitlines()]
    assert events == ["first_failure", "second_failure"]


def test_a_host_that_fails_to_start_still_writes_and_releases_its_log(tmp_path, monkeypatch):
    def start(self, on_phase=None):
        background_diagnostics.record_background_event("worker_host_start_failed", "error=RuntimeError")
        raise _StopError

    monkeypatch.setattr(worker_host, "GuardStore", lambda guard_home: _Store(guard_home))
    monkeypatch.setattr(worker_host.WorkerHost, "start", start)

    with pytest.raises(_StopError):
        worker_host.run_worker_host(tmp_path)

    # The sink is gone and the queued record reached the log before the raise left.
    assert background_diagnostics.record_background_event("after_exit", "error=RuntimeError") is False
    events = [json.loads(line)["event"] for line in (tmp_path / "logs" / "daemon.log").read_text().splitlines()]
    assert events == ["worker_host_start_failed"]


def test_worker_host_reports_ready_before_starting_the_workers_no_hook_waits_on(tmp_path, monkeypatch):
    events: list[str] = []

    class _Stdout:
        def write(self, text: str) -> int:
            events.append(text.strip())
            return len(text)

        def flush(self) -> None:
            pass

    class _Stdin:
        class buffer:  # noqa: N801 - mirrors sys.stdin.buffer
            @staticmethod
            def read(_size: int) -> bytes:
                return b""

    monkeypatch.setattr(worker_host, "GuardStore", lambda guard_home: _Store(guard_home))
    monkeypatch.setattr(worker_host.WorkerHost, "start", lambda self, on_phase=None: events.append("<start>"))
    monkeypatch.setattr(worker_host.WorkerHost, "wait_for_policy_publication", lambda self: events.append("<wait>"))
    monkeypatch.setattr(worker_host.WorkerHost, "start_background_workers", lambda self: events.append("<background>"))
    monkeypatch.setattr(worker_host.WorkerHost, "shutdown", lambda self: events.append("<shutdown>"))
    monkeypatch.setattr(worker_host.sys, "stdout", _Stdout())
    monkeypatch.setattr(worker_host.sys, "stdin", _Stdin())

    assert worker_host.run_worker_host(tmp_path) == 0

    assert events == [
        "phase launched",
        "<start>",
        "phase started",
        "<wait>",
        "ready",
        "<background>",
        "<shutdown>",
    ]


def test_a_background_worker_that_fails_to_start_is_not_swallowed(tmp_path, monkeypatch):
    stopped: list[bool] = []

    def failing(self):
        raise OSError("no thread")

    monkeypatch.setattr(worker_host, "GuardStore", lambda guard_home: _Store(guard_home))
    monkeypatch.setattr(worker_host.WorkerHost, "start", lambda self, on_phase=None: None)
    monkeypatch.setattr(worker_host.WorkerHost, "wait_for_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "start_background_workers", failing)
    monkeypatch.setattr(worker_host.WorkerHost, "shutdown", lambda self: stopped.append(True))
    monkeypatch.setattr(worker_host, "_report_phase", lambda step: None)

    with pytest.raises(OSError, match="no thread"):
        worker_host.run_worker_host(tmp_path)

    assert stopped == [True]


class _PreparedWorker:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def start_native_policy_publication(self, *, home_dir=None, workspace=None) -> None:
        self.calls.append("publish")


def test_worker_host_builds_the_publisher_beside_admission_and_publishes_after_it(tmp_path, monkeypatch):
    store = _Store(tmp_path)
    built = threading.Event()
    migrate = store.migrate_installed_command_pack_authority

    def build(self):
        store.calls.append("build")
        built.set()
        return _PreparedWorker(store.calls)

    def slow_migrate():
        # The build runs while the admission still holds the start.
        assert built.wait(timeout=5)
        migrate()

    monkeypatch.setattr(worker_host.WorkerHost, "_build_hook_worker", build)
    monkeypatch.setattr(store, "migrate_installed_command_pack_authority", slow_migrate)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start()

    assert store.calls == ["build", "migrate", "publish"]
    assert isinstance(host._hook_worker, _PreparedWorker)  # pyright: ignore[reportPrivateUsage]


def test_worker_host_builds_the_publisher_again_when_the_early_build_failed(tmp_path, monkeypatch):
    store = _Store(tmp_path)
    attempts: list[str] = []

    def build(self):
        attempts.append(threading.current_thread().name)
        if len(attempts) == 1:
            return None
        return _PreparedWorker(store.calls)

    monkeypatch.setattr(worker_host.WorkerHost, "_build_hook_worker", build)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start()

    assert attempts == ["guard-worker-policy-prepare", threading.current_thread().name]
    assert store.calls == ["migrate", "publish"]


class _WarmPublisher:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def warm_first_publication(self) -> None:
        self.calls.append(f"warm:{threading.current_thread().name}")


def test_worker_host_warms_the_first_publication_beside_admission(tmp_path, monkeypatch):
    store = _Store(tmp_path)

    def build(self):
        worker = _PreparedWorker(store.calls)
        worker.policy_snapshot_publisher = _WarmPublisher(store.calls)  # pyright: ignore[reportAttributeAccessIssue]
        return worker

    monkeypatch.setattr(worker_host.WorkerHost, "_build_hook_worker", build)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    host.start()

    # The compiles run on the prepare thread; publishing still waits for the admission.
    assert sorted(store.calls[:2]) == ["migrate", "warm:guard-worker-policy-prepare"]
    assert store.calls[2:] == ["publish"]
