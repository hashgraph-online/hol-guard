"""Only one Guard process migrates the installed command-pack authority at a time.

After an upgrade the worker host and each extension-control host (library
servers, CLI processes) all found the same unmigrated activation and migrated
it at once. Each prepared the full candidate set, they competed for the
resident and the authority lock, and the losers failed the final
compare-and-swap with ``active_security_observation_conflict`` and retried. On
a long-lived install every hook failed closed for over five minutes while they
did. These tests hold the migration to one process at a time: the worker host
waits its turn, and an extension-control host that finds the turn taken
starts on its fallback view and retries on refresh instead of migrating too.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import extension_control_host
from codex_plugin_scanner.guard.extension_control_host import (
    ExtensionControlHost,
    _InstalledAuthorityMigrationError,
    migrate_installed_authority,
)
from codex_plugin_scanner.guard.installed_authority_migration_turn import installed_authority_migration_turn
from codex_plugin_scanner.guard.runtime_health import background_diagnostics


@pytest.fixture
def recorded():
    events: list[tuple[str, str]] = []

    def sink(event: str, detail: str) -> None:
        events.append((event, detail))

    background_diagnostics.install_sink(sink, notice=sink)
    yield events
    background_diagnostics.release_sink(sink)


class _SlowStore:
    """Counts how many migrations overlap."""

    def __init__(self, guard_home: Path, seconds: float = 0.3) -> None:
        self.guard_home = guard_home
        self.seconds = seconds
        self.calls = 0
        self.running = 0
        self.overlap = 0
        self._lock = threading.Lock()

    def migrate_installed_command_pack_authority(self) -> None:
        with self._lock:
            self.calls += 1
            self.running += 1
            self.overlap = max(self.overlap, self.running)
        time.sleep(self.seconds)
        with self._lock:
            self.running -= 1


def test_concurrent_migrations_run_one_at_a_time(tmp_path) -> None:
    store = _SlowStore(tmp_path)
    results: list[bool] = []

    def migrate() -> None:
        results.append(migrate_installed_authority(store))  # pyright: ignore[reportArgumentType]

    threads = [threading.Thread(target=migrate) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert results == [True, True, True]
    assert store.calls == 3
    assert store.overlap == 1


def test_an_extension_control_host_does_not_queue_behind_another_migration(tmp_path, recorded) -> None:
    store = _SlowStore(tmp_path)
    server = SimpleNamespace(store=store, _installed_authority_pending=False)

    with installed_authority_migration_turn(tmp_path, wait_seconds=0.0) as held:
        assert held is True
        started = time.monotonic()
        with pytest.raises(_InstalledAuthorityMigrationError):
            ExtensionControlHost._migrate_installed_authority(server)  # pyright: ignore[reportArgumentType]
        assert time.monotonic() - started < 1.0

    # Pending, so the refresh tick retries it; nothing migrated and no failure recorded.
    assert server._installed_authority_pending is True
    assert store.calls == 0
    assert recorded == []

    ExtensionControlHost._migrate_installed_authority(server)  # pyright: ignore[reportArgumentType]
    assert server._installed_authority_pending is False
    assert store.calls == 1


def test_a_pending_migration_backoff_keeps_refresh_from_blocking(tmp_path, monkeypatch) -> None:
    sentinel = object()
    clock = [100.0]
    attempts = 0

    def fail_migration(*_args, **_kwargs) -> bool:
        nonlocal attempts
        attempts += 1
        return False

    server = SimpleNamespace(
        store=SimpleNamespace(guard_home=tmp_path),
        _installed_authority_pending=True,
        _installed_authority_retry_at=0.0,
        runtime=SimpleNamespace(current=lambda: sentinel),
    )
    monkeypatch.setattr(extension_control_host, "migrate_installed_authority", fail_migration)
    monkeypatch.setattr(extension_control_host.time, "monotonic", lambda: clock[0])
    server._migrate_installed_authority = lambda: ExtensionControlHost._migrate_installed_authority(server)

    assert ExtensionControlHost.refresh(server) is sentinel  # pyright: ignore[reportArgumentType]
    assert server._installed_authority_retry_at == 105.0
    assert ExtensionControlHost.refresh(server) is sentinel  # pyright: ignore[reportArgumentType]
    assert attempts == 1


def test_a_busy_migration_turn_reports_busy_without_marking_failure(tmp_path) -> None:
    store = _SlowStore(tmp_path, seconds=0.0)
    busy: list[bool] = []

    with installed_authority_migration_turn(tmp_path, wait_seconds=0.0) as held:
        assert held is True
        assert migrate_installed_authority(store, wait_seconds=0.0, on_busy=lambda: busy.append(True)) is False

    assert busy == [True]
    assert store.calls == 0


def test_a_failed_migration_starts_backoff_after_the_attempt(tmp_path, monkeypatch) -> None:
    server = SimpleNamespace(
        store=SimpleNamespace(guard_home=tmp_path),
        _installed_authority_pending=False,
        _installed_authority_retry_at=0.0,
    )
    monkeypatch.setattr(extension_control_host, "migrate_installed_authority", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(extension_control_host.time, "monotonic", lambda: 10.0)

    with pytest.raises(_InstalledAuthorityMigrationError):
        ExtensionControlHost._migrate_installed_authority(server)  # pyright: ignore[reportArgumentType]

    assert server._installed_authority_retry_at == 15.0


def test_the_worker_host_waits_for_another_process_to_finish(tmp_path) -> None:
    store = _SlowStore(tmp_path, seconds=0.0)
    ready = tmp_path / "held"
    release = tmp_path / "release"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import sys, time
                from pathlib import Path
                from codex_plugin_scanner.guard.installed_authority_migration_turn import (
                    installed_authority_migration_turn,
                )

                home = Path(sys.argv[1])
                with installed_authority_migration_turn(home, wait_seconds=0.0) as held:
                    assert held
                    (home / "held").write_text("1")
                    deadline = time.monotonic() + 60
                    while not (home / "release").exists():
                        assert time.monotonic() < deadline
                        time.sleep(0.02)
                """
            ),
            str(tmp_path),
        ],
    )
    waited: list[bool] = []
    waiter = threading.Thread(target=lambda: waited.append(migrate_installed_authority(store, wait_seconds=60.0)))  # pyright: ignore[reportArgumentType]
    try:
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert holder.poll() is None, "turn holder exited early"
            assert time.monotonic() < deadline
            time.sleep(0.02)
        # The other process holds the turn until told to let go.
        assert migrate_installed_authority(store, wait_seconds=0.0) is False  # pyright: ignore[reportArgumentType]
        waiter.start()
        waiter.join(timeout=0.5)
        assert waiter.is_alive()
        assert store.calls == 0
        release.write_text("1")
        waiter.join(timeout=30)
        assert waited == [True]
        assert store.calls == 1
    finally:
        release.write_text("1")
        holder.wait(timeout=30)
        if waiter.is_alive():
            waiter.join(timeout=30)
    assert holder.returncode == 0


def test_a_slow_migration_leaves_its_duration(tmp_path, recorded, monkeypatch) -> None:
    monkeypatch.setattr(extension_control_host, "_SLOW_MIGRATION_SECONDS", 0.0)

    assert migrate_installed_authority(_SlowStore(tmp_path, seconds=0.0)) is True  # pyright: ignore[reportArgumentType]

    [(event, detail)] = recorded
    assert event == "installed_authority_migration_slow"
    assert detail.startswith("elapsed_ms=")


def test_a_failed_migration_records_how_long_it_ran(tmp_path, recorded) -> None:
    def unavailable() -> None:
        raise RuntimeError("native runtime did not answer")

    store = SimpleNamespace(guard_home=tmp_path, migrate_installed_command_pack_authority=unavailable)

    assert migrate_installed_authority(store) is False  # pyright: ignore[reportArgumentType]

    [(event, detail)] = recorded
    assert event == "installed_authority_migration_failed"
    assert " elapsed_ms=" in detail


def test_the_bundle_check_runs_while_another_process_holds_the_turn(tmp_path, monkeypatch) -> None:
    # At a cold start the artifact reconcile usually holds the turn; checking
    # the installed bundle first overlaps that wait instead of following it.
    checks: list[str] = []
    steps: list[str] = []
    monkeypatch.setattr(extension_control_host, "_verify_installed_bundle_early", lambda: checks.append("bundle"))
    store = _SlowStore(tmp_path, seconds=0.0)

    with installed_authority_migration_turn(tmp_path, wait_seconds=0.0) as held:
        assert held
        assert migrate_installed_authority(store, wait_seconds=0.05, on_phase=steps.append) is False  # pyright: ignore[reportArgumentType]

    assert checks == ["bundle"]
    assert steps == ["bundle_checked"]
    assert store.calls == 0

    assert migrate_installed_authority(store, wait_seconds=0.05, on_phase=steps.append) is True  # pyright: ignore[reportArgumentType]
    assert steps == ["bundle_checked", "bundle_checked", "turn_held"]
    assert store.calls == 1


def test_a_caller_that_will_not_wait_skips_the_early_bundle_check(tmp_path, monkeypatch) -> None:
    # An extension-control host gives up on a taken turn at once; checking
    # the bundle first would only delay its fallback.
    checks: list[str] = []
    steps: list[str] = []
    monkeypatch.setattr(extension_control_host, "_verify_installed_bundle_early", lambda: checks.append("bundle"))
    store = _SlowStore(tmp_path, seconds=0.0)

    with installed_authority_migration_turn(tmp_path, wait_seconds=0.0) as held:
        assert held
        assert migrate_installed_authority(store, wait_seconds=0.0, on_phase=steps.append) is False  # pyright: ignore[reportArgumentType]

    assert checks == []
    assert steps == []
    assert store.calls == 0


def test_a_failed_early_bundle_check_leaves_the_failure_to_the_migration(tmp_path, recorded, monkeypatch) -> None:
    from codex_plugin_scanner.guard.catalog_delivery import preparation_authority

    def unverifiable():
        raise ValueError("installed bundle metadata unavailable")

    monkeypatch.setattr(preparation_authority, "load_installed_bundle", unverifiable)
    store = _SlowStore(tmp_path, seconds=0.0)

    assert migrate_installed_authority(store) is True  # pyright: ignore[reportArgumentType]
    assert store.calls == 1
    assert recorded == []


def test_a_failing_phase_reporter_does_not_skip_the_migration(tmp_path, monkeypatch) -> None:
    def broken(_step: str) -> None:
        raise BrokenPipeError

    monkeypatch.setattr(extension_control_host, "_verify_installed_bundle_early", lambda: None)
    store = _SlowStore(tmp_path, seconds=0.0)

    assert migrate_installed_authority(store, on_phase=broken) is True  # pyright: ignore[reportArgumentType]
    assert store.calls == 1


def test_the_early_bundle_check_waits_for_the_one_the_worker_host_started(monkeypatch) -> None:
    # The daemon's worker host starts the check before its imports; the
    # migration's early check then waits for it instead of loading again.
    from codex_plugin_scanner.guard.catalog_delivery import preparation_authority
    from codex_plugin_scanner.guard.cli import desktop_daemon_workers

    loads: list[str] = []
    release = threading.Event()
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: loads.append("load"))

    def started_check() -> None:
        release.wait(5)
        loads.append("early")

    early = threading.Thread(target=started_check, daemon=True)
    early.start()
    monkeypatch.setattr(desktop_daemon_workers, "_bundle_check", early)
    release.set()

    extension_control_host._verify_installed_bundle_early()

    assert loads == ["early"]
    # A later attempt checks for itself.
    extension_control_host._verify_installed_bundle_early()
    assert loads == ["early", "load"]


def test_a_migration_step_reaches_only_a_caller_that_listens(tmp_path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.catalog_delivery.installed_upgrade import report_migration_step

    monkeypatch.setattr(extension_control_host, "_verify_installed_bundle_early", lambda: None)

    def stepping() -> None:
        report_migration_step("candidate_prepared")

    store = SimpleNamespace(guard_home=tmp_path, migrate_installed_command_pack_authority=stepping)
    steps: list[str] = []

    # An extension-control host passes no reporter; its steps go nowhere.
    assert migrate_installed_authority(store, wait_seconds=0) is True  # pyright: ignore[reportArgumentType]
    assert migrate_installed_authority(store, wait_seconds=0.05, on_phase=steps.append) is True  # pyright: ignore[reportArgumentType]
    assert steps == ["bundle_checked", "turn_held", "candidate_prepared"]
    # Outside a migration a step is heard by no one and costs nothing.
    report_migration_step("catalog_migrated")
    assert steps == ["bundle_checked", "turn_held", "candidate_prepared"]


def test_a_reporter_that_fails_never_fails_the_migration(tmp_path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.catalog_delivery.installed_upgrade import report_migration_step

    monkeypatch.setattr(extension_control_host, "_verify_installed_bundle_early", lambda: None)
    finished: list[str] = []

    def stepping() -> None:
        report_migration_step("candidate_prepared")
        finished.append("migrated")

    def broken(step: str) -> None:
        raise BrokenPipeError(step)

    store = SimpleNamespace(guard_home=tmp_path, migrate_installed_command_pack_authority=stepping)

    assert migrate_installed_authority(store, wait_seconds=0.05, on_phase=broken) is True  # pyright: ignore[reportArgumentType]
    assert finished == ["migrated"]
