"""Tests for tray state persistence: locator file, crash tracking, staleness.

Validates atomic writes, schema validation, stale process detection,
crash counter increment/reset, and crash-loop detection. All file
operations use ``tmp_path`` for isolation.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.tray.contracts import (
    CRASH_LOOP_WINDOW_SECONDS,
    LOCATOR_SCHEMA_VERSION,
    MAX_CRASH_RETRIES,
    TrayBackend,
    TrayLocator,
    utcnow,
)
from codex_plugin_scanner.guard.tray.state import (
    build_locator_for_current_process,
    crash_loop_detected,
    ensure_locator_dir,
    is_process_alive,
    locator_is_stale,
    locator_path,
    read_locator,
    record_crash,
    remove_locator,
    reset_crash_count,
    write_locator,
)


class TestLocatorPath:
    def test_path_under_guard_home(self, tmp_path: Path) -> None:
        path = locator_path(tmp_path)
        assert path == tmp_path / "tray" / "locator.json"

    def test_ensure_dir_creates_directory(self, tmp_path: Path) -> None:
        directory = ensure_locator_dir(tmp_path)
        assert directory.is_dir()
        assert directory == tmp_path / "tray"


class TestWriteAndReadLocator:
    def _locator(self, guard_home: Path, **overrides: object) -> TrayLocator:
        defaults: dict[str, object] = {
            "schema_version": LOCATOR_SCHEMA_VERSION,
            "package_version": "2.0.0",
            "pid": 12345,
            "process_start_fingerprint": "2024-01-01T00:00:00",
            "executable": "/usr/bin/python3",
            "command": "python3 -m hol-guard tray run",
            "guard_home": str(guard_home),
            "backend": TrayBackend.APPKIT,
            "registration_generation": 1,
            "last_ready": datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
            "crash_count": 0,
            "last_crash": None,
        }
        defaults.update(overrides)
        return TrayLocator(**defaults)  # type: ignore[arg-type]

    def test_round_trip(self, tmp_path: Path) -> None:
        locator = self._locator(tmp_path)
        write_locator(tmp_path, locator)
        read = read_locator(tmp_path)
        assert read is not None
        assert read.pid == 12345
        assert read.backend == TrayBackend.APPKIT
        assert read.schema_version == LOCATOR_SCHEMA_VERSION

    def test_file_permissions_are_restricted(self, tmp_path: Path) -> None:
        if os.name == "nt":
            pytest.skip("POSIX-only permission test")
        locator = self._locator(tmp_path)
        write_locator(tmp_path, locator)
        path = locator_path(tmp_path)
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"

    def test_atomic_write_no_partial_file(self, tmp_path: Path) -> None:
        locator = self._locator(tmp_path)
        write_locator(tmp_path, locator)
        # No temp files left behind
        directory = tmp_path / "tray"
        leftovers = [p for p in directory.iterdir() if p.name.startswith(".locator.json")]
        assert leftovers == []

    def test_read_missing_returns_none(self, tmp_path: Path) -> None:
        assert read_locator(tmp_path) is None

    def test_read_malformed_raises(self, tmp_path: Path) -> None:
        directory = ensure_locator_dir(tmp_path)
        (directory / "locator.json").write_text("not json{", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            read_locator(tmp_path)

    def test_read_non_object_raises(self, tmp_path: Path) -> None:
        directory = ensure_locator_dir(tmp_path)
        (directory / "locator.json").write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(ValueError, match="not an object"):
            read_locator(tmp_path)

    def test_write_overwrites_existing(self, tmp_path: Path) -> None:
        locator1 = self._locator(tmp_path, pid=11111)
        write_locator(tmp_path, locator1)
        locator2 = self._locator(tmp_path, pid=22222)
        write_locator(tmp_path, locator2)
        read = read_locator(tmp_path)
        assert read is not None
        assert read.pid == 22222

    def test_payload_has_no_secrets(self, tmp_path: Path) -> None:
        # Use a clean temp dir — pytest embeds the test name (which
        # contains "secret") in tmp_path, which would false-positive.
        import tempfile

        guard_home = Path(tempfile.mkdtemp(prefix="guard-home-"))
        try:
            locator = self._locator(guard_home)
            write_locator(guard_home, locator)
            path = locator_path(guard_home)
            content = path.read_text(encoding="utf-8")
            assert "token" not in content.lower()
            assert "secret" not in content.lower()
            assert "password" not in content.lower()
            assert "fragment" not in content.lower()
        finally:
            import shutil

            shutil.rmtree(guard_home, ignore_errors=True)


class TestRemoveLocator:
    def test_remove_existing(self, tmp_path: Path) -> None:
        locator = TrayLocator(
            schema_version=LOCATOR_SCHEMA_VERSION,
            package_version="2.0.0",
            pid=12345,
            process_start_fingerprint="2024-01-01T00:00:00",
            executable="/usr/bin/python3",
            command="python3 -m hol-guard tray run",
            guard_home=str(tmp_path),
            backend=TrayBackend.APPKIT,
            registration_generation=1,
            last_ready=None,
            crash_count=0,
            last_crash=None,
        )
        write_locator(tmp_path, locator)
        assert remove_locator(tmp_path) is True
        assert not locator_path(tmp_path).exists()

    def test_remove_missing_returns_false(self, tmp_path: Path) -> None:
        assert remove_locator(tmp_path) is False


class TestIsProcessAlive:
    def test_current_process_is_alive(self) -> None:
        assert is_process_alive(os.getpid()) is True

    def test_invalid_pid_returns_false(self) -> None:
        assert is_process_alive(0) is False
        assert is_process_alive(-1) is False

    def test_dead_pid_returns_false(self) -> None:
        # PID 1 is init on Linux/macOS, but on macOS it's launchd and alive.
        # Use a very high PID that is almost certainly not in use.
        assert is_process_alive(999999) is False

    def test_windows_tasklist_exact_pid_match(self) -> None:
        """On Windows, tasklist /FO CSV /NH emits rows as
        \"image\",\"PID\",\"session\",... — the PID is at field index 1.
        Verify we parse field 1 (not field 0, which is the image name)
        and require an exact match (no substring false positives)."""
        from unittest.mock import patch

        # tasklist output for PID 1234 — PID is in field 1
        csv_output = '"python.exe","1234","Console","1","24,576 K"\r\n'
        with patch("os.name", "nt"), patch("subprocess.run") as mock_run:
            mock_run.return_value = type(
                "R",
                (),
                {"stdout": csv_output, "returncode": 0},
            )()
            # Exact match on PID 1234
            assert is_process_alive(1234) is True
            # Substring must NOT match: PID 123 is not PID 1234
            assert is_process_alive(123) is False
            # PID 234 is not 1234 either
            assert is_process_alive(234) is False

    def test_windows_tasklist_no_match_info_line(self) -> None:
        """When no process matches, tasklist emits an INFO: line (single
        field, no PID) — must return False."""
        from unittest.mock import patch

        info_output = "INFO: No tasks are running which match the specified criteria.\r\n"
        with patch("os.name", "nt"), patch("subprocess.run") as mock_run:
            mock_run.return_value = type(
                "R",
                (),
                {"stdout": info_output, "returncode": 0},
            )()
            assert is_process_alive(12345) is False

    def test_windows_tasklist_empty_output(self) -> None:
        from unittest.mock import patch

        with patch("os.name", "nt"), patch("subprocess.run") as mock_run:
            mock_run.return_value = type(
                "R",
                (),
                {"stdout": "", "returncode": 0},
            )()
            assert is_process_alive(12345) is False


class TestLocatorStaleness:
    def _locator(self, guard_home: Path, pid: int, fingerprint: str | None) -> TrayLocator:
        return TrayLocator(
            schema_version=LOCATOR_SCHEMA_VERSION,
            package_version="2.0.0",
            pid=pid,
            process_start_fingerprint=fingerprint,
            executable="/usr/bin/python3",
            command="python3 -m hol-guard tray run",
            guard_home=str(guard_home),
            backend=TrayBackend.APPKIT,
            registration_generation=1,
            last_ready=None,
            crash_count=0,
            last_crash=None,
        )

    def test_invalid_pid_is_stale(self, tmp_path: Path) -> None:
        locator = self._locator(tmp_path, pid=0, fingerprint="x")
        assert locator_is_stale(locator) is True

    def test_dead_pid_is_stale(self, tmp_path: Path) -> None:
        locator = self._locator(tmp_path, pid=999999, fingerprint="x")
        assert locator_is_stale(locator) is True

    def test_current_process_not_stale(self, tmp_path: Path) -> None:
        # Current process is alive; fingerprint may or may not match but
        # the process is definitely not stale by liveness alone.
        locator = self._locator(tmp_path, pid=os.getpid(), fingerprint=None)
        # With no fingerprint, staleness depends only on liveness
        assert locator_is_stale(locator) is False

    def test_fingerprint_mismatch_is_stale(self, tmp_path: Path) -> None:
        locator = self._locator(tmp_path, pid=os.getpid(), fingerprint="old-fingerprint")
        # The current process's fingerprint won't match "old-fingerprint"
        with patch("codex_plugin_scanner.guard.tray.state.process_start_fingerprint", return_value="new-fingerprint"):
            assert locator_is_stale(locator) is True

    def test_fingerprint_match_not_stale(self, tmp_path: Path) -> None:
        locator = self._locator(tmp_path, pid=os.getpid(), fingerprint="matching-fingerprint")
        with patch(
            "codex_plugin_scanner.guard.tray.state.process_start_fingerprint",
            return_value="matching-fingerprint",
        ):
            assert locator_is_stale(locator) is False


class TestCrashTracking:
    def _write_locator(self, guard_home: Path, crash_count: int = 0) -> None:
        locator = TrayLocator(
            schema_version=LOCATOR_SCHEMA_VERSION,
            package_version="2.0.0",
            pid=12345,
            process_start_fingerprint="2024-01-01T00:00:00",
            executable="/usr/bin/python3",
            command="python3 -m hol-guard tray run",
            guard_home=str(guard_home),
            backend=TrayBackend.APPKIT,
            registration_generation=1,
            last_ready=None,
            crash_count=crash_count,
            last_crash=None,
        )
        write_locator(guard_home, locator)

    def test_record_crash_increments(self, tmp_path: Path) -> None:
        self._write_locator(tmp_path, crash_count=2)
        new_count = record_crash(tmp_path)
        assert new_count == 3
        locator = read_locator(tmp_path)
        assert locator is not None
        assert locator.crash_count == 3
        assert locator.last_crash is not None

    def test_record_crash_starts_from_missing(self, tmp_path: Path) -> None:
        new_count = record_crash(tmp_path)
        assert new_count == 1
        locator = read_locator(tmp_path)
        assert locator is not None
        assert locator.crash_count == 1

    def test_record_crash_from_malformed(self, tmp_path: Path) -> None:
        directory = ensure_locator_dir(tmp_path)
        (directory / "locator.json").write_text("not json{", encoding="utf-8")
        new_count = record_crash(tmp_path)
        assert new_count == 1

    def test_crash_loop_detected_at_limit(self, tmp_path: Path) -> None:
        self._write_locator(tmp_path, crash_count=MAX_CRASH_RETRIES)
        assert crash_loop_detected(tmp_path) is True

    def test_crash_loop_not_detected_below_limit(self, tmp_path: Path) -> None:
        self._write_locator(tmp_path, crash_count=MAX_CRASH_RETRIES - 1)
        assert crash_loop_detected(tmp_path) is False

    def test_crash_loop_not_detected_when_missing(self, tmp_path: Path) -> None:
        assert crash_loop_detected(tmp_path) is False

    def test_crash_loop_window_expires(self, tmp_path: Path) -> None:
        """Crashes older than ``CRASH_LOOP_WINDOW_SECONDS`` must NOT trigger
        loop detection — a tray that crashed weeks ago should be allowed to
        start again, not be permanently blocked."""
        from datetime import timedelta

        old_crash = utcnow() - timedelta(seconds=CRASH_LOOP_WINDOW_SECONDS + 3600)
        locator = TrayLocator(
            schema_version=LOCATOR_SCHEMA_VERSION,
            package_version="2.0.0",
            pid=12345,
            process_start_fingerprint="2024-01-01T00:00:00",
            executable="/usr/bin/python3",
            command="python3 -m hol-guard tray run",
            guard_home=str(tmp_path),
            backend=TrayBackend.APPKIT,
            registration_generation=1,
            last_ready=None,
            crash_count=MAX_CRASH_RETRIES,
            last_crash=old_crash,
        )
        write_locator(tmp_path, locator)
        assert crash_loop_detected(tmp_path) is False

    def test_crash_loop_within_window_triggers(self, tmp_path: Path) -> None:
        """A recent crash (within the window) at the limit triggers loop detection."""
        from datetime import timedelta

        recent_crash = utcnow() - timedelta(seconds=60)
        locator = TrayLocator(
            schema_version=LOCATOR_SCHEMA_VERSION,
            package_version="2.0.0",
            pid=12345,
            process_start_fingerprint="2024-01-01T00:00:00",
            executable="/usr/bin/python3",
            command="python3 -m hol-guard tray run",
            guard_home=str(tmp_path),
            backend=TrayBackend.APPKIT,
            registration_generation=1,
            last_ready=None,
            crash_count=MAX_CRASH_RETRIES,
            last_crash=recent_crash,
        )
        write_locator(tmp_path, locator)
        assert crash_loop_detected(tmp_path) is True

    def test_reset_crash_count(self, tmp_path: Path) -> None:
        self._write_locator(tmp_path, crash_count=3)
        reset_crash_count(tmp_path)
        locator = read_locator(tmp_path)
        assert locator is not None
        assert locator.crash_count == 0
        assert locator.last_crash is None

    def test_reset_when_already_zero_is_noop(self, tmp_path: Path) -> None:
        self._write_locator(tmp_path, crash_count=0)
        reset_crash_count(tmp_path)
        locator = read_locator(tmp_path)
        assert locator is not None
        assert locator.crash_count == 0

    def test_reset_when_missing_is_noop(self, tmp_path: Path) -> None:
        reset_crash_count(tmp_path)
        assert read_locator(tmp_path) is None


class TestBuildLocatorForCurrentProcess:
    def test_builds_with_current_pid(self, tmp_path: Path) -> None:
        locator = build_locator_for_current_process(
            guard_home=tmp_path,
            package_version="2.0.0",
            backend=TrayBackend.APPKIT,
        )
        assert locator.pid == os.getpid()
        assert locator.schema_version == LOCATOR_SCHEMA_VERSION
        assert locator.backend == TrayBackend.APPKIT
        assert locator.guard_home == str(tmp_path)
        assert locator.crash_count == 0
        assert locator.last_crash is None
        assert locator.last_ready is not None

    def test_builds_with_registration_generation(self, tmp_path: Path) -> None:
        locator = build_locator_for_current_process(
            guard_home=tmp_path,
            package_version="2.0.0",
            backend=TrayBackend.WIN32,
            registration_generation=5,
        )
        assert locator.registration_generation == 5
        assert locator.backend == TrayBackend.WIN32

    def test_command_includes_guard_home(self, tmp_path: Path) -> None:
        """The stored command line must include ``--guard-home`` so that
        ``TrayProcessIdentity.matches()`` (which compares command) can
        distinguish tray instances for different guard homes."""
        locator = build_locator_for_current_process(
            guard_home=tmp_path,
            package_version="2.0.0",
            backend=TrayBackend.APPKIT,
        )
        assert "--guard-home" in locator.command
        assert str(tmp_path) in locator.command
