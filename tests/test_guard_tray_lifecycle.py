"""Tests for tray lifecycle orchestration: start, stop, status, repair.

Uses fake platform adapters and mocked subprocess/locator operations to
validate state transitions, crash recovery, and registration management
without spawning real tray processes.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.tray.contracts import (
    LOCATOR_SCHEMA_VERSION,
    MAX_CRASH_RETRIES,
    TrayBackend,
    TrayCapability,
    TrayLocator,
    TrayPlatform,
    TrayReasonCode,
    TrayState,
)
from codex_plugin_scanner.guard.tray.lifecycle import (
    get_status,
    repair_tray,
    start_tray,
    stop_tray,
)


def _capability(supported: bool = True, platform: TrayPlatform | None = TrayPlatform.MACOS) -> TrayCapability:
    return TrayCapability(
        platform=platform,
        backend=TrayBackend.APPKIT if supported else TrayBackend.NONE,
        supported=supported,
        reason=TrayReasonCode.OK if supported else TrayReasonCode.UNSUPPORTED_PLATFORM,
        details="test" if supported else "unsupported",
    )


def _write_locator(
    guard_home: Path,
    *,
    pid: int = 12345,
    crash_count: int = 0,
    backend: TrayBackend = TrayBackend.APPKIT,
) -> None:
    from codex_plugin_scanner.guard.tray.state import write_locator

    locator = TrayLocator(
        schema_version=LOCATOR_SCHEMA_VERSION,
        package_version="2.0.0",
        pid=pid,
        process_start_fingerprint="2024-01-01T00:00:00",
        executable="/usr/bin/python3",
        command="python3 -m hol-guard tray run",
        guard_home=str(guard_home),
        backend=backend,
        registration_generation=1,
        last_ready=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
        crash_count=crash_count,
        last_crash=None,
    )
    write_locator(guard_home, locator)


class FakeAdapter:
    """Fake platform adapter for testing."""

    def __init__(self, *, start_succeeds: bool = True, stop_succeeds: bool = True) -> None:
        self.start_succeeds = start_succeeds
        self.stop_succeeds = stop_succeeds
        self.start_calls: list[dict[str, object]] = []
        self.stop_calls: list[dict[str, object]] = []
        self._next_pid = 54321

    def start_process(self, *, guard_home: Path, capability: TrayCapability) -> dict[str, object]:
        pid = self._next_pid
        self._next_pid += 1
        self.start_calls.append({"guard_home": guard_home, "capability": capability, "pid": pid})
        if not self.start_succeeds:
            return {"started": False, "reason": "internal_error", "message": "fake failure"}
        # Simulate the process writing its locator
        _write_locator(guard_home, pid=pid)
        return {"started": True, "pid": pid}

    def stop_process(self, *, pid: int) -> dict[str, object]:
        self.stop_calls.append({"pid": pid})
        if not self.stop_succeeds:
            return {"stopped": False, "reason": "internal_error"}
        return {"stopped": True}

    def detect_capability(self) -> TrayCapability:
        return _capability()

    def inspect_registration(self, *, guard_home: Path) -> dict[str, object]:
        return {"installed": False}

    def install_registration(
        self, *, guard_home: Path, capability: TrayCapability, run_at_login: bool
    ) -> dict[str, object]:
        return {"installed": True, "path": "/fake/registration"}

    def remove_registration(self, *, guard_home: Path) -> dict[str, object]:
        return {"removed": True}

    def is_process_running(self, *, pid: int) -> bool:
        return False


class TestGetStatus:
    def test_no_locator_returns_supported(self, tmp_path: Path) -> None:
        with patch(
            "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
            return_value=_capability(),
        ):
            state, cap, locator = get_status(tmp_path)
        assert state == TrayState.SUPPORTED
        assert cap.supported is True
        assert locator is None

    def test_unsupported_platform(self, tmp_path: Path) -> None:
        with patch(
            "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
            return_value=_capability(supported=False),
        ):
            state, _cap, locator = get_status(tmp_path)
        assert state == TrayState.UNSUPPORTED
        assert locator is None

    def test_running_tray(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=os.getpid())
        with (
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
                return_value=_capability(),
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.is_process_alive",
                return_value=True,
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.process_start_fingerprint",
                return_value="2024-01-01T00:00:00",
            ),
        ):
            state, _cap, locator = get_status(tmp_path)
        assert state == TrayState.RUNNING
        assert locator is not None
        assert locator.pid == os.getpid()

    def test_stale_locator(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=999999)
        with patch(
            "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
            return_value=_capability(),
        ):
            state, _cap, locator = get_status(tmp_path)
        assert state == TrayState.STALE
        assert locator is not None

    def test_malformed_locator(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.state import ensure_locator_dir

        directory = ensure_locator_dir(tmp_path)
        (directory / "locator.json").write_text("not json{", encoding="utf-8")
        with patch(
            "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
            return_value=_capability(),
        ):
            state, _cap, _locator = get_status(tmp_path)
        assert state == TrayState.REPAIR_REQUIRED

    def test_crash_loop(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=os.getpid(), crash_count=MAX_CRASH_RETRIES)
        with (
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
                return_value=_capability(),
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.is_process_alive",
                return_value=True,
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.process_start_fingerprint",
                return_value="2024-01-01T00:00:00",
            ),
        ):
            state, _cap, _locator = get_status(tmp_path)
        assert state == TrayState.REPAIR_REQUIRED


class TestStartTray:
    def test_unsupported_platform(self, tmp_path: Path) -> None:
        with patch(
            "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
            return_value=_capability(supported=False),
        ):
            result = start_tray(tmp_path)
        assert result.ok is False
        assert result.state == TrayState.UNSUPPORTED

    def test_already_running(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=os.getpid())
        with (
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
                return_value=_capability(),
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.is_process_alive",
                return_value=True,
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.process_start_fingerprint",
                return_value="2024-01-01T00:00:00",
            ),
        ):
            result = start_tray(tmp_path)
        assert result.ok is True
        assert result.reason == TrayReasonCode.ALREADY_RUNNING

    def test_crash_loop_blocks_start(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=999999, crash_count=MAX_CRASH_RETRIES)
        with patch(
            "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
            return_value=_capability(),
        ):
            result = start_tray(tmp_path)
        assert result.ok is False
        assert result.reason == TrayReasonCode.CRASH_LOOP_DETECTED
        assert result.state == TrayState.REPAIR_REQUIRED

    def test_start_via_adapter(self, tmp_path: Path) -> None:
        adapter = FakeAdapter()
        with (
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
                return_value=_capability(),
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.is_process_alive",
                return_value=True,
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.process_start_fingerprint",
                return_value="2024-01-01T00:00:00",
            ),
        ):
            result = start_tray(tmp_path, adapter=adapter)
        assert result.ok is True
        assert result.state == TrayState.RUNNING
        assert result.reason == TrayReasonCode.OK
        assert len(adapter.start_calls) == 1

    def test_adapter_start_failure(self, tmp_path: Path) -> None:
        adapter = FakeAdapter(start_succeeds=False)
        with patch(
            "codex_plugin_scanner.guard.tray.lifecycle.detect_capability",
            return_value=_capability(),
        ):
            result = start_tray(tmp_path, adapter=adapter)
        assert result.ok is False
        assert result.state == TrayState.FAILED

    def test_force_stops_existing(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=os.getpid())
        adapter = FakeAdapter()
        # is_process_alive: True (initial check in get_status), then False
        # (after stop_tray kills it, the wait loop sees it's dead).
        with (
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.is_process_alive",
                side_effect=[True, False],
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.is_process_alive",
                side_effect=[True, False],
            ),
            patch(
                "codex_plugin_scanner.guard.tray.state.process_start_fingerprint",
                return_value="2024-01-01T00:00:00",
            ),
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.locator_is_stale",
                return_value=False,
            ),
        ):
            result = start_tray(tmp_path, force=True, adapter=adapter)
        assert result.ok is True
        assert result.state == TrayState.RUNNING


class TestStopTray:
    def test_stop_via_adapter(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=12345)
        adapter = FakeAdapter()
        # is_process_alive calls: initial check=True, then wait loop=False.
        # locator_is_stale must be mocked False — the fake PID 12345 is not
        # a real process, so its fingerprint would not match and the new
        # PID-reuse safety guard would short-circuit to NOT_RUNNING.
        with (
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.is_process_alive",
                side_effect=[True, False],
            ),
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.locator_is_stale",
                return_value=False,
            ),
        ):
            result = stop_tray(tmp_path, adapter=adapter)
        assert result.ok is True
        assert result.reason == TrayReasonCode.OK
        assert len(adapter.stop_calls) == 1

    def test_dead_process_cleans_locator(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=999999)
        with patch("codex_plugin_scanner.guard.tray.state.is_process_alive", return_value=False):
            result = stop_tray(tmp_path)
        assert result.ok is True
        assert result.reason == TrayReasonCode.NOT_RUNNING

    def test_no_locator(self, tmp_path: Path) -> None:
        result = stop_tray(tmp_path)
        assert result.ok is True
        assert result.reason == TrayReasonCode.NOT_RUNNING

    def test_malformed_locator(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.state import ensure_locator_dir

        directory = ensure_locator_dir(tmp_path)
        (directory / "locator.json").write_text("not json{", encoding="utf-8")
        result = stop_tray(tmp_path)
        assert result.ok is False
        assert result.reason == TrayReasonCode.LOCATOR_MALFORMED

    def test_pid_reuse_does_not_kill_wrong_process(self, tmp_path: Path) -> None:
        """If the locator's PID was recycled to an unrelated process, stop_tray
        must NOT signal the foreign process — it should clean up the stale
        locator and return NOT_RUNNING instead."""
        _write_locator(tmp_path, pid=os.getpid())
        # is_process_alive=True (pid exists) but locator_is_stale=True (fingerprint
        # mismatch — PID was reused). The safety guard must short-circuit.
        with (
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.is_process_alive",
                return_value=True,
            ),
            patch(
                "codex_plugin_scanner.guard.tray.lifecycle.locator_is_stale",
                return_value=True,
            ),
        ):
            result = stop_tray(tmp_path)
        assert result.ok is True
        assert result.reason == TrayReasonCode.NOT_RUNNING
        assert "no signal sent" in result.message
        # Locator should be cleaned up
        from codex_plugin_scanner.guard.tray.state import read_locator

        assert read_locator(tmp_path) is None


class TestRepairTray:
    def test_repair_cleans_state(self, tmp_path: Path) -> None:
        _write_locator(tmp_path, pid=999999, crash_count=MAX_CRASH_RETRIES)
        result = repair_tray(tmp_path)
        assert result.ok is True
        assert result.state == TrayState.ABSENT
        # Locator should be removed
        from codex_plugin_scanner.guard.tray.state import read_locator

        assert read_locator(tmp_path) is None

    def test_repair_when_clean(self, tmp_path: Path) -> None:
        result = repair_tray(tmp_path)
        assert result.ok is True
        assert result.state == TrayState.ABSENT

    def test_repair_after_malformed(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.state import ensure_locator_dir

        directory = ensure_locator_dir(tmp_path)
        (directory / "locator.json").write_text("not json{", encoding="utf-8")
        result = repair_tray(tmp_path)
        assert result.ok is True
        # Malformed file should be removed by repair
        from codex_plugin_scanner.guard.tray.state import read_locator

        assert read_locator(tmp_path) is None
