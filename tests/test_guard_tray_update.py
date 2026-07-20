"""Tests for update handoff: _stop_tray_for_update / _restart_tray_after_update.

Validates that updating the guard package correctly stops/restarts the
tray process and that errors are swallowed so the update proceeds.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from codex_plugin_scanner.guard.cli.update_commands import (
    _restart_tray_after_update,
    _stop_tray_for_update,
)
from codex_plugin_scanner.guard.tray.contracts import (
    TrayBackend,
    TrayCapability,
    TrayPlatform,
    TrayReasonCode,
)

_LT = "codex_plugin_scanner.guard.tray.lifecycle"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_store(guard_home: Path) -> MagicMock:
    """Return a mock GuardStore with a guard_home attribute."""
    store = MagicMock()
    store.guard_home = guard_home
    return store


def _make_locator() -> MagicMock:
    loc = MagicMock()
    loc.pid = 99
    return loc


def _make_capability(
    supported: bool = True,
    platform: TrayPlatform = TrayPlatform.MACOS,
    reason: TrayReasonCode = TrayReasonCode.NOT_RUNNING,
    backend: TrayBackend = TrayBackend.APPKIT,
) -> TrayCapability:
    return TrayCapability(
        platform=platform,
        backend=backend,
        supported=supported,
        reason=reason,
        details="test",
    )


# ---------------------------------------------------------------------------
# _stop_tray_for_update
# ---------------------------------------------------------------------------


class TestStopTrayForUpdate:
    def test_none_store_returns_false(self) -> None:
        """None store returns False without calling tray functions."""
        assert _stop_tray_for_update(None) is False

    def test_stop_tray_returns_true(self, tmp_path: Path) -> None:
        """Running tray is stopped and True is returned."""
        store = _make_store(tmp_path)
        mock_locator = _make_locator()

        with (
            patch(f"{_LT}.get_status", return_value=("running", _make_capability(), mock_locator)),
            patch(f"{_LT}.stop_tray", return_value=MagicMock(ok=True)),
        ):
            result = _stop_tray_for_update(store)

        assert result is True

    def test_stop_tray_returns_false_when_not_running(self, tmp_path: Path) -> None:
        """Non-running tray returns False without calling stop."""
        store = _make_store(tmp_path)

        with patch(f"{_LT}.get_status", return_value=("supported", _make_capability(), None)) as mock_get:
            result = _stop_tray_for_update(store)

        assert result is False
        mock_get.assert_called_once()

    def test_stop_tray_returns_false_when_no_locator(self, tmp_path: Path) -> None:
        """Running state but no locator returns False."""
        store = _make_store(tmp_path)

        with (
            patch(
                f"{_LT}.get_status",
                return_value=("running", _make_capability(), None),
            ) as mock_get,
            patch(f"{_LT}.stop_tray", return_value=MagicMock(ok=True)),
        ):
            result = _stop_tray_for_update(store)

        assert result is False
        mock_get.assert_called_once()

    def test_stop_tray_exception_swallowed(self, tmp_path: Path) -> None:
        """Exceptions during stop are swallowed and False is returned."""
        store = _make_store(tmp_path)

        with patch(f"{_LT}.get_status", side_effect=OSError("disaster")):
            result = _stop_tray_for_update(store)

        assert result is False

    def test_stop_tray_locator_stopped(self, tmp_path: Path) -> None:
        """Running tray with locator calls stop_tray."""
        store = _make_store(tmp_path)
        mock_locator = _make_locator()

        with patch(f"{_LT}.get_status", return_value=("running", _make_capability(), mock_locator)):  # noqa: SIM117
            with patch(f"{_LT}.stop_tray", return_value=MagicMock(ok=True)) as mock_stop:
                _stop_tray_for_update(store)

        mock_stop.assert_called_once()


# ---------------------------------------------------------------------------
# _restart_tray_after_update
# ---------------------------------------------------------------------------


class TestRestartTrayAfterUpdate:
    def test_none_store_returns_early(self) -> None:
        """None store returns early without calling tray functions."""
        _restart_tray_after_update(None)  # should not raise

    def test_start_tray_called(self, tmp_path: Path) -> None:
        """Running store calls start_tray."""
        store = _make_store(tmp_path)

        with patch(f"{_LT}.start_tray") as mock_start:
            _restart_tray_after_update(store)

        mock_start.assert_called_once_with(tmp_path)

    def test_exception_swallowed(self, tmp_path: Path) -> None:
        """Exceptions during restart are swallowed."""
        store = _make_store(tmp_path)

        with patch(f"{_LT}.start_tray", side_effect=OSError("fail")):
            _restart_tray_after_update(store)  # should not raise

    def test_non_interactive_update_continues_despite_tray_failure(self, tmp_path: Path) -> None:
        """Update should continue even if tray restart fails."""
        store = _make_store(tmp_path)

        with patch(f"{_LT}.start_tray", side_effect=OSError("disaster")):
            _restart_tray_after_update(store)  # No exception — update already succeeded.
