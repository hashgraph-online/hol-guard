"""Tests for ``hol-guard tray`` CLI subcommand dispatch.

Validates status JSON output, start/stop/repair return codes, unknown
subcommand handling, ``--json`` flag producing valid JSON, and ``tray run``
with ``--guard-home`` writing the locator file.

All tray functions are dynamically imported inside the function body at
runtime, so tests patch them at their source modules, not on
``commands_dispatch_local``.

NOTE: ``_emit`` is imported via a ``TYPE_CHECKING`` block that does not
execute at runtime. Tests inject it into the module namespace before
calling ``_run_guard_tray_command``.
"""

from __future__ import annotations

import argparse
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from codex_plugin_scanner.guard.cli.commands_dispatch_local import (
    _run_guard_tray_command,
)
from codex_plugin_scanner.guard.tray.contracts import (
    TrayBackend,
    TrayCapability,
    TrayPlatform,
    TrayReasonCode,
    TrayState,
)

# Source modules — names are dynamically imported inside the function at
# lines 451-520 of commands_dispatch_local.py.
_LC = "codex_plugin_scanner.guard.cli._commands_shared"
_LT = "codex_plugin_scanner.guard.tray.lifecycle"
_ST = "codex_plugin_scanner.guard.tray.state"
_RT = "codex_plugin_scanner.guard.tray.runtime"
_CDL = "codex_plugin_scanner.guard.cli.commands_dispatch_local"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tray_args(subcommand: str, **overrides: object) -> argparse.Namespace:
    """Build an argparse.Namespace mimicking a parsed ``tray`` subcommand."""
    attrs: dict[str, object] = {"tray_command": subcommand}
    if "json" in overrides or overrides.get("json") is not None:
        attrs["json"] = overrides.pop("json")
    if "guard_home" in overrides or overrides.get("guard_home") is not None:
        attrs["guard_home"] = overrides.pop("guard_home")
    if "force" in overrides or overrides.get("force") is not None:
        attrs["force"] = overrides.pop("force")
    attrs.update(overrides)
    return argparse.Namespace(**attrs)


def _make_capability(
    supported: bool = True,
    platform: TrayPlatform | None = TrayPlatform.MACOS,
    reason: TrayReasonCode = TrayReasonCode.NOT_RUNNING,
    backend: TrayBackend = TrayBackend.APPKIT,
) -> TrayCapability:
    """Build a TrayCapability for testing."""
    return TrayCapability(
        platform=platform,
        backend=backend,
        supported=supported,
        reason=reason,
        details="test",
    )


def _inject_emit() -> MagicMock:
    """Inject a mock ``_emit`` into the CDL module namespace.

    ``_emit`` lives in a ``TYPE_CHECKING`` block so it is absent at runtime.
    Patching the module's ``__dict__`` makes it resolvable as a closure
    variable inside ``_run_guard_tray_command``.
    """
    import importlib

    mod = importlib.import_module(_CDL)
    mock = MagicMock()
    mod.__dict__["_emit"] = mock
    return mock


# ---------------------------------------------------------------------------
# Status subcommand
# ---------------------------------------------------------------------------


class TestTrayStatus:
    def test_status_json_has_required_fields(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_cap = _make_capability(supported=True, reason=TrayReasonCode.NOT_RUNNING, backend=TrayBackend.APPKIT)
        mock_emit = _inject_emit()

        with (
            patch(f"{_ST}.read_locator", return_value=None),
            patch(f"{_LT}.get_status", return_value=(TrayState.SUPPORTED, mock_cap, None)),
            patch(f"{_RT}.detect_capability", return_value=mock_cap),
        ):
            rc = _run_guard_tray_command(
                _make_tray_args("status", json=True),
                guard_home=guard_home,
            )

        assert rc == 0
        args = mock_emit.call_args
        assert args is not None
        command_name, payload = args[0][0], args[0][1]
        assert command_name == "tray-status"
        assert "state" in payload
        assert "supported" in payload
        assert "platform" in payload

    def test_status_non_json(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_cap = _make_capability(supported=True, reason=TrayReasonCode.NOT_RUNNING, backend=TrayBackend.APPKIT)
        mock_emit = _inject_emit()

        with (
            patch(f"{_LT}.get_status", return_value=(TrayState.SUPPORTED, mock_cap, None)),
            patch(f"{_RT}.detect_capability", return_value=mock_cap),
            patch(f"{_ST}.read_locator", return_value=None),
        ):
            rc = _run_guard_tray_command(
                _make_tray_args("status"),
                guard_home=guard_home,
            )

        assert rc == 0
        assert mock_emit.called

    def test_status_with_locator(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_cap = _make_capability(supported=True, reason=TrayReasonCode.NOT_RUNNING, backend=TrayBackend.APPKIT)
        mock_locator = MagicMock()
        mock_locator.to_payload.return_value = {"pid": 99, "guard_home": str(guard_home)}
        mock_emit = _inject_emit()

        with (
            patch(f"{_LT}.get_status", return_value=(TrayState.RUNNING, mock_cap, mock_locator)),
            patch(f"{_RT}.detect_capability", return_value=mock_cap),
        ):
            rc = _run_guard_tray_command(
                _make_tray_args("status", json=True),
                guard_home=guard_home,
            )

        assert rc == 0
        payload = mock_emit.call_args[0][1]
        assert payload["state"] == "running"
        assert payload["locator"] == {"pid": 99, "guard_home": str(guard_home)}


# ---------------------------------------------------------------------------
# Start subcommand
# ---------------------------------------------------------------------------


class TestTrayStart:
    def test_start_returns_ok_state(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.state = TrayState.RUNNING
        mock_result.reason = TrayReasonCode.NOT_RUNNING
        mock_result.message = "tray started"
        mock_result.recovery_command = ""
        mock_emit = _inject_emit()

        with patch(f"{_LT}.start_tray", return_value=mock_result):
            rc = _run_guard_tray_command(
                _make_tray_args("start", json=True),
                guard_home=guard_home,
            )

        assert rc == 0
        payload = mock_emit.call_args[0][1]
        assert payload["ok"] is True
        assert payload["state"] == "running"

    def test_start_failure_returns_nonzero(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_result = MagicMock()
        mock_result.ok = False
        mock_result.state = TrayState.FAILED
        mock_result.reason = TrayReasonCode.INTERNAL_ERROR
        mock_result.message = "start failed"
        mock_result.recovery_command = ""
        mock_emit = _inject_emit()

        with patch(f"{_LT}.start_tray", return_value=mock_result):
            rc = _run_guard_tray_command(
                _make_tray_args("start", json=True),
                guard_home=guard_home,
            )

        assert rc == 1
        payload = mock_emit.call_args[0][1]
        assert payload["ok"] is False


# ---------------------------------------------------------------------------
# Stop subcommand
# ---------------------------------------------------------------------------


class TestTrayStop:
    def test_stop_returns_ok_state(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.state = TrayState.STOPPING
        mock_result.reason = TrayReasonCode.NOT_RUNNING
        mock_result.message = "tray stopped"
        mock_result.recovery_command = ""
        mock_emit = _inject_emit()

        with patch(f"{_LT}.stop_tray", return_value=mock_result):
            rc = _run_guard_tray_command(
                _make_tray_args("stop", json=True),
                guard_home=guard_home,
            )

        assert rc == 0
        payload = mock_emit.call_args[0][1]
        assert payload["ok"] is True
        assert payload["state"] == "stopping"


# ---------------------------------------------------------------------------
# Repair subcommand
# ---------------------------------------------------------------------------


class TestTrayRepair:
    def test_repair_returns_ok_true(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.state = TrayState.RUNNING
        mock_result.reason = TrayReasonCode.NOT_RUNNING
        mock_result.message = "tray repaired"
        mock_result.recovery_command = ""
        mock_emit = _inject_emit()

        with patch(f"{_LT}.repair_tray", return_value=mock_result):
            rc = _run_guard_tray_command(
                _make_tray_args("repair", json=True),
                guard_home=guard_home,
            )

        assert rc == 0
        payload = mock_emit.call_args[0][1]
        assert payload["ok"] is True


# ---------------------------------------------------------------------------
# Unknown subcommand
# ---------------------------------------------------------------------------


class TestTrayUnknownCommand:
    def test_unknown_subcommand_returns_error(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        buf = StringIO()
        old = sys.stderr
        sys.stderr = buf
        try:
            rc = _run_guard_tray_command(
                _make_tray_args("fizzbuzz"),
                guard_home=guard_home,
            )
        finally:
            sys.stderr = old

        assert rc == 2
        assert "Unknown tray command: fizzbuzz" in buf.getvalue()


# ---------------------------------------------------------------------------
# --json flag
# ---------------------------------------------------------------------------


class TestJsonFlag:
    def test_json_produces_valid_json(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.state = TrayState.RUNNING
        mock_result.reason = TrayReasonCode.NOT_RUNNING
        mock_result.message = "ok"
        mock_result.recovery_command = ""
        mock_emit = _inject_emit()

        captured: list[str] = []

        def capture_emit(command: str, payload: dict, as_json: bool) -> None:
            if as_json:
                captured.append(json.dumps(payload))

        mock_emit.side_effect = capture_emit

        with patch(f"{_LT}.start_tray", return_value=mock_result):
            _run_guard_tray_command(
                _make_tray_args("start", json=True),
                guard_home=guard_home,
            )

        assert len(captured) == 1
        parsed = json.loads(captured[0])
        assert isinstance(parsed, dict)
        assert "ok" in parsed
        assert "state" in parsed


# ---------------------------------------------------------------------------
# Run subcommand
# ---------------------------------------------------------------------------


class TestTrayRun:
    def test_run_with_guard_home_writes_locator(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_runtime = MagicMock()
        mock_runtime.run.return_value = 0
        mock_locator = MagicMock()

        with (
            patch(f"{_RT}.TrayRuntime", return_value=mock_runtime),
            patch(f"{_RT}.detect_capability", return_value=_make_capability()),
            patch(f"{_ST}.build_locator_for_current_process", return_value=mock_locator),
            patch(f"{_ST}.write_locator") as mock_write,
            patch(f"{_ST}.reset_crash_count"),
            patch(f"{_CDL}._require_guard_config", return_value=MagicMock()),
            patch(f"{_CDL}._require_guard_store", return_value=MagicMock()),
        ):
            rc = _run_guard_tray_command(
                _make_tray_args("run", guard_home=str(guard_home)),
                guard_home=guard_home,
            )

        assert rc == 0
        assert mock_write.called
        write_call = mock_write.call_args
        assert write_call is not None
        assert write_call[0][0] == guard_home
        assert write_call[0][1] is mock_locator

    def test_run_without_guard_home_raises(self) -> None:
        """When guard_home parameter is None, the function raises RuntimeError."""
        with pytest.raises(RuntimeError, match="Guard home is required"):
            _run_guard_tray_command(
                _make_tray_args("run"),
                guard_home=None,
            )

    def test_run_calls_runtime_run_and_cleans_up(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()

        mock_runtime = MagicMock()
        mock_runtime.run.return_value = 0
        mock_locator = MagicMock()

        with (
            patch(f"{_RT}.TrayRuntime", return_value=mock_runtime),
            patch(f"{_RT}.detect_capability", return_value=_make_capability()),
            patch(f"{_ST}.build_locator_for_current_process", return_value=mock_locator),
            patch(f"{_ST}.write_locator"),
            patch(f"{_ST}.reset_crash_count"),
            patch(f"{_ST}.remove_locator") as mock_remove,
            patch(f"{_CDL}._require_guard_config", return_value=MagicMock()),
            patch(f"{_CDL}._require_guard_store", return_value=MagicMock()),
        ):
            _run_guard_tray_command(
                _make_tray_args("run", guard_home=str(guard_home)),
                guard_home=guard_home,
            )

        mock_runtime.run.assert_called_once()
        assert mock_remove.called


# ---------------------------------------------------------------------------
# Guard home required
# ---------------------------------------------------------------------------


class TestGuardHomeRequired:
    def test_raises_when_guard_home_none(self) -> None:
        with pytest.raises(RuntimeError, match="Guard home is required"):
            _run_guard_tray_command(
                _make_tray_args("status"),
                guard_home=None,
            )
