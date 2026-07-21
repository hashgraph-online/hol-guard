"""Tests for guard.app.update and guard.app.updateCheck command executors."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime.command_executors import (
    APP_OPERATIONS,
    execute_guard_command_job,
)


def _make_context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard",
    )


def _make_job(operation: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "id": "job-1",
        "operation": operation,
        "operationSchemaVersion": 1,
        "payload": payload or {},
    }


class _FakeStore:
    """Minimal fake store with get_sync_payload/set_sync_payload for auto-update state."""

    def __init__(self) -> None:
        self._kv_data: dict[str, object] = {}

    def get_sync_payload(self, key: str) -> object:
        return self._kv_data.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        self._kv_data[key] = payload


class TestAppUpdateOperations:
    """Verify guard.app.update and guard.app.updateCheck are registered and executable."""

    def test_update_operations_in_app_operations(self) -> None:
        assert "guard.app.update" in APP_OPERATIONS
        assert "guard.app.updateCheck" in APP_OPERATIONS

    def test_update_check_returns_status_payload(self, tmp_path: Path) -> None:
        context = _make_context(tmp_path)
        store = _FakeStore()
        job = _make_job("guard.app.updateCheck")
        expected_status = {
            "current_version": "2.0.967",
            "latest_version": "2.0.970",
            "auto_updatable": True,
            "update_available": True,
            "blocked_reason": None,
        }
        with patch(
            "codex_plugin_scanner.guard.runtime.command_executors.build_guard_update_status_payload",
            return_value=expected_status,
        ):
            result = execute_guard_command_job(job, context=context, store=store, now=lambda: "2026-07-04T00:00:00Z")
        assert result["data"]["current_version"] == "2.0.967"
        assert result["data"]["latest_version"] == "2.0.970"
        assert result["data"]["update_available"] is True

    def test_update_calls_run_guard_update(self, tmp_path: Path) -> None:
        context = _make_context(tmp_path)
        store = _FakeStore()
        job = _make_job("guard.app.update")
        expected_update = {
            "current_version": "2.0.967",
            "latest_version": "2.0.970",
            "status": "updated",
            "changed": True,
        }
        with patch(
            "codex_plugin_scanner.guard.runtime.command_executors.run_guard_update",
            return_value=(expected_update, 0),
        ):
            result = execute_guard_command_job(job, context=context, store=store, now=lambda: "2026-07-04T00:00:00Z")
        assert result["data"]["succeeded"] is True
        assert result["data"]["exitCode"] == 0
        assert result["data"]["update"]["status"] == "updated"
        assert result["data"]["update"]["changed"] is True

    def test_update_handles_failure_exit_code(self, tmp_path: Path) -> None:
        context = _make_context(tmp_path)
        store = _FakeStore()
        job = _make_job("guard.app.update")
        expected_update = {
            "current_version": "2.0.967",
            "status": "failed",
            "changed": False,
            "error": "pip install failed",
        }
        with patch(
            "codex_plugin_scanner.guard.runtime.command_executors.run_guard_update",
            return_value=(expected_update, 1),
        ):
            result = execute_guard_command_job(job, context=context, store=store, now=lambda: "2026-07-04T00:00:00Z")
        assert result["data"]["succeeded"] is False
        assert result["data"]["exitCode"] == 1
        assert result["data"]["update"]["error"] == "pip install failed"

    def test_unsupported_app_operation_returns_failure(self, tmp_path: Path) -> None:
        context = _make_context(tmp_path)
        store = _FakeStore()
        job = _make_job("guard.app.unknownOperation")
        result = execute_guard_command_job(job, context=context, store=store, now=lambda: "2026-07-04T00:00:00Z")
        assert result["failureCode"] == "unsupported_operation"


class TestAutoUpdateThrottle:
    """Verify auto-update throttling in maybe_auto_update."""

    def test_auto_update_skipped_within_throttle_window(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.runtime import auto_update

        context = _make_context(tmp_path)
        store = _FakeStore()
        recent = datetime.now(timezone.utc)
        store._kv_data[auto_update.AUTO_UPDATE_STATE_KEY] = {"last_check_at": recent.isoformat()}
        with patch.object(auto_update, "build_guard_update_status_payload") as mock:
            auto_update.maybe_auto_update(store, context)
        mock.assert_not_called()

    def test_auto_update_runs_after_throttle_window(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.runtime import auto_update

        context = _make_context(tmp_path)
        store = _FakeStore()
        old = datetime(2026, 7, 3, 0, 0, 0, tzinfo=timezone.utc)
        store._kv_data[auto_update.AUTO_UPDATE_STATE_KEY] = {"last_check_at": old.isoformat()}
        status = {
            "current_version": "2.0.967",
            "latest_version": "2.0.970",
            "auto_updatable": True,
            "update_available": True,
            "blocked_reason": None,
        }
        with (
            patch.object(auto_update, "build_guard_update_status_payload", return_value=status),
            patch.object(auto_update, "run_guard_update", return_value=({"changed": True}, 0)) as mock_update,
        ):
            auto_update.maybe_auto_update(store, context)
        mock_update.assert_called_once()

    def test_auto_update_skipped_when_not_auto_updatable(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.runtime import auto_update

        context = _make_context(tmp_path)
        store = _FakeStore()
        status = {
            "current_version": "2.0.967",
            "latest_version": "2.0.970",
            "auto_updatable": False,
            "update_available": True,
            "blocked_reason": "This install was set up from local source code.",
        }
        with (
            patch.object(auto_update, "build_guard_update_status_payload", return_value=status),
            patch.object(auto_update, "run_guard_update") as mock_update,
        ):
            auto_update.maybe_auto_update(store, context)
        mock_update.assert_not_called()

    def test_auto_update_skipped_when_no_update_available(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.runtime import auto_update

        context = _make_context(tmp_path)
        store = _FakeStore()
        status = {
            "current_version": "2.0.970",
            "latest_version": "2.0.970",
            "auto_updatable": True,
            "update_available": False,
            "blocked_reason": None,
        }
        with (
            patch.object(auto_update, "build_guard_update_status_payload", return_value=status),
            patch.object(auto_update, "run_guard_update") as mock_update,
        ):
            auto_update.maybe_auto_update(store, context)
        mock_update.assert_not_called()

    def test_auto_update_handles_malformed_state(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.runtime import auto_update

        context = _make_context(tmp_path)
        store = _FakeStore()
        store._kv_data[auto_update.AUTO_UPDATE_STATE_KEY] = "not valid json{{"
        status = {
            "current_version": "2.0.970",
            "latest_version": "2.0.970",
            "auto_updatable": True,
            "update_available": False,
            "blocked_reason": None,
        }
        with patch.object(auto_update, "build_guard_update_status_payload", return_value=status):
            auto_update.maybe_auto_update(store, context)
        # Should not crash — malformed state is treated as empty
