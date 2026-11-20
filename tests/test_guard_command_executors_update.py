"""Tests for guard.app.update and guard.app.updateCheck command executors."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.runtime.audit_workspace import audit_workspace_is_bound_to_context
from codex_plugin_scanner.guard.runtime.command_executors import (
    APP_OPERATIONS,
    execute_guard_command_job,
)

# Every job is planned by the native runtime before it runs.
pytestmark = pytest.mark.usefixtures("native_command_capability_runtime")


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
        self.guard_home = Path("/opt/guard-test")

    def get_sync_payload(self, key: str) -> object:
        return self._kv_data.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        self._kv_data[key] = payload

    def list_managed_installs(self) -> list[object]:
        return []


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


def test_cloud_audit_rejects_workspace_override_outside_active_context(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    assert context.workspace_dir is not None
    context.workspace_dir.mkdir()
    other_workspace = tmp_path / "other-workspace"
    other_workspace.mkdir()

    result = execute_guard_command_job(
        _make_job("guard.packageShims.audit", {"workspace_dir": str(other_workspace)}),
        context=context,
        store=_FakeStore(),
        now=lambda: "2026-07-04T00:00:00Z",
    )

    assert result["failureCode"] == "workspace_scope_mismatch"


def test_cloud_audit_accepts_relative_active_workspace_without_approval(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    assert context.workspace_dir is not None
    context.workspace_dir.mkdir()

    assert audit_workspace_is_bound_to_context({"workspace_dir": "."}, context)


def test_cloud_audit_executes_relative_dot_in_active_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _make_context(tmp_path)
    assert context.workspace_dir is not None
    context.workspace_dir.mkdir()
    unrelated_cwd = tmp_path / "unrelated"
    unrelated_cwd.mkdir()
    monkeypatch.chdir(unrelated_cwd)

    with (
        patch(
            "codex_plugin_scanner.guard.runtime.command_executors.build_workspace_audit_payload",
            return_value=({"workspace": str(context.workspace_dir)}, 0),
        ) as audit,
        patch("codex_plugin_scanner.guard.runtime.command_executors.load_guard_config", return_value=object()),
        patch(
            "codex_plugin_scanner.guard.runtime.command_executors.record_package_shim_audit_result",
            return_value={"audit_proof_recorded": False, "audit_proof_error": "native_shim_admin_unavailable"},
        ),
    ):
        result = execute_guard_command_job(
            _make_job("guard.packageShims.audit", {"workspace_dir": "."}),
            context=context,
            store=_FakeStore(),
            now=lambda: "2026-07-04T00:00:00Z",
        )

    assert result["data"]["workspace"] == str(context.workspace_dir)
    assert result["data"]["audit_proof_recorded"] is False
    assert result["data"]["audit_proof_error"] == "native_shim_admin_unavailable"
    assert audit.call_args.kwargs["workspace_dir"] == context.workspace_dir.resolve()
