"""Automatic update checks against the native auto-update bookkeeping."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_auto_update_state import AutoUpdateStateError
from codex_plugin_scanner.guard.runtime import auto_update
from codex_plugin_scanner.guard.store import GuardStore

AVAILABLE: dict[str, object] = {
    "current_version": "2.0.967",
    "latest_version": "2.0.970",
    "auto_updatable": True,
    "update_available": True,
    "update_mode": "automatic",
    "blocked_reason": None,
}


@pytest.fixture(autouse=True)
def _native_runtime(native_command_capability_runtime: Path) -> None:
    del native_command_capability_runtime


def _setup(tmp_path: Path) -> tuple[GuardStore, HarnessContext]:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=guard_home,
    )
    return store, context


def _state(store: GuardStore) -> dict[str, object]:
    saved = store.get_sync_payload(auto_update.AUTO_UPDATE_STATE_KEY)
    assert isinstance(saved, dict)
    return saved


def _save(store: GuardStore, payload: object) -> None:
    store.set_sync_payload(auto_update.AUTO_UPDATE_STATE_KEY, payload, datetime.now(timezone.utc).isoformat())


def _run(store: GuardStore, context: HarnessContext, status: object, result: object = ({"changed": True}, 0)):
    with (
        patch.object(auto_update, "build_guard_update_status_payload", return_value=status) as check,
        patch.object(auto_update, "run_guard_update", return_value=result) as update,
    ):
        auto_update.maybe_auto_update(store, context)
    return check, update


def test_a_check_inside_the_throttle_window_is_skipped(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    _save(store, {"last_check_at": datetime.now(timezone.utc).isoformat()})
    check, update = _run(store, context, AVAILABLE)
    check.assert_not_called()
    update.assert_not_called()


def test_an_available_update_runs_after_the_window(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    old = datetime.now(timezone.utc) - timedelta(hours=7)
    _save(store, {"last_check_at": old.isoformat(), "failed_version": "2.0.968"})
    _check, update = _run(store, context, AVAILABLE)
    update.assert_called_once()
    assert update.call_args.kwargs["include_alpha"] is False
    saved = _state(store)
    assert saved["last_status"] == AVAILABLE
    assert saved["last_update_result"] == {"changed": True}
    assert saved["last_update_exit_code"] == 0
    assert "failed_version" not in saved
    assert saved["last_check_at"] != old.isoformat()


def test_the_second_call_in_a_window_does_not_check_again(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    _run(store, context, AVAILABLE)
    check, update = _run(store, context, AVAILABLE)
    check.assert_not_called()
    update.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        {"auto_updatable": False, "blocked_reason": "This install was set up from local source code."},
        {"update_mode": "ask"},
        {"update_mode": "off"},
        {"update_available": False},
    ],
)
def test_held_back_updates_do_not_run(tmp_path: Path, change: dict[str, object]) -> None:
    store, context = _setup(tmp_path)
    status = {**AVAILABLE, **change}
    _check, update = _run(store, context, status)
    update.assert_not_called()
    assert _state(store)["last_status"] == status


def test_a_failed_target_version_is_not_retried(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    _save(store, {"failed_version": "2.0.970"})
    _check, update = _run(store, context, AVAILABLE)
    update.assert_not_called()


def test_a_failed_run_records_its_target_version(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    _run(store, context, AVAILABLE, result=({"status": "failed"}, 1))
    assert _state(store)["failed_version"] == "2.0.970"


def test_a_raised_run_records_the_error(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    with (
        patch.object(auto_update, "build_guard_update_status_payload", return_value=AVAILABLE),
        patch.object(auto_update, "run_guard_update", side_effect=RuntimeError("boom")),
    ):
        auto_update.maybe_auto_update(store, context)
    saved = _state(store)
    assert saved["last_update_error"] is True
    assert saved["failed_version"] == "2.0.970"


def test_a_failed_status_fetch_is_recorded(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    with (
        patch.object(auto_update, "build_guard_update_status_payload", side_effect=RuntimeError("offline")),
        patch.object(auto_update, "run_guard_update") as update,
    ):
        auto_update.maybe_auto_update(store, context)
    update.assert_not_called()
    saved = _state(store)
    assert saved["last_check_error"] is True
    assert "last_status" not in saved


def test_malformed_state_is_treated_as_empty(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    # The store only writes objects and arrays, so the malformed row is
    # written straight into the table.
    with store._connect() as connection:
        connection.execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
            (auto_update.AUTO_UPDATE_STATE_KEY, "not valid json{{", datetime.now(timezone.utc).isoformat()),
        )
    _check, update = _run(store, context, {**AVAILABLE, "update_available": False})
    update.assert_not_called()
    assert _state(store)["last_status"]["update_available"] is False


def test_no_runtime_answer_skips_the_check(tmp_path: Path) -> None:
    store, context = _setup(tmp_path)
    with patch.object(auto_update, "native_auto_update_state", side_effect=AutoUpdateStateError):
        check, update = _run(store, context, AVAILABLE)
    check.assert_not_called()
    update.assert_not_called()
