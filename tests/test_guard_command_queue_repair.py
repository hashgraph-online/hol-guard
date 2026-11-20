"""Queue state repair through the native command ledger."""

from __future__ import annotations

import contextvars
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.native_command_state import CommandStateUnavailableError
from codex_plugin_scanner.guard.runtime import command_queue_state
from codex_plugin_scanner.guard.runtime.command_queue_drain import review_drain_lane
from codex_plugin_scanner.guard.runtime.command_queue_state import (
    COMMAND_QUEUE_STATE_KEY,
    enter_command_queue_lane,
    repair_command_queue_state,
)
from codex_plugin_scanner.guard.store import GuardStore

SAVED_AT = "2026-06-13T00:00:00+00:00"
DAMAGED = {"state": "result_pending", "last_error": "boom", "active_job": "bad", "pending_result": {"job": "bad"}}


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_a_drain_lane_repairs_its_own_row_and_leaves_the_main_row(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    lane = review_drain_lane(3)
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, DAMAGED, SAVED_AT)
    store.set_sync_payload(lane.state_key, DAMAGED, SAVED_AT)

    def repair_in_lane() -> dict[str, object]:
        enter_command_queue_lane(lane)
        return repair_command_queue_state(store)

    result = contextvars.copy_context().run(repair_in_lane)

    assert result["repaired"] == ["active_job", "pending_result"]
    assert result["repaired_count"] == 2
    assert store.get_sync_payload(lane.state_key) == {"state": "idle", "last_error": None}
    assert store.get_sync_payload(COMMAND_QUEUE_STATE_KEY) == DAMAGED


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_a_healthy_row_is_not_rewritten(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    healthy = {"state": "idle", "active_job": {"id": "job-1"}}
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, healthy, SAVED_AT)

    result = repair_command_queue_state(store)

    assert result["repaired"] == []
    assert result["repaired_count"] == 0
    assert store.get_sync_payload(COMMAND_QUEUE_STATE_KEY) == healthy


def test_doctor_reports_a_repair_the_runtime_could_not_answer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, DAMAGED, SAVED_AT)

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise CommandStateUnavailableError

    monkeypatch.setattr(command_queue_state, "native_command_state", unavailable)

    rc = main(["guard", "doctor", "--guard-home", str(guard_home), "--repair", "--json"])

    assert rc == 0
    repair = json.loads(capsys.readouterr().out)["command_queue"]["repair"]
    assert repair == {"repaired": [], "repaired_count": 0, "error": "native_command_state_unavailable"}
    assert store.get_sync_payload(COMMAND_QUEUE_STATE_KEY) == DAMAGED


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_doctor_repair_clears_malformed_command_queue_state(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        COMMAND_QUEUE_STATE_KEY,
        {"state": "result_pending", "active_job": "bad", "pending_result": {"job": "bad"}},
        SAVED_AT,
    )

    rc = main(["guard", "doctor", "--guard-home", str(guard_home), "--repair", "--json"])

    assert rc == 0
    repair = json.loads(capsys.readouterr().out)["command_queue"]["repair"]
    assert repair["repaired_count"] == 2
    assert sorted(repair["repaired"]) == ["active_job", "pending_result"]
    state = store.get_sync_payload(COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "idle"
    assert "active_job" not in state
    assert "pending_result" not in state
