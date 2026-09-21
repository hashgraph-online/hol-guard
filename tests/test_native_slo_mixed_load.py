"""Accounting tests for the runner; these do not qualify an installed runtime."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import Counter
from pathlib import Path

import pytest

from scripts import native_slo_mixed
from scripts.native_slo_contract import MAX_INSTALLED_ADAPTER_P99_MS
from scripts.native_slo_mixed import _checks, _receipt_pages, _schedule, run_mixed_scenario
from scripts.native_slo_mixed_load import MixedLoad, MixedPlan, PrivateLedger
from scripts.native_slo_mixed_response import delivered_decision


def test_success_failure_and_capacity_are_retained_in_the_same_denominator(tmp_path: Path) -> None:
    ledger = PrivateLedger(tmp_path / "attempts.jsonl")
    plan = MixedPlan(duration_seconds=0.15, rate=20, concurrency=1)

    def request(_harness: str, payload: object) -> tuple[dict[str, object], float]:
        assert isinstance(payload, dict)
        index = int(payload["tool_use_id"].rsplit("-", 1)[1])
        if index == 1:
            raise OSError("must never be retained as raw exception text")
        if index == 2:
            return {"decision": "deny", "reason_code": "daemon_capacity"}, 1.0
        return {"decision": "allow"}, 1.0

    load = MixedLoad(plan, request, ledger)
    load.start()
    result = load.finish()
    retained = ledger.finish()
    assert result["offered"] == result["planned"] == result["generator_admitted"] == 3
    assert result["completed"] == 2
    assert result["transport_failed"] == result["capacity_rejected"] == 1
    assert result["accounting_complete"]
    data = (tmp_path / "attempts.jsonl").read_bytes()
    rows = [json.loads(line) for line in data.splitlines()]
    assert Counter(row["kind"] for row in rows) == {"offer": 3, "terminal": 3}
    assert "raw exception text" not in data.decode()
    assert retained["sha256"] == hashlib.sha256(data).hexdigest()
    if os.name != "nt":
        assert (tmp_path / "attempts.jsonl").stat().st_mode & 0o777 == 0o600


def test_flood_and_blocked_worker_keep_one_terminal_result_even_after_late_completion(tmp_path: Path) -> None:
    ledger = PrivateLedger(tmp_path / "blocked.jsonl")
    release = threading.Event()
    dispatched = threading.Event()

    def blocked(_harness: str, _payload: object) -> tuple[dict[str, object], float]:
        dispatched.set()
        assert release.wait(3)
        return {"decision": "allow"}, 2.0

    plan = MixedPlan(duration_seconds=0.04, rate=500, concurrency=1, completion_seconds=0.05)
    load = MixedLoad(plan, blocked, ledger)
    load.start()
    assert dispatched.wait(1)
    result = load.finish()
    assert result["offered"] == 20
    assert result["generator_rejected"] > 0
    assert result["completion_timeout"] == result["generator_admitted"]
    assert result["workers_unfinished"] == 1
    assert result["accounting_complete"]
    release.set()
    for thread in load._threads:
        thread.join(1)
    assert load.late_completions == 1
    ledger.finish()
    rows = [json.loads(line) for line in (tmp_path / "blocked.jsonl").read_text().splitlines()]
    terminal = [row for row in rows if row["kind"] == "terminal"]
    assert len(terminal) == len({row["attempt"] for row in terminal}) == 20
    assert all(row["state"] != "completed" for row in terminal)


def test_private_retention_failure_is_not_a_successful_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = PrivateLedger(tmp_path / "io-error.jsonl")
    monkeypatch.setattr(ledger, "write", lambda _row: (_ for _ in ()).throw(OSError("full")))
    load = MixedLoad(MixedPlan(duration_seconds=0.01, rate=100), lambda *_: ({"decision": "allow"}, 1.0), ledger)
    load.start()
    result = load.finish()
    assert result["completed"] == result["offered"] == 1
    assert result["errors"]["ledger_write_failure"] == 2
    assert _checks(result, {}, [], {}, {})["all_offered_work_retained"] is False
    ledger.finish()


@pytest.mark.parametrize(
    "arguments",
    (
        {"concurrency": 65},
        {"concurrency": True},
        {"duration_seconds": float("nan")},
        {"rate": float("inf")},
        {"rate": 10001},
        {"rate": 10000, "duration_seconds": 11},
        {"mutations": 1},
        {"restarts": 0},
        {"inventory_batches": 0},
    ),
)
def test_scenario_bounds_require_each_mixed_workstream(arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        MixedPlan(**arguments)


def test_schedule_changes_policy_both_directions_during_offered_work() -> None:
    plan = MixedPlan()
    schedule = _schedule(plan)
    assert len(schedule) == plan.mutations + plan.restarts + plan.inventory_batches
    assert all(0 < at < plan.duration_seconds for at, _op, _args in schedule)
    assert [args["action"] for _at, op, args in schedule if op == "mixed_policy"] == [
        "block",
        "allow",
        "block",
        "allow",
    ]


def test_missing_metrics_and_empty_receipts_cannot_produce_a_pass() -> None:
    checks = _checks({}, {}, [], {}, {})
    assert not any(checks.values())


def test_page_total_and_progress_are_bounded(tmp_path: Path) -> None:
    class EmptyPage:
        def control(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            return {"status": "completed", "total": 3, "rows": []}

    ledger = PrivateLedger(tmp_path / "page.jsonl")
    load = MixedLoad(MixedPlan(), lambda *_: ({}, 0.0), ledger)
    with pytest.raises(RuntimeError, match="no progress"):
        _receipt_pages(EmptyPage(), load, ledger)
    ledger.finish()


def test_failed_setup_keeps_control_attempt_and_never_fabricates_http_work(tmp_path: Path) -> None:
    class FailedFixture:
        def control(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            return {"status": "failed", "failure_type": "RuntimeError"}

        def request(self, *_args: object, **_kwargs: object) -> tuple[dict[str, object], float]:
            pytest.fail("failed setup must not fabricate native work")

    result = run_mixed_scenario(FailedFixture(), raw_file=tmp_path / "failed.jsonl")
    assert result["passed"] is False
    assert result["failures"] == {"setup_failed": 1}
    assert result["load"] == {}
    rows = [json.loads(line) for line in (tmp_path / "failed.jsonl").read_text().splitlines()]
    assert [row["kind"] for row in rows] == ["control_offer", "control_terminal"]


def test_resource_setup_failure_closes_started_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    operations: list[str] = []

    class Fixture:
        pid = 123

        def control(self, operation: str, **_kwargs: object) -> dict[str, object]:
            operations.append(operation)
            return {"status": "completed"}

        def request(self, *_args: object) -> tuple[dict[str, object], float]:
            pytest.fail("resource setup did not admit hook work")

    def unavailable(**_kwargs: object) -> None:
        raise RuntimeError("resource collector unavailable")

    monkeypatch.setattr(native_slo_mixed, "ResourceSampler", unavailable)
    result = run_mixed_scenario(Fixture(), raw_file=tmp_path / "resource-failure.jsonl")
    assert result["passed"] is False
    assert result["failures"] == {"runner_failed": 1}
    assert operations == ["mixed_start", "mixed_finish"]


def test_generator_queue_delay_fails_offered_latency_gate_despite_fast_http(tmp_path: Path) -> None:
    ledger = PrivateLedger(tmp_path / "queue-delay.jsonl")
    plan = MixedPlan(duration_seconds=0.1, rate=10, concurrency=1, completion_seconds=3)
    load = MixedLoad(
        plan,
        lambda *_: ({"policy_action": "allow", "hookSpecificOutput": {"hookEventName": "PostToolUse"}}, 1.0),
        ledger,
    )
    release = threading.Event()
    worker = load._worker

    def delayed_worker() -> None:
        assert release.wait(3)
        worker()

    load._worker = delayed_worker
    load.start()
    time.sleep((MAX_INSTALLED_ADAPTER_P99_MS + 50) / 1000)
    release.set()
    result = load.finish()
    ledger.finish()
    assert result["completed"] == result["offered"] == 1
    assert result["generator_rejected"] == result["completion_timeout"] == 0
    assert result["request_latency"]["p99_ms"] == 1.0
    assert result["offered_latency"]["p99_ms"] > MAX_INSTALLED_ADAPTER_P99_MS
    assert result["generator_wait"]["p99_ms"] > MAX_INSTALLED_ADAPTER_P99_MS
    assert _checks(result, {}, [], {}, {})["offered_completion_latency_target"] is False


@pytest.mark.parametrize(
    "response",
    ({}, {"decision": "deny"}, {"policy_action": "block"}, {"hookSpecificOutput": {"permissionDecision": "deny"}}),
)
def test_malformed_response_is_never_proof_of_a_delivered_denial(response: dict[str, object]) -> None:
    assert delivered_decision("PreToolUse", response) is None
    assert delivered_decision("PostToolUse", response) is None


def test_frozen_delivered_permission_contract_rejects_contradictory_fields() -> None:
    pre = {
        "continue": True,
        "policy_action": "allow",
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
    }
    assert delivered_decision("PreToolUse", pre) == "allow"
    assert delivered_decision("PreToolUse", {**pre, "decision": "deny"}) is None
    deny = {
        "policy_action": "block",
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
    }
    assert delivered_decision("PreToolUse", deny) == "deny"
    assert delivered_decision("PreToolUse", {**deny, "decision": "allow"}) is None
    post = {
        "policy_action": "block",
        "decision": "block",
        "model_output_action": "block",
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }
    assert delivered_decision("PostToolUse", post) == "deny"
    assert delivered_decision("PostToolUse", {**post, "model_output_action": "allow_original"}) is None
