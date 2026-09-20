"""Control-only clocks and failure evidence; no native timing qualification."""

from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace

import pytest

from scripts import native_slo_expiry as expiry
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_publisher_failure import rejected_starting_snapshot
from scripts.native_slo_workspace_lifecycle_clocks import LifecycleClocks, valid_lifecycle_clocks
from tests.test_native_slo_workspace_lifecycle_evidence import Ledger, restored
from tests.test_native_slo_workspace_lifecycle_evidence import cell as cell


def test_completed_and_interrupted_clocks_survive_exact_ledger_json(cell):
    from scripts.native_slo_workspace_lifecycle_evidence import retain_cell

    now = iter((10.0, 10.1, 10.65, 10.66))
    clocks = LifecycleClocks(lambda: next(now))
    clocks.mark("daemon_start_enter")
    clocks.mark("daemon_start_return")
    clocks.mark("recovered_ack_enter")
    report = clocks.report()
    boundaries = report["boundaries_ms"]
    assert isinstance(boundaries, dict)
    assert boundaries["daemon_start_return"] > 600
    assert "recovered_ack_return" not in boundaries
    assert valid_lifecycle_clocks(report)
    assert assert_privacy_safe(report) == report
    failed = copy.deepcopy(cell)
    failed.update(passed=False, lifecycle_clocks=report)
    ledger = Ledger()
    summary = retain_cell(ledger, failed)
    assert summary["passed"] is False
    assert restored(ledger.rows, summary)["proof"]["lifecycle_clocks"] == json.loads(json.dumps(report))


@pytest.mark.parametrize("malformed", [float("nan"), float("inf"), -1, True, "unbounded", 2**63])
def test_clock_non_measurements_cannot_enter_ledger(malformed):
    from scripts.native_slo_workspace_lifecycle_evidence import retain_cell

    report = LifecycleClocks().report()
    report["boundaries_ms"] = {"daemon_start_enter": malformed}
    assert not valid_lifecycle_clocks(report)
    ledger = Ledger()
    result = {"scenario": "expiry_fault", "registered_workspaces": 1, "passed": False, "lifecycle_clocks": report}
    with pytest.raises(ValueError):
        retain_cell(ledger, result)
    assert ledger.rows == []


def test_arbitrary_duplicate_and_reversed_clock_boundaries_are_rejected():
    clocks = LifecycleClocks()
    with pytest.raises(ValueError):
        clocks.mark("caller-path")
    clocks.mark("daemon_start_enter")
    with pytest.raises(ValueError):
        clocks.mark("daemon_start_enter")
    report = clocks.report()
    report["boundaries_ms"] = {"daemon_start_enter": 2, "daemon_start_return": 1}
    assert not valid_lifecycle_clocks(report)
    report["boundaries_ms"] = {"arbitrary": 1}
    assert not valid_lifecycle_clocks(report)


def test_expiry_missing_snapshot_keeps_original_failure_and_one_getter_call():
    calls = []
    publisher = SimpleNamespace(
        _condition=threading.Condition(),
        _acked=False,
        _closed=False,
        _epoch=3,
        _snapshot={"generation": 2, "expires_at_ms": 0, "raw_payload": "never-export"},
        _last_error="never-export-private-message",
        current_snapshot=lambda: calls.append("current_snapshot") or None,
    )
    session = SimpleNamespace(
        daemon=SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))
        )
    )
    with pytest.raises(FixtureFailureError, match="acknowledged starting generation") as raised:
        expiry.expire_acknowledged_authority(session)
    assert calls == ["current_snapshot"]
    detail = assert_privacy_safe(failure_evidence(raised.value))
    state = detail["publisher_state"]
    assert isinstance(state, dict)
    assert detail["expiry_stage"] == "starting_authority"
    assert state["capture_boundary"] == "after_original_starting_snapshot_rejection"
    assert state["capture_available"] is True and state["publisher_acked"] is False
    assert state["retained_generation"] == 2 and state["retained_expired_at_observation"] is True
    assert "never-export" not in json.dumps(detail)
    assert publisher._epoch == 3 and publisher._closed is False


def test_busy_publisher_capture_never_waits_or_reads_state():
    attempts = []
    condition = SimpleNamespace(acquire=lambda **kwargs: attempts.append(kwargs) or False)
    publisher = SimpleNamespace(_condition=condition)
    result = rejected_starting_snapshot(publisher)
    assert attempts == [{"blocking": False}]
    assert result["capture_busy"] is True and result["capture_available"] is False


def test_capture_failure_does_not_replace_original_expiry_failure():
    publisher = SimpleNamespace(current_snapshot=lambda: None)
    session = SimpleNamespace(
        daemon=SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))
        )
    )
    with pytest.raises(FixtureFailureError, match="acknowledged starting generation") as raised:
        expiry.expire_acknowledged_authority(session)
    state = failure_evidence(raised.value)["publisher_state"]
    assert isinstance(state, dict) and state["capture_failed"] is True
