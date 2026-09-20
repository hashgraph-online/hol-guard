"""Collector transport and exact-evidence integration, without native timings."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from scripts import native_slo_workspace_lifecycle_runner as runner
from scripts import native_slo_workspace_server as server
from scripts.native_slo_failure import failure_evidence
from tests.test_native_slo_workspace_lifecycle_evidence import cell as cell


def _runtime(monkeypatch, digest="b" * 64):
    monkeypatch.setattr(runner, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(runner, "_runtime_summary", lambda _: {"runtime_sha256": digest})
    monkeypatch.setattr(runner, "validate_receipt_profile", lambda *_: None)
    monkeypatch.setattr(runner, "_definition", lambda: {"files": 1, "sha256": "d" * 64})


def _fixture(monkeypatch, result, *, cleanup_error=None):
    calls = []

    class Fixture:
        def __init__(self, runtime, *, policy, workspace_count):
            assert policy == "normal"
            self.count = workspace_count
            calls.append(("construct", workspace_count))

        def __enter__(self):
            return self

        def control(self, operation, *, scenario, receipt_profile):
            assert operation == "workspace_lifecycle" and receipt_profile == "candidate"
            calls.append(("control", self.count, scenario))
            return (
                copy.deepcopy(result)
                if result is not None
                else {
                    "status": "completed",
                    "scenario": scenario,
                    "registered_workspaces": self.count,
                    "passed": False,
                }
            )

        def __exit__(self, *_args):
            calls.append(("close", self.count))
            if cleanup_error is not None:
                raise cleanup_error

    monkeypatch.setattr(runner, "DaemonFixture", Fixture)
    return calls


def _proof(path):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    parts = [row for row in rows if row["kind"] == "lifecycle_cell_terminal_part"]
    assert [row["part"] for row in parts] == list(range(len(parts)))
    return json.loads("".join(part["content"] for part in parts))["proof"]


def test_runner_retains_full_typed_receipts_before_generic_aggregate_summary(tmp_path, monkeypatch, cell):
    _runtime(monkeypatch)
    calls = _fixture(monkeypatch, cell)
    path = tmp_path / "raw.jsonl"
    result = runner.run_lifecycle_sweep(
        Path("runtime"), ledger_path=path, counts=(1,), scenarios=("lost_metadata_hint",)
    )
    assert calls == [("construct", 1), ("control", 1, "lost_metadata_hint"), ("close", 1)]
    saved = result["cells"][0]
    assert saved["passed"] and saved["request_checks"]["passed"]
    assert result["implemented_checks_passed"] is False  # A subset never qualifies the matrix.
    assert result["full_rsp_128_129_qualification"] is False
    assert "requests" not in saved and saved["evidence"]["parts"] > 0
    retained = _proof(path)["requests"]["actual_request_rows"][0]
    for key in ("native_receipt", "committed_receipt"):
        assert validate_native_decision_receipt(retained[key]) == retained[key]
        assert retained[key] == cell["requests"]["actual_request_rows"][0][key]


def test_fixture_cleanup_failure_keeps_original_cell_failure_and_exact_evidence(tmp_path, monkeypatch, cell):
    _runtime(monkeypatch)
    original = ValueError("first readback failure")
    cell.update(passed=False, failure=failure_evidence(original))
    cleanup = OSError("service containment failure")
    _fixture(monkeypatch, cell, cleanup_error=cleanup)
    path = tmp_path / "raw.jsonl"
    result = runner.run_lifecycle_sweep(
        Path("runtime"), ledger_path=path, counts=(1,), scenarios=("lost_metadata_hint",)
    )
    assert result["cells"][0]["passed"] is False
    proof = _proof(path)
    assert proof["failure"] == failure_evidence(original)
    assert proof["fixture_cleanup_failure"] == failure_evidence(cleanup)
    assert proof["requests"] == cell["requests"]
    assert proof["publication_rows"] == cell["publication_rows"]


def test_valid_receipt_from_another_installed_binary_cannot_pass(tmp_path, monkeypatch, cell):
    _runtime(monkeypatch, "c" * 64)
    _fixture(monkeypatch, cell)
    result = runner.run_lifecycle_sweep(
        Path("runtime"), ledger_path=tmp_path / "raw.jsonl", counts=(1,), scenarios=("lost_metadata_hint",)
    )
    assert result["cells"][0]["installed_runtime_matches"] is False
    assert result["cells"][0]["passed"] is False


def test_another_scenario_cannot_satisfy_the_declared_fault(tmp_path, monkeypatch, cell):
    _runtime(monkeypatch)
    _fixture(monkeypatch, cell)
    result = runner.run_lifecycle_sweep(
        Path("runtime"), ledger_path=tmp_path / "raw.jsonl", counts=(1,), scenarios=("key_rotation",)
    )
    assert result["cells"][0]["declared_cell_matches"] is False
    assert result["cells"][0]["passed"] is False


def test_full_matrix_visits_every_1_10_100_scenario_in_a_distinct_contained_fixture(tmp_path, monkeypatch):
    _runtime(monkeypatch)
    calls = _fixture(monkeypatch, None)
    result = runner.run_lifecycle_sweep(Path("runtime"), ledger_path=tmp_path / "raw.jsonl")
    expected = [(count, scenario) for count in (1, 10, 100) for scenario in runner.LIFECYCLE_SCENARIOS]
    assert [(row[1], row[2]) for row in calls if row[0] == "control"] == expected
    assert len([row for row in calls if row[0] == "close"]) == len(expected) == 15
    assert result["complete_lifecycle_matrix_visited"]
    assert result["declared_cells_visited"]
    assert result["implemented_checks_passed"] is False


def test_workspace_lifecycle_dispatch_closes_initial_observer_and_cannot_be_reused(monkeypatch):
    from scripts import native_slo_workspace_lifecycle as lifecycle

    value = server.WorkspaceScenarioFixture.__new__(server.WorkspaceScenarioFixture)
    calls = []
    value.witness, value.finished, value.failed = None, False, False
    value.session, value.workspaces = object(), (Path("workspace"),)
    value.observer = SimpleNamespace(close=lambda: calls.append("old_observer_closed"), report=lambda: {})

    def run(session, workspaces, scenario):
        assert calls == ["old_observer_closed"]
        assert session is value.session and workspaces is value.workspaces
        calls.append(scenario)
        return {"status": "completed", "passed": False}

    monkeypatch.setattr(lifecycle, "run_lifecycle_cell", run)
    assert value.dispatch("workspace_lifecycle", {"receipt_profile": "candidate", "scenario": "expiry_fault"}) == {
        "status": "completed",
        "passed": False,
    }
    assert value.finished
    assert (
        value.dispatch("workspace_lifecycle", {"receipt_profile": "candidate", "scenario": "expiry_fault"})["passed"]
        is False
    )
    assert value.dispatch("workspace_start", {"receipt_profile": "candidate"})["passed"] is False
    assert calls == ["old_observer_closed", "expiry_fault"]


@pytest.mark.parametrize("counts", [(True,), (), (10, 1), (1, 1), (2,)])
def test_invalid_matrix_is_rejected_before_any_fixture_or_ledger(tmp_path, monkeypatch, counts):
    monkeypatch.setattr(runner, "_clear_proof_overrides", lambda: pytest.fail("invalid matrix reached setup"))
    path = tmp_path / "raw.jsonl"
    with pytest.raises(ValueError, match="matrix"):
        runner.run_lifecycle_sweep(Path("runtime"), ledger_path=path, counts=counts)
    assert not path.exists()
