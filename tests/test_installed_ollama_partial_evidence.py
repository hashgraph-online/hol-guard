"""A late readiness failure retains prior evidence without reporting a pass."""

from __future__ import annotations

import json
import sys

import pytest

from scripts.ci import installed_native_ollama_probe as probe
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError


def test_late_readiness_failure_retains_only_completed_cases_and_verified_identity(monkeypatch) -> None:
    def late_failure(_expected, progress):
        progress["identity"] = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64}
        progress["phase"] = "stale_write_rejected"
        progress["cases"].extend(
            [
                {"phase": "enabled", "case": "push", "receipt_durable": True},
                {"phase": "settings_rollback", "case": "rm", "receipt_durable": True},
            ]
        )
        raise FixtureFailureError(
            {
                "reason": "installed_ollama_native_readiness_failed",
                "phase": "stale_write_rejected",
                "readiness": {"elapsed_ms": 406.0, "budget_ms": 400.0, "budget_exhausted": True},
            }
        )

    monkeypatch.setattr(probe, "_run_probe", late_failure)
    result = json.loads(json.dumps(assert_privacy_safe({"native": probe.run_probe({})})))
    native = result["native"]
    assert native["passed"] is False
    assert native["identity"]["build_sha"] == "a" * 40
    assert native["completed_case_count"] == native["completed_phase_count"] == 2
    assert [item["phase"] for item in native["cases"]] == ["enabled", "settings_rollback"]
    assert native["failure"]["readiness"] == {
        "elapsed_ms": 406.0,
        "budget_ms": 400.0,
        "budget_exhausted": True,
    }
    assert native["retained_scope"] == "completed_cases_only"


def test_identity_failure_never_exports_unverified_expected_identity(monkeypatch) -> None:
    def fail(_expected, _progress):
        raise RuntimeError("/home/private/confidential fixture")

    monkeypatch.setattr(probe, "_run_probe", fail)
    result = probe.run_probe({"build_sha": "a" * 40})
    assert result["passed"] is False and result["completed_case_count"] == 0
    assert "identity" not in result
    assert "/home/private" not in json.dumps(result)


@pytest.mark.parametrize("passed", [False, True])
def test_worker_exit_preserves_failure_even_when_completed_cases_exist(passed, monkeypatch, tmp_path, capsys) -> None:
    expected = tmp_path / "expected.json"
    expected.write_text("{}")
    monkeypatch.setattr(sys, "argv", ["probe", "--expected", str(expected)])
    monkeypatch.setattr(probe, "run_probe", lambda _expected: {"passed": passed, "cases": [{"phase": "enabled"}]})
    assert probe.main() == (0 if passed else 1)
    assert json.loads(capsys.readouterr().out)["passed"] is passed
