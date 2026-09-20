"""Expected negative acceptance cannot erase a failed functional downgrade."""

from __future__ import annotations

import copy
import json

import pytest

from scripts.ci import verify_installed_artifact_transitions as driver
from scripts.native_slo_contract import assert_privacy_safe
from tests.test_installed_artifact_transitions import _report, _result, _wheel
from tests.test_installed_transition_recovery import _rejection


@pytest.fixture
def complete_suite(monkeypatch, tmp_path):
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    prior = _wheel(tmp_path / "prior.whl", "prior")
    (tmp_path / "uv.lock").write_text("pinned")
    monkeypatch.setattr(driver.shutil, "which", lambda _: "/usr/bin/uv")
    monkeypatch.setattr(driver, "_required_command", lambda *_: None)
    monkeypatch.setattr(driver, "provision_venv_interpreter", lambda _python: {"passed": True})

    def run(argv, root):
        phase = argv[-1]
        expected = json.loads((root / "expected.json").read_text())
        if phase == "baseline_rollback":
            return _result(_rejection(expected), returncode=1)
        observed = _report(expected, phase)
        if phase == "candidate_restore":
            observed.update(prior_receipts_verified=6, restored_after_rejected_legacy=True)
        return _result(observed)

    monkeypatch.setattr(driver, "_run", run)
    monkeypatch.setattr(driver, "_run_phase", lambda argv, root, _prior: run(argv, root))
    return driver.verify(
        tmp_path / "python",
        baseline,
        candidate,
        driver.AUDITED_BASELINE_SHA,
        "a" * 40,
        dependency_root=tmp_path,
        prior_candidate_wheel=prior,
        prior_candidate_sha="b" * 40,
    )


def test_complete_expected_negative_acceptance_keeps_failed_phase_and_positive_counters(complete_suite):
    report = complete_suite
    assert report["passed"] is False
    assert report["phases"][3]["passed"] is False
    assert (
        report["phases"][3]["worker"]["failure"]["reason"] == "native_installed_slo_failed:_native_policy_was_not_ready"
    )
    assert report["completed_phase_count"] == 4 and report["required_phase_count"] == 5
    accepted = report["suite_acceptance"]
    assert accepted["passed"] is True
    assert accepted["verified_positive_count"] == 7 and accepted["verified_expected_negative_count"] == 1
    assert accepted["original_baseline_functional_downgrade_passed"] is False
    assert assert_privacy_safe(report) == report


@pytest.mark.parametrize(
    "mutation",
    [
        "prior_missing",
        "prior_failed",
        "missing_phase",
        "duplicate_phase",
        "counter",
        "boolean_counter",
        "identity",
        "dependency",
        "artifact",
        "floor",
        "containment",
        "live_publisher",
        "restore_binding",
        "failure_erased",
        "unexpected_failure",
        "positive_legacy",
        "legacy_forged_pass",
        "boolean_return_code",
        "receipt_count",
        "broader_claim",
        "revision_regressed",
        "prior_identity",
    ],
)
def test_suite_rechecks_completeness_identity_retirement_and_counters(complete_suite, mutation):
    report = copy.deepcopy(complete_suite)
    negative = report["phases"][3]
    if mutation == "prior_missing":
        report.pop("compatible_rollback")
    elif mutation == "prior_failed":
        report["compatible_rollback"]["phases"][1]["worker"]["cleanup_confirmed"] = False
    elif mutation == "missing_phase":
        report["phases"].pop()
    elif mutation == "duplicate_phase":
        report["phases"][-1] = report["phases"][2]
    elif mutation == "counter":
        report["completed_phase_count"] = 5
    elif mutation == "boolean_counter":
        report["compatible_rollback"]["completed_phase_count"] = True
    elif mutation == "identity":
        report["phases"][-1]["worker"]["identity"]["build_sha"] = "d" * 40
    elif mutation == "dependency":
        report["compatible_rollback"]["dependency_lock_sha256"] = "e" * 64
    elif mutation == "artifact":
        report["artifact_integrity_verified"] = False
    elif mutation == "floor":
        negative["worker"]["policy_after"]["authority"]["sha256"] = "c" * 64
    elif mutation == "containment":
        negative["worker"]["retirement_verification"]["containment_failed"] = True
    elif mutation == "live_publisher":
        negative["worker"]["retirement_verification"]["publisher_after_close"]["thread_alive"] = True
    elif mutation == "restore_binding":
        report["phases"][-1]["worker"]["restored_after_rejected_legacy"] = False
    elif mutation == "failure_erased":
        negative["worker"].pop("failure")
    elif mutation == "unexpected_failure":
        report["phases"][1]["worker"]["failure"] = {"reason": "unexpected"}
    elif mutation == "positive_legacy":
        report["passed"] = True
    elif mutation == "legacy_forged_pass":
        negative["passed"] = True
    elif mutation == "boolean_return_code":
        report["phases"][0]["process"]["return_code"] = False
    elif mutation == "receipt_count":
        report["phases"][-1]["worker"]["prior_receipts_verified"] = 8
    elif mutation == "broader_claim":
        report["native_program_downgrade_qualified"] = True
    elif mutation == "revision_regressed":
        report["phases"][-1]["worker"]["control_revision"] = 0
    elif mutation == "prior_identity":
        report["compatible_rollback"]["identities"]["prior_candidate"]["build_sha"] = "f" * 40
    assert driver.suite_acceptance(report)["passed"] is False


@pytest.mark.parametrize(
    "prior_requested,old_positive,suite_pass,exit_code",
    [
        (True, False, True, 0),
        (True, True, False, 1),
        (True, False, False, 1),
        (False, False, False, 1),
        (False, True, False, 0),
    ],
)
def test_cli_uses_explicit_contract_and_cannot_ignore_compatible_failure(
    prior_requested,
    old_positive,
    suite_pass,
    exit_code,
    monkeypatch,
    tmp_path,
):
    result = {
        "passed": old_positive,
        "prior_candidate_requested": prior_requested,
        "suite_acceptance": {"passed": suite_pass},
    }
    monkeypatch.setattr(driver, "verify", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(
        driver.sys,
        "argv",
        [
            "transition",
            "--python",
            "python",
            "--baseline-wheel",
            "base.whl",
            "--candidate-wheel",
            "current.whl",
            "--baseline-sha",
            driver.AUDITED_BASELINE_SHA,
            "--candidate-sha",
            "a" * 40,
            "--dependency-root",
            str(tmp_path),
            "--output",
            str(tmp_path / "report.json"),
        ],
    )
    assert driver.main() == exit_code
    assert json.loads((tmp_path / "report.json").read_text()) == result
