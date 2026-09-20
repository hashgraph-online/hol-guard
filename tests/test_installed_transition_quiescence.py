"""A kernel boundary cannot turn a different failure or changed authority into acceptance."""

from __future__ import annotations

import copy
import json
import sys

import pytest

from scripts.ci import installed_transition_quiescence as proof
from scripts.ci import installed_transition_receipts as receipts
from scripts.ci import verify_installed_artifact_transitions as driver
from scripts.native_slo_contract import assert_privacy_safe
from tests.test_installed_artifact_transitions import _result
from tests.test_installed_transition_recovery import _rejection

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux owned legacy rollback certificate")

_ARTIFACT = {
    "build_sha": receipts.AUDITED_BASELINE_SHA,
    "wheel_sha256": "b" * 64,
    "installed_package_sha256": "c" * 64,
}


def _pending_report():
    report = _rejection(_ARTIFACT)
    report.update(cleanup_confirmed=False, legacy_postcheck_verified=True, native_review_started=False)
    report.pop("rejected_legacy_start_verified")
    report["retirement_verification"].update(verified=False, return_code=2, active_hook_requests=0)
    report["retirement_verification"]["publisher_after_close"].update(ready=False)
    return report


def _evidence(report):
    return {
        "schema": proof._SCHEMA,
        "mechanism": "linux_child_subreaper",
        "platform": "linux",
        "verified": False,
        **{
            key: True
            for key in (
                "initial_children_empty",
                "enabled_before_spawn",
                "worker_exit_observed",
                "descendants_exhausted",
                "fixture_unchanged",
                "installation_unchanged",
                "code_unchanged",
                "enrollment_records_absent_before",
                "enrollment_records_absent_after",
            )
        },
        **{key: False for key in ("timed_out", "limit_exceeded", "containment_failed")},
        "termination_signals_sent": 0,
        "adopted_signalled_exits": 0,
        "worker_return_code": 1,
        "worker_pid": 123,
        "worker_birth": "123456",
        "reaped_process_count": 3,
        **{
            key: "d" * 64
            for key in (
                "nonce",
                "argv_sha256",
                "code_sha256",
                "installation_sha256",
                "fixture_sha256",
                "prior_retirement_sha256",
                "exit_statuses_sha256",
                "request_sha256",
            )
        },
        "artifact": _ARTIFACT,
        "runtime_sha256": report["identity"]["runtime_sha256"],
        "worker_report_sha256": proof.digest_json(report),
    }


def _certified_report():
    report = _pending_report()
    evidence = _evidence(report)
    evidence["verified"] = True
    report.update(quiescence=evidence, cleanup_confirmed=True, rejected_legacy_start_verified=True)
    return report


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "signals",
        "timeout",
        "output_limit",
        "containment",
        "source",
        "fixture",
        "installation",
        "nonce",
        "prior_retirement",
        "runtime",
        "baseline",
        "reason",
        "native_review",
        "active_requests",
        "returncode",
        "worker_exit",
        "descendants",
        "unclosed_publisher",
        "changed_worker",
        "changed_private_checkpoint",
    ],
)
def test_every_certificate_and_exact_rejection_fact_is_mandatory(mutation):
    report = _certified_report()
    evidence = report["quiescence"]
    if mutation == "signals":
        evidence["termination_signals_sent"] = 1
    elif mutation in {"timeout", "output_limit", "containment"}:
        evidence[
            {"timeout": "timed_out", "output_limit": "limit_exceeded", "containment": "containment_failed"}[mutation]
        ] = True
    elif mutation in {"source", "fixture", "installation"}:
        evidence[
            {"source": "code_unchanged", "fixture": "fixture_unchanged", "installation": "installation_unchanged"}[
                mutation
            ]
        ] = False
    elif mutation == "nonce":
        evidence["nonce"] = ""
    elif mutation == "prior_retirement":
        evidence["prior_retirement_sha256"] = "e" * 64
    elif mutation == "runtime":
        evidence["runtime_sha256"] = "e" * 64
    elif mutation == "baseline":
        report["identity"]["build_sha"] = "e" * 40
    elif mutation == "reason":
        report["publisher_at_failure"]["reason"] = "native_policy_snapshot_cache_invalid"
    elif mutation == "native_review":
        report["native_review_started"] = True
    elif mutation == "active_requests":
        report["retirement_verification"]["active_hook_requests"] = 1
    elif mutation == "returncode":
        evidence["worker_return_code"] = 0
    elif mutation == "worker_exit":
        evidence["worker_exit_observed"] = False
    elif mutation == "descendants":
        evidence["descendants_exhausted"] = False
    elif mutation == "unclosed_publisher":
        report["retirement_verification"]["publisher_after_close"]["thread_alive"] = True
    elif mutation == "changed_worker":
        report["control_revision"] += 1
    elif mutation == "changed_private_checkpoint":
        report["policy_after"]["authority"]["sha256"] = "f" * 64
    assert proof.certificate_valid(report, prior_retirement_sha256="d" * 64) is (mutation is None)
    observed = driver.worker_evidence(
        _result(report, returncode=1), _ARTIFACT, "baseline_rollback", prior_retirement_sha256="d" * 64
    )
    assert observed["passed"] is False
    assert observed["verified_legacy_rejection"] is (mutation is None)
    # Failed resident-stop remains failed even when separate ownership proves cleanup.
    assert observed["worker"]["retirement_verification"]["return_code"] == 2
    assert observed["worker"]["retirement_verification"]["verified"] is False
    assert assert_privacy_safe(observed) == observed


def test_certificate_cannot_replace_previous_candidate_retirement():
    observed = driver.worker_evidence(_result(_certified_report(), returncode=1), _ARTIFACT, "baseline_rollback")
    assert observed["verified_legacy_rejection"] is False


@pytest.mark.parametrize("mutation", [None, "fixture", "checkpoint", "nonce", "code", "installation", "report"])
def test_checkpoint_is_committed_only_after_all_post_exit_bindings_match(tmp_path, monkeypatch, mutation):
    fixture = tmp_path / "fixture"
    fixture.mkdir(mode=0o700)
    journal = fixture / "transition-state.json"
    previous = {"phase": "candidate_reinstall", "revision": 1, "password": "never-exported", "receipts": ["retained"]}
    proof.write_private(journal, previous)
    report = _pending_report()
    checkpoint = previous | {
        "phase": "baseline_rollback",
        "revision": 1,
        "rejected_legacy": True,
        "policy_state": report["policy_before"],
    }
    evidence = _evidence(report)
    request = {"nonce": "d" * 64, "prior_retirement_sha256": "d" * 64, "code_sha256": "d" * 64}
    pending = {
        "fixture_sha256": proof.tree_digest(fixture),
        "previous_sha256": proof.digest_json(previous),
        "worker_report_sha256": proof.digest_json(report),
        "nonce": request["nonce"],
        "checkpoint": copy.deepcopy(checkpoint),
    }
    if mutation == "checkpoint":
        pending["checkpoint"]["receipts"] = []
    elif mutation == "nonce":
        pending["nonce"] = "e" * 64
    elif mutation == "report":
        pending["worker_report_sha256"] = "e" * 64
    proof.write_private(tmp_path / proof._PENDING, pending)
    if mutation == "fixture":
        (fixture / "unexpected").write_text("changed after worker exit")
    monkeypatch.setattr(proof, "code_digest", lambda: ("e" if mutation == "code" else "d") * 64)
    pins = {"runtime": {"sha256": "c" * 64}}
    monkeypatch.setattr(proof, "installation_pin", lambda _python: {} if mutation == "installation" else pins)
    proof._commit_continuation(report, evidence, request, tmp_path, fixture, pins, ("/unused/python",))
    assert proof.private_json(journal) == (checkpoint if mutation is None else previous)
    assert evidence["verified"] is (mutation is None)


def test_tree_digest_rejects_external_links(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    (tmp_path / "outside").write_text("authority")
    (root / "link").symlink_to(tmp_path / "outside")
    with pytest.raises(ValueError, match="tree_member_invalid"):
        proof.tree_digest(root)


def test_exact_immutable_baseline_pin_is_shared_with_receipt_contract():
    assert proof.AUDITED_BASELINE_SHA == receipts.AUDITED_BASELINE_SHA


@pytest.mark.parametrize("mutation", [None, "nonce", "arguments", "collector", "installation", "prior"])
def test_driver_binds_its_own_request_before_accepting_supervisor_result(tmp_path, monkeypatch, mutation):
    monkeypatch.setattr(driver.sys, "platform", "linux")
    fixture = tmp_path / "fixture"
    fixture.mkdir(mode=0o700)
    expected = tmp_path / "expected.json"
    proof.write_private(expected, _ARTIFACT)
    prior = {"phase": "candidate_reinstall", "passed": True, "worker": {"cleanup_confirmed": True}}
    pins = {"runtime": {"sha256": "c" * 64}}
    monkeypatch.setattr(driver, "installation_pin", lambda _python: pins)
    monkeypatch.setattr(driver, "code_digest", lambda: "d" * 64)

    def launch(argv, root, *, timeout_seconds):
        assert argv[2].endswith("installed_transition_quiescence.py")
        assert timeout_seconds == 195
        request = proof.private_json(root / "quiescence-request.json")
        assert request["arguments"][-1] == "baseline_rollback"
        report = _certified_report()
        certificate = report["quiescence"]
        certificate.update(
            nonce=request["nonce"],
            argv_sha256=request["argv_sha256"],
            code_sha256=request["code_sha256"],
            installation_sha256=proof.digest_json(pins),
            prior_retirement_sha256=proof.digest_json(prior),
            request_sha256=proof.digest_json(request),
        )
        if mutation is not None:
            field = {
                "nonce": "nonce",
                "arguments": "argv_sha256",
                "collector": "code_sha256",
                "installation": "installation_sha256",
                "prior": "prior_retirement_sha256",
            }[mutation]
            certificate[field] = "e" * 64
        return _result(report, returncode=1)

    monkeypatch.setattr(driver, "_run", launch)
    arguments = (
        "/unused/bin/python",
        "-I",
        "installed_transition_entry.py",
        "--expected",
        str(expected),
        "--fixture-root",
        str(fixture),
        "--phase",
        "baseline_rollback",
    )
    if mutation is None:
        observed = driver._run_phase(arguments, tmp_path, prior)
        assert observed.returncode == 1
        assert json.loads(observed.stdout)["passed"] is False
    else:
        with pytest.raises(RuntimeError, match="owner_binding_invalid"):
            driver._run_phase(arguments, tmp_path, prior)


@pytest.mark.parametrize("record", ["approval-authority.v1.json", "approval-authority-v4.json"])
def test_enrolled_fixture_cannot_use_unenrolled_boundary(tmp_path, record):
    assert proof.enrollment_records_absent(tmp_path) is True
    state = tmp_path / ".hol-guard" / "native-runtime"
    state.mkdir(parents=True)
    (state / record).write_text("present")
    assert proof.enrollment_records_absent(tmp_path) is False


@pytest.mark.parametrize("bad", [None, [], "bad", {"retirement_verification": None}])
def test_malformed_certificate_is_unaccepted(bad):
    report = _certified_report()
    report["quiescence"] = bad
    assert proof.certificate_valid(report, prior_retirement_sha256="d" * 64) is False
