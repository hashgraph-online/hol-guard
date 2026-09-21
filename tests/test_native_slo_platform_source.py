"""Platform refusal is valid denial evidence, never completed source review."""

from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bench_guard_native_installed_slo as installed
from scripts import native_slo_qualification_run as qualification
from scripts.native_slo_acceptance import scoped_acceptance
from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_qualification import compare_routes, sampling_gates
from scripts.native_slo_reporting import SloMeasurements, slo_result, summarize_measurements
from scripts.native_slo_source_witness import source_reference_denial_witness, source_review_witness
from scripts.native_slo_workloads import (
    build_cases,
    platform_scope_summary,
    validate_case,
    validate_native_result,
)
from tests.test_guard_native_qualification_corpus import _delivered
from tests.test_native_slo_acceptance import _reports


@pytest.fixture(scope="module")
def windows_cases(tmp_path_factory: pytest.TempPathFactory):
    return build_cases(tmp_path_factory.mktemp("windows-source-corpus"), system="Windows")


def test_windows_source_cases_prove_existing_platform_denial_without_full_review(windows_cases) -> None:
    source = [case for case in windows_cases if case.payload_kind == "source_file_ref"]
    assert source
    for case in source:
        assert case.validation_scope == "platform_source_reference_denial"
        assert not case.semantic_sample
        assert case.native_expected is not None
        assert case.native_expected.decision == "deny"
        reason = "no_output_to_review"
        assert case.native_expected.reason_code == reason
        validate_native_result(case, dict(case.native_expected.fields))
        validate_case(case, _delivered(case), case.expected_route)
        assert not replace(case, validation_scope="full_semantics").semantic_sample


def test_windows_deny_cannot_be_replaced_with_a_full_scan_allow_or_content_match(windows_cases) -> None:
    case = next(case for case in windows_cases if case.case_id == "pi/PostToolUse/benign/1m")
    for reason in ("source_full_scan_allow", "source_secret_match", "output_scan_allow"):
        response = dict(case.native_expected.fields)
        response["reason_code"] = reason
        with pytest.raises(AssertionError):
            validate_native_result(case, response)
    response = _delivered(case)
    response.update(decision="allow", model_output_action="allow_original", policy_action="allow")
    with pytest.raises(AssertionError):
        validate_case(case, response, case.expected_route)


def test_supported_inline_work_and_unix_source_oracles_remain_unchanged(tmp_path: Path, windows_cases) -> None:
    unix = {case.case_id: case for case in build_cases(tmp_path, system="Linux")}
    for case in windows_cases:
        if case.payload_kind == "source_file_ref":
            if "source-digest-mismatch" not in case.case_id:
                assert unix[case.case_id].semantic_sample
                assert unix[case.case_id].native_expected.reason_code != case.native_expected.reason_code
        else:
            assert case.expected == unix[case.case_id].expected
            assert case.native_expected == unix[case.case_id].native_expected
            assert case.semantic_sample == unix[case.case_id].semantic_sample
    scope = platform_scope_summary(tuple(unix.values()), list(unix))
    persisted = json.loads(json.dumps(assert_privacy_safe({"platform_scope": scope})))
    assert persisted["platform_scope"]["reference_review_qualified"] is True
    assert persisted["platform_scope"]["semantic_coverage"]["representation"]["file_reference"] > 0


def test_platform_report_excludes_denials_from_semantic_coverage(windows_cases) -> None:
    validated = [case.case_id for case in windows_cases]
    scope = platform_scope_summary(windows_cases, validated)
    assert scope["platform_denial_contract_passed"] is True
    assert scope["platform_denial_validated_cases"] == scope["platform_denial_declared_cases"] > 0
    assert scope["reference_review_supported"] is False
    assert scope["reference_review_qualified"] is False
    assert scope["platform_denial_timing_eligible"] is False
    assert "file_reference" not in scope["semantic_coverage"]["representation"]
    assert "1m" not in scope["semantic_coverage"]["size"]
    assert "max" not in scope["semantic_coverage"]["size"]
    partial = platform_scope_summary(windows_cases, [case.case_id for case in windows_cases if case.semantic_sample])
    assert partial["platform_denial_contract_passed"] is False
    assert partial["platform_denial_validated_cases"] == 0


def test_no_output_with_a_matching_claimed_digest_still_cannot_supply_source_timing() -> None:
    digest = "a" * 64
    request = {"guard_source_ref": {"output_sha256": digest}}
    for reason in ("no_output_to_review", "observe_no_output_to_review", "output_scan_allow"):
        worker = SimpleNamespace(
            _review_raw_hook_native=lambda _reason=reason, **_kwargs: {
                "authority": "rust",
                "result": {
                    "decision": "allow",
                    "model_output_action": "allow_original",
                    "reviewed_output_sha256": digest,
                    "reason_code": _reason,
                },
            }
        )
        with (
            pytest.raises(RuntimeError, match="complete native content review"),
            source_review_witness(worker, request),
        ):
            worker._review_raw_hook_native()


@pytest.mark.parametrize("mutation", [None, "authority", "reason", "allow", "digest", "missing", "duplicate"])
def test_platform_denial_witness_requires_the_exact_native_denial(mutation: str | None) -> None:
    native = {
        "decision": "deny",
        "model_output_action": "block",
        "policy_action": "block",
        "reason_code": "no_output_to_review",
    }
    edge = {"authority": "rust", "result": native}
    if mutation == "authority":
        edge["authority"] = "python"
    if mutation == "reason":
        native["reason_code"] = "source_secret_match"
    if mutation == "allow":
        native["decision"] = "allow"
    if mutation == "digest":
        native["reviewed_output_sha256"] = "a" * 64
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: edge)
    request = {"guard_source_ref": {"output_sha256": "a" * 64}}

    def run() -> None:
        with source_reference_denial_witness(worker, request):
            for _ in range(0 if mutation == "missing" else 2 if mutation == "duplicate" else 1):
                worker._review_raw_hook_native()

    if mutation is None:
        run()
    else:
        with pytest.raises(RuntimeError, match="exact platform source-reference denial"):
            run()


def test_unsupported_source_probes_continue_and_never_return_latency_observations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = []

    def denied(harness, event, size, payload):
        assert "guard_source_ref" in payload
        observed.append((harness, event, size))
        return {"size_class": size, "native_denial_validated": True, "headline_timing_eligible": False}

    session = SimpleNamespace(
        workspace=tmp_path,
        probe_source_reference_denial=denied,
        observe=lambda *_args: pytest.fail("source refusal entered headline observation path"),
    )
    monkeypatch.setattr(installed, "source_reference_supported", lambda: False)
    evidence = []
    samples = installed._run_sizes(
        session, (("pi", "PostToolUse"), ("codex", "PostToolUse")), unsupported_evidence=evidence
    )
    assert samples == []
    assert len(evidence) == len(observed) == 6
    assert {item[2] for item in observed} == {"250k", "1m", "5m"}


def test_windows_slo_continues_supported_work_after_refusal_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = []
    ordinary = Observation("pi", "PostToolUse", "1k", 1, "native_resident", True)

    def probe(harness, event, size, request):
        completed.append(size)
        return {"size_class": size, "native_denial_validated": True, "headline_timing_eligible": False}

    session = SimpleNamespace(
        workspace=tmp_path,
        readiness_ms=1,
        probe_source_reference_denial=probe,
        observe=lambda *_args: ordinary,
    )
    capacity = SimpleNamespace(
        concurrent_16=[],
        concurrent_64=[],
        errors_16=0,
        errors_64=0,
        rss_baseline=1,
        rss_peak=1,
        routes_16={},
        routes_64={},
        native_overloads_16=0,
        native_overloads_64=0,
    )
    monkeypatch.setattr(installed, "source_reference_supported", lambda: False)
    monkeypatch.setattr(installed, "AdapterSession", lambda _runtime: nullcontext(session))
    monkeypatch.setattr(installed, "_run_cold", lambda *_args: completed.append("cold") or [1])
    monkeypatch.setattr(installed, "_run_warm", lambda *_args: completed.append("warm") or [ordinary])
    monkeypatch.setattr(installed, "_run_recovery", lambda *_args: completed.append("recovery") or [1])
    monkeypatch.setattr(
        installed, "measure_capacity", lambda *_args, **_kwargs: completed.append("capacity") or capacity
    )
    monkeypatch.setattr(
        installed, "measure_registered_launcher", lambda *_args, **_kwargs: completed.append("launcher") or {}
    )
    monkeypatch.setattr(installed, "_readiness_samples", lambda *_args: completed.append("readiness") or [1])
    monkeypatch.setattr(installed, "process_rss_bytes", lambda: 1)
    measured = installed._measure_slo(
        tmp_path / "runtime",
        (("pi", "PostToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=2,
        include_capacity=True,
        launcher_iterations=1,
    )
    assert completed == ["cold", "warm", "250k", "1m", "5m", "recovery", "capacity", "launcher", "readiness"]
    assert measured.sizes == []
    assert len(measured.source_reference_denials) == 3
    assert measured.warm == [ordinary]
    report = slo_result({}, (("pi", "PostToolUse"),), {}, measured, summarize_measurements(measured), {})
    persisted = json.loads(json.dumps(report))
    evidence = persisted["reference_review"]
    assert evidence["full_review_qualified"] is False
    assert len(evidence["platform_denial_cases"]) == 3
    assert evidence["platform_denial_timing_eligible"] is False
    assert evidence["missing_scopes"] == [
        "source_reference_full_content_review",
        "source_reference_identity_verification",
    ]


def test_platform_scope_survives_sanitized_block_roundtrip(windows_cases, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qualification, "source_reference_supported", lambda: False)
    scope = platform_scope_summary(windows_cases, [case.case_id for case in windows_cases])
    corpus = {
        "coverage": {},
        "declared_cases": len(windows_cases),
        "validated_cases": len(windows_cases),
        "remaining_setups": [],
        "complete": False,
        "platform_scope": scope,
    }
    report = {
        "contract_corpus": corpus,
        "matrix": qualification.workload_matrix((("pi", "PostToolUse"),), corpus),
    }
    persisted = json.loads(json.dumps(assert_privacy_safe(report)))
    assert persisted["contract_corpus"]["platform_scope"] == scope
    matrix = persisted["matrix"]
    assert matrix["reference_review_supported"] is False
    assert matrix["reference_review_qualified"] is False
    assert matrix["missing_reference_scopes"] == scope["missing_scopes"]
    assert matrix["daemon_semantic_coverage"] == scope["semantic_coverage"]
    assert matrix["daemon_contract_complete"] is False


def test_denied_large_source_observation_cannot_enter_size_latency_summary() -> None:
    measurements = SloMeasurements(
        warm=[Observation("pi", "PostToolUse", "1k", 1, "native_resident", True)],
        sizes=[Observation("pi", "PostToolUse", "5m", 0.01, "native_resident", False)],
        recovery=[],
        cold=[],
        concurrent_16=[],
        concurrent_64=[],
        errors_16=0,
        errors_64=0,
        readiness=[],
        rss_baseline=1,
        rss_peak=1,
    )
    summary = summarize_measurements(measurements)
    assert summary.size_values["5m"] == []
    assert "5m" not in summary.size_p95
    assert summary.security_denials_by_size["5m"] == 1


def test_windows_missing_source_scope_cannot_be_qualified_by_supported_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(qualification, "source_reference_supported", lambda: False)
    corpus = {
        "coverage": {"size": {"1m": 30}},
        "declared_cases": 30,
        "validated_cases": 30,
        "remaining_setups": [],
        "complete": True,
        "platform_scope": {"reference_review_qualified": False},
    }
    matrix = qualification.workload_matrix((("pi", "PostToolUse"),), corpus)
    assert matrix["daemon_contract_complete"] is False
    assert matrix["reference_review_qualified"] is False
    assert matrix["missing_reference_scopes"] == [
        "source_reference_full_content_review",
        "source_reference_identity_verification",
    ]
    baseline, candidate = _reports()
    for report in baseline + candidate:
        report["contract_corpus"]["platform_scope"] = {"reference_review_qualified": False}
    compared = compare_routes([r["measurements"] for r in baseline], [r["measurements"] for r in candidate])
    accepted = json.loads(
        json.dumps(
            assert_privacy_safe(scoped_acceptance(baseline, candidate, compared, sampling_gates(compared, runs=5)))
        )
    )
    assert accepted["scopes"]["launcher.claude-code.PostToolUse"]["qualified"] is True
    assert accepted["scopes"]["reference_full_review"]["qualified"] is False
    assert accepted["program_qualification_complete"] is False
    assert "source_reference_full_content_review" in accepted["remaining_program_evidence"]
