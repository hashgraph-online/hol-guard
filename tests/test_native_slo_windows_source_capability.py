"""A Windows capability selects an oracle; the native result must still prove it."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)
from scripts import native_slo_source_witness as witness
from scripts import native_slo_workloads as workloads
from scripts.native_slo_qualification_run import workload_matrix
from tests.test_guard_native_qualification_corpus import _delivered

_FEATURE = "post-tool-source-read-windows-handles-v1"


def _status(runtime: Path, features: tuple[str, ...]) -> NativeRuntimeStatus:
    return NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="native_ready",
        identity=NativeRuntimeIdentity(runtime, 1, 1, "a" * 64),
        capabilities=NativeRuntimeCapabilities(
            1, "1.0.0", "b" * 64, "c" * 40, "x86_64-pc-windows-msvc", features
        ),
    )


@pytest.mark.parametrize("features", [(), ("post-tool-source-read-v1",)])
def test_baseline_and_generic_feature_keep_the_exact_windows_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, features: tuple[str, ...]
) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setattr(witness, "native_runtime_status", lambda: _status(runtime, features))
    bound = workloads.build_cases(tmp_path, system="Windows", runtime=runtime)
    original = workloads.build_cases(tmp_path, system="Windows")
    assert bound == original
    assert not workloads.source_reference_supported(system="Windows", runtime=runtime)
    scope = workloads.platform_scope_summary(bound, [case.case_id for case in bound])
    assert scope["reference_review_qualified"] is False
    assert scope["platform_denial_contract_passed"] is True


@pytest.mark.parametrize(
    "mutation", ["mode", "available", "compatible", "reason", "identity", "capabilities", "path", "target"]
)
def test_feature_from_an_unbound_or_unready_runtime_cannot_select_the_source_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    runtime = tmp_path / "runtime"
    status = _status(runtime, (_FEATURE,))
    if mutation == "path":
        assert status.identity is not None
        status = replace(status, identity=replace(status.identity, path=tmp_path / "other-runtime"))
    elif mutation == "target":
        assert status.capabilities is not None
        status = replace(status, capabilities=replace(status.capabilities, target="x86_64-unknown-linux-gnu"))
    else:
        value = {"mode": "force", "available": False, "compatible": False, "reason": "native_unavailable"}.get(
            mutation
        )
        status = replace(status, **{mutation: value})
    monkeypatch.setattr(witness, "native_runtime_status", lambda: status)
    with pytest.raises(RuntimeError, match="identity is not bound"):
        workloads.source_reference_supported(system="Windows", runtime=runtime)


def test_exact_candidate_capability_preserves_all_full_source_and_privacy_oracles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setattr(witness, "native_runtime_status", lambda: _status(runtime, (_FEATURE,)))
    candidate = workloads.build_cases(tmp_path, system="Windows", runtime=runtime)
    full_source = workloads.build_cases(tmp_path, system="Linux")
    assert candidate == full_source
    sources = [case for case in candidate if case.payload_kind == "source_file_ref"]
    assert {case.harness for case in sources}.issuperset({"pi", "omp"})
    assert {case.expected.reason_class for case in sources}.issuperset(
        {"benign", "completed_block", "observation"}
    )
    for case in sources:
        assert case.native_expected is not None
        workloads.validate_native_result(case, dict(case.native_expected.fields))
        workloads.validate_case(case, _delivered(case), case.expected_route)
    benign = next(case for case in sources if case.expected.reason_class == "benign")
    assert benign.native_expected is not None
    refused = dict(benign.native_expected.fields)
    refused.update(reason_code="no_output_to_review", decision="deny", model_output_action="block")
    with pytest.raises(AssertionError):
        workloads.validate_native_result(benign, refused)
    false_digest = dict(benign.native_expected.fields)
    false_digest["reviewed_output_sha256"] = "0" * 64
    with pytest.raises(AssertionError):
        workloads.validate_native_result(benign, false_digest)
    assert all(
        "reviewed_excerpt" not in case.native_expected.fields
        for case in sources
        if case.native_expected is not None
    )


def test_candidate_support_alone_does_not_report_completed_content_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setattr(witness, "native_runtime_status", lambda: _status(runtime, (_FEATURE,)))
    monkeypatch.setattr(workloads.platform, "system", lambda: "Windows")
    cases = workloads.build_cases(tmp_path, runtime=runtime)
    scope = workloads.platform_scope_summary(cases, [])
    corpus = {
        "coverage": {},
        "declared_cases": len(cases),
        "validated_cases": 0,
        "remaining_setups": [],
        "complete": False,
        "platform_scope": scope,
    }
    matrix = workload_matrix((("pi", "PostToolUse"),), corpus, runtime=runtime)
    assert matrix["reference_review_supported"] is True
    assert matrix["reference_review_qualified"] is False
    assert matrix["daemon_contract_complete"] is False
    assert matrix["missing_reference_scopes"] == [
        "source_reference_full_content_review",
        "source_reference_identity_verification",
    ]
