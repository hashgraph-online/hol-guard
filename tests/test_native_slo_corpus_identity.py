"""Fixed requests remain comparable; newly supported source reads remain untimed."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from scripts import native_slo_source_witness as witness
from scripts import native_slo_workloads as workloads
from scripts.native_slo_acceptance import scoped_acceptance
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_corpus_identity import corpus_identity, paired_corpus_identity
from scripts.native_slo_qualification_run import workload_matrix
from tests.test_native_slo_windows_source_capability import _status


@pytest.fixture
def declared_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Construct declaration-only reports from the actual frozen case builder."""
    runtime = tmp_path / "runtime"
    monkeypatch.setattr(workloads.platform, "system", lambda: "Windows")
    definitions = []
    reports = []
    cases_by_arm = []
    for baseline in (True, False):
        features = () if baseline else ("post-tool-source-read-windows-handles-v1",)
        status = _status(runtime, features)
        monkeypatch.setattr(witness, "native_runtime_status", lambda _status=status: _status)
        cases = workloads.build_cases(tmp_path, runtime=runtime)
        cases_by_arm.append(cases)
        ids = [case.case_id for case in cases]
        contract = {
            "coverage": {"delivered": dict(Counter(case.expected.decision for case in cases))},
            "declared_cases": len(cases),
            "validated_cases": len(cases),
            "remaining_setups": [],
            "complete": not baseline,
            "platform_scope": workloads.platform_scope_summary(cases, ids),
        }
        definition = {
            "matrix": workload_matrix((("pi", "PostToolUse"),), contract, runtime=runtime),
            "manifest_digest": hashlib.sha256(json.dumps(workloads.corpus_manifest()).encode()).hexdigest(),
            "oracle_digest": workloads.oracle_source_digest(),
            "oracle_selection_digest": hashlib.sha256(Path(witness.__file__).read_bytes()).hexdigest(),
            "validated_digest": hashlib.sha256(json.dumps(ids).encode()).hexdigest(),
            "launcher_validated_digest": "c" * 64,
            "fixtures": [{"hook_event_name": "PostToolUse", "tool_output": "ordinary"}],
            "native_client": [{"case": "benign"}, {"case": "secret"}],
            "launcher": [{"case": "benign"}, {"case": "block"}],
        }
        definitions.append(definition)
        reports.append(
            {
                **corpus_identity(definition),
                "runtime": {"build_sha": "2e672d2d950c6ec471005ddba46e49bba16dc23b" if baseline else "f" * 40},
                "contract_corpus": contract,
            }
        )
    assert all(
        baseline.case_id == candidate.case_id and baseline.payload == candidate.payload
        for baseline, candidate in zip(*cases_by_arm, strict=True)
    )
    return definitions, reports


def test_windows_source_feature_keeps_shared_requests_and_separate_untimed_evidence(declared_pair) -> None:
    _, (baseline, candidate) = declared_pair
    assert baseline["corpus_digest"] == candidate["corpus_digest"]
    assert baseline["contract_evidence_digest"] != candidate["contract_evidence_digest"]
    result = paired_corpus_identity([baseline], [candidate])
    assert result["reference_oracle_profiles"] == {
        "baseline": "windows_refusal_v1",
        "candidate": "windows_handles_v1",
    }
    assert result["reference_feature_evidence"] == {
        "baseline_full_review": False,
        "candidate_full_review": True,
        "headline_timing_eligible": False,
        "reference_performance_comparison_available": False,
    }
    acceptance = scoped_acceptance([baseline], [candidate], {}, {"independent_runs": True})
    assert acceptance["scopes"]["reference_full_review"]["qualified"] is False
    assert acceptance["migration_benefit_go"] is False


def test_serialized_qualification_blocks_keep_exact_finite_oracle_evidence(declared_pair) -> None:
    _, reports = declared_pair
    baseline, candidate = [json.loads(json.dumps(assert_privacy_safe(report))) for report in reports]
    identity = paired_corpus_identity([baseline], [candidate])
    restored = json.loads(json.dumps(assert_privacy_safe(identity)))
    assert restored["reference_oracle_profiles"] == {
        "baseline": "windows_refusal_v1",
        "candidate": "windows_handles_v1",
    }
    assert restored["reference_feature_evidence"] == {
        "baseline_full_review": False,
        "candidate_full_review": True,
        "headline_timing_eligible": False,
        "reference_performance_comparison_available": False,
    }
    assert baseline["corpus_digest"] == candidate["corpus_digest"]
    assert restored["contract_evidence_digests"] == {
        "baseline": reports[0]["contract_evidence_digest"],
        "candidate": reports[1]["contract_evidence_digest"],
    }


@pytest.mark.parametrize("arm", (0, 1))
def test_serialized_block_requires_its_explicit_oracle_profile(declared_pair, arm: int) -> None:
    _, reports = declared_pair
    restored = [json.loads(json.dumps(assert_privacy_safe(report))) for report in reports]
    restored[arm].pop("reference_oracle_profile")
    with pytest.raises(RuntimeError, match="source oracle profile changed within a paired arm"):
        paired_corpus_identity([restored[0]], [restored[1]])


@pytest.mark.parametrize(
    "field", ["fixtures", "native_client", "launcher", "manifest_digest", "oracle_digest", "validated_digest"]
)
def test_changed_requests_or_oracle_implementation_still_reject_the_pair(declared_pair, field: str) -> None:
    definitions, (baseline, candidate) = declared_pair
    changed = deepcopy(definitions[1])
    changed[field] = "different"
    candidate = {**candidate, **corpus_identity(changed)}
    with pytest.raises(RuntimeError, match="different corpus definitions"):
        paired_corpus_identity([baseline], [candidate])


@pytest.mark.parametrize("field", ["daemon_routes", "required_sizes", "concurrency", "observed_platform"])
def test_changed_fixed_matrix_is_not_erased_by_coverage_projection(declared_pair, field: str) -> None:
    definitions, (baseline, candidate) = declared_pair
    changed = deepcopy(definitions[1])
    changed["matrix"][field] = "linux-x64" if field == "observed_platform" else ["different"]
    candidate = {**candidate, **corpus_identity(changed)}
    with pytest.raises(RuntimeError, match="different corpus definitions"):
        paired_corpus_identity([baseline], [candidate])


@pytest.mark.parametrize("mutation", ["baseline_build", "baseline_denial", "candidate_full_review", "scope"])
def test_source_transition_requires_exact_baseline_and_completed_candidate_evidence(
    declared_pair, mutation: str
) -> None:
    _, original = declared_pair
    baseline, candidate = deepcopy(original)
    if mutation == "baseline_build":
        baseline["runtime"]["build_sha"] = "d" * 40
    elif mutation == "baseline_denial":
        baseline["contract_corpus"]["platform_scope"]["platform_denial_contract_passed"] = False
    elif mutation == "candidate_full_review":
        candidate["contract_corpus"]["platform_scope"]["reference_review_qualified"] = False
    else:
        candidate.pop("corpus_definition_scope")
    with pytest.raises(RuntimeError):
        paired_corpus_identity([baseline], [candidate])


def test_profile_and_evidence_must_be_stable_within_each_arm(declared_pair) -> None:
    _, (baseline, candidate) = declared_pair
    for field, value in (("reference_oracle_profile", "unix_source_v1"), ("contract_evidence_digest", "a" * 64)):
        changed = {**candidate, field: value}
        with pytest.raises(RuntimeError, match="within a paired arm"):
            paired_corpus_identity([baseline, baseline], [candidate, changed])


def test_equal_profiles_keep_exact_contract_evidence_equality(declared_pair) -> None:
    definitions, (_, candidate) = declared_pair
    changed = deepcopy(definitions[1])
    changed["matrix"]["daemon_coverage"] = {"different": 1}
    other = {**candidate, **corpus_identity(changed)}
    assert other["corpus_digest"] == candidate["corpus_digest"]
    with pytest.raises(RuntimeError, match="without a source oracle transition"):
        paired_corpus_identity([candidate], [other])


@pytest.mark.parametrize("digest", ["same", "a" * 64])
def test_equal_unscoped_reports_are_rejected(digest: str) -> None:
    with pytest.raises(RuntimeError, match="corpus definition scopes differ"):
        paired_corpus_identity([{"corpus_digest": digest}], [{"corpus_digest": digest}])


def test_changed_unscoped_request_digests_are_rejected() -> None:
    with pytest.raises(RuntimeError, match="different corpus definitions"):
        paired_corpus_identity([{"corpus_digest": "one"}], [{"corpus_digest": "two"}])


def test_new_oracle_profiles_cannot_opt_out_by_omitting_both_scope_fields(declared_pair) -> None:
    _, original = declared_pair
    baseline, candidate = deepcopy(original)
    baseline.pop("corpus_definition_scope")
    candidate.pop("corpus_definition_scope")
    with pytest.raises(RuntimeError, match="corpus definition scopes differ"):
        paired_corpus_identity([baseline], [candidate])


@pytest.mark.parametrize("value", ["short", "A" * 64, "z" * 64])
def test_new_request_identity_requires_a_sha256_digest(declared_pair, value: str) -> None:
    _, original = declared_pair
    baseline, candidate = deepcopy(original)
    baseline["corpus_digest"] = candidate["corpus_digest"] = value
    with pytest.raises(RuntimeError, match="request digest is invalid"):
        paired_corpus_identity([baseline], [candidate])
