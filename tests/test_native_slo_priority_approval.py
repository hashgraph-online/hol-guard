"""Synthetic report/orchestration tests; these supply no installed evidence."""

from __future__ import annotations

import copy
import json

import pytest

from scripts import native_slo_priority_approval as scenarios
from scripts.native_slo_contract import assert_privacy_safe


def _valid(scenario, *, renewed=False):
    before = {"generation": 1, "policy_digest": "d" * 64, "runtime_identity": "e" * 64}
    after = {**before, "generation": 2} if renewed else dict(before)
    count = 1 if scenario == "approval_wait_expiry" else 3 if scenario == "ambiguous_completion_retry" else 2
    allow = scenario == "ambiguous_completion_retry" or (scenario == "resident_restart_pending" and not renewed)
    attempts = 2 if scenario == "ambiguous_completion_retry" else 1
    fault = {
        "applied": True,
        "pending_observed": True,
        "original_wait_present": True,
        "original_wait_live": True,
        "binding_before": before,
    }
    if scenario == "approval_wait_expiry":
        fault.update(configured_wait_seconds=2, delay_entered=True, original_wait_expired=True)
    elif scenario == "ambiguous_completion_retry":
        fault["completed_response_dropped"] = True
    elif scenario == "resident_restart_pending":
        fault.update(contained=True, acknowledged=True, binding_after=after)
    else:
        after = {**before, "generation": 2, "policy_digest": "f" * 64}
        fault.update(mutation_returned=True, acknowledged=True, binding_after=after, effective_action="block")
    native = [
        {
            "evaluation_index": index,
            "decision_id": f"{index + 1:064x}",
            "request_digest": "c" * 64,
            "policy_generation": 1,
            "policy_digest": before["policy_digest"],
            "runtime_identity": before["runtime_identity"],
            "decision": "deny",
            "policy_action": "review",
            "minimum_action": "review",
            "rust_authority": True,
            "receipt_valid": True,
            "program_binding_present": True,
            "committed": True,
            "commit_binding_valid": True,
        }
        for index in range(count)
    ]
    if renewed or scenario == "stricter_policy_pending":
        native[-1].update(
            policy_generation=after["generation"], policy_digest=after["policy_digest"], request_digest="b" * 64
        )
    if scenario == "stricter_policy_pending":
        native[-1].update(policy_action="block", minimum_action="block")
    return {
        "scenario": scenario,
        "request_id": "a" * 32,
        "state": "resolved",
        "resolution": "allow",
        "approval_durable": True,
        "matching": "exact_identity_and_new_row",
        "authority": "ordinary_local_review",
        "binding_present": True,
        "native_completion_available": True,
        "witness_overflow": False,
        "settled": True,
        "revalidation_routes": {},
        "continuation_capability": "suspended-response",
        "continuation_status": "resumed" if allow else "waiting",
        "fault": fault,
        "native_witnesses": native,
        "whole_operation_routes": {"native_resident": count},
        "posts": [{"request_id": "a" * 32, "body_digest": "b" * 64} for _ in range(attempts)],
        "responses": [
            {
                "completed": allow,
                "action": "allow" if allow else None,
                "status": 200 if allow else 409,
                "replayed": index > 0,
                "delivered": not (scenario == "ambiguous_completion_retry" and index == 0),
                "error": None if allow else "fresh_policy_revalidation_failed",
            }
            for index in range(attempts)
        ],
        "live_decision": [
            {
                "request_id": "a" * 32,
                "completed": True,
                "action": "allow",
                "fresh_allow_authorized": True,
                "replayed": index > 0,
            }
            for index in range(attempts)
        ]
        if allow
        else [],
        "local_once": {
            "records": 1,
            "claimed": int(allow),
            "unclaimed_verified": not allow,
            "claimed_verified": allow,
        },
    }


@pytest.mark.parametrize("scenario", scenarios.SCENARIOS)
def test_complete_independent_witnesses_determine_delivered_verdict(scenario):
    result = _valid(scenario)
    assert scenarios.validate_fault_evidence(scenario, result) == (
        "allow" if scenario in {"resident_restart_pending", "ambiguous_completion_retry"} else "deny"
    )
    assert assert_privacy_safe(result) == result


def test_real_restart_with_renewed_generation_requires_a_new_review():
    result = _valid("resident_restart_pending", renewed=True)
    assert scenarios.validate_fault_evidence("resident_restart_pending", result) == "deny"
    result["native_witnesses"][-1]["policy_generation"] = 1
    with pytest.raises(RuntimeError, match="acknowledgment_unproven"):
        scenarios.validate_fault_evidence("resident_restart_pending", result)


@pytest.mark.parametrize(
    "path,value",
    [
        (("state",), "failed"),
        (("request_id",), None),
        (("approval_durable",), False),
        (("binding_present",), False),
        (("native_completion_available",), False),
        (("witness_overflow",), True),
        (("settled",), False),
        (("continuation_capability",), "retry-only"),
        (("revalidation_routes",), {"native_resident": 1}),
        (("whole_operation_routes",), {"native_resident": 2}),
        (("whole_operation_routes",), {"native_resident": 3, "native_oneshot": 1}),
        (("fault", "applied"), False),
        (("fault", "pending_observed"), False),
        (("fault", "original_wait_live"), False),
        (("fault", "completed_response_dropped"), False),
        (("native_witnesses", 1, "rust_authority"), False),
        (("native_witnesses", 1, "receipt_valid"), False),
        (("native_witnesses", 1, "program_binding_present"), False),
        (("native_witnesses", 1, "committed"), False),
        (("native_witnesses", 1, "commit_binding_valid"), False),
        (("native_witnesses", 1, "request_digest"), "f" * 64),
        (("native_witnesses", 1, "request_digest"), None),
        (("native_witnesses", 1, "evaluation_index"), 0),
        (("native_witnesses", 1, "policy_generation"), 2),
        (("posts", 1, "request_id"), "f" * 32),
        (("posts", 1, "body_digest"), "f" * 64),
        (("posts", 1, "body_digest"), None),
        (("local_once", "records"), 2),
        (("local_once", "claimed"), 2),
        (("local_once", "claimed_verified"), False),
        (("local_once", "unclaimed_verified"), True),
        (("live_decision", 1, "request_id"), "f" * 32),
        (("live_decision", 1, "replayed"), False),
        (("live_decision", 1, "fresh_allow_authorized"), False),
        (("responses", 0, "delivered"), True),
        (("responses", 1, "delivered"), False),
        (("responses", 1, "completed"), False),
        (("responses", 1, "status"), 503),
        (("responses", 1), None),
    ],
)
def test_ambiguous_allow_rejects_missing_forged_extra_or_duplicate_witnesses(path, value):
    result = _valid("ambiguous_completion_retry")
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(RuntimeError):
        scenarios.validate_fault_evidence("ambiguous_completion_retry", result)


@pytest.mark.parametrize(
    "scenario,path,value",
    [
        ("approval_wait_expiry", ("fault", "original_wait_expired"), False),
        ("approval_wait_expiry", ("fault", "configured_wait_seconds"), 120),
        ("approval_wait_expiry", ("responses", 0, "error"), "unrelated_failure"),
        ("approval_wait_expiry", ("continuation_status",), "resumed"),
        ("stricter_policy_pending", ("fault", "mutation_returned"), False),
        ("stricter_policy_pending", ("fault", "binding_after", "generation"), 1),
        ("stricter_policy_pending", ("native_witnesses", 1, "minimum_action"), "review"),
        ("resident_restart_pending", ("fault", "contained"), False),
        ("resident_restart_pending", ("fault", "acknowledged"), False),
        ("resident_restart_pending", ("responses", 0, "delivered"), False),
    ],
)
def test_fault_cases_do_not_credit_an_unwitnessed_failure_or_control(scenario, path, value):
    result = _valid(scenario)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(RuntimeError):
        scenarios.validate_fault_evidence(scenario, result)


def test_exact_retry_can_reproduce_a_deterministic_receipt_identity():
    result = _valid("ambiguous_completion_retry")
    for row in result["native_witnesses"]:
        row["decision_id"] = "f" * 64
    assert scenarios.validate_fault_evidence("ambiguous_completion_retry", result) == "allow"


@pytest.mark.parametrize("ordinary_passed", [True, False])
@pytest.mark.parametrize("failed_case", [None, *scenarios.SCENARIOS])
def test_baseline_failure_is_retained_and_every_remaining_fault_is_offered(
    tmp_path, monkeypatch, ordinary_passed, failed_case
):
    offered = []

    def ordinary(*_args, **_kwargs):
        if not ordinary_passed:
            raise RuntimeError("qualification_ordinary_baseline_unsupported")
        return {"implemented_scope_passed": True}

    def fault(_runtime, scenario, *, receipt_profile, report):
        offered.append(scenario)
        assert receipt_profile == "baseline_2e672d2"
        report["witness"] = {"observed_attempts": 1, "original_wait_present": scenario != failed_case}
        if scenario == failed_case:
            raise RuntimeError("qualification_baseline_native_wait_unsupported")
        report.update(status="validated", passed=True)

    monkeypatch.setattr(scenarios, "run_registered_approval_corpus", ordinary)
    monkeypatch.setattr(scenarios, "_fault_case", fault)
    evidence = tmp_path / "cases.jsonl"
    report = scenarios.run_priority_approval_scenarios(
        tmp_path / "unused", evidence_file=evidence, receipt_profile="baseline_2e672d2"
    )
    assert offered == list(scenarios.SCENARIOS)
    assert report["passed"] is (ordinary_passed and failed_case is None)
    assert report["stored_approval_ttl_exercised"] is False
    assert report["expiry_scope"] == "original_browser_wait_deadline"
    assert report["headline_timing_eligible"] is False
    rows = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert len(rows) == 2 * len(scenarios.SCENARIOS)
    assert [row["scenario"] for row in rows if row["status"] == "offered"] == offered
    for row in rows:
        assert row["headline_timing_eligible"] is False
    if failed_case is not None:
        failure = report["codex_faults"][failed_case]
        assert failure["passed"] is False
        assert failure["witness"]["observed_attempts"] == 1
        assert "failure" in failure


def test_poll_deadline_returns_the_partial_native_witness_without_filling_missing_counts(monkeypatch):
    values = iter((0, 0, 3))
    monkeypatch.setattr(scenarios.time, "monotonic", lambda: next(values))
    monkeypatch.setattr(scenarios.time, "sleep", lambda _seconds: None)
    partial = {"state": "resolved", "settled": False, "native_witnesses": [{"committed": False}]}

    class Session:
        def control(self, operation, **kwargs):
            assert operation == "launcher_approval_fault_result" and kwargs == {"operation_id": "a" * 32}
            return copy.deepcopy(partial)

    assert scenarios._await_fault(Session(), "a" * 32) == partial


def test_required_flat_proof_survives_actual_block_nesting_and_json_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(
        scenarios, "run_registered_approval_corpus", lambda *_args, **_kwargs: {"implemented_scope_passed": True}
    )

    def fault(_runtime, scenario, *, receipt_profile, report):
        assert receipt_profile == "candidate"
        witness = _valid(scenario)
        verdict = scenarios.validate_fault_evidence(scenario, witness)
        report.update(
            witness=witness,
            witness_validation_attempted=True,
            witness_validation_passed=True,
            expected_delivery=verdict,
            delivery=verdict,
            stdout_and_exit_checked=True,
            passed=True,
            status="validated",
        )

    monkeypatch.setattr(scenarios, "_fault_case", fault)
    side = scenarios.run_priority_approval_scenarios(tmp_path / "unused", evidence_file=tmp_path / "cases.jsonl")
    # This is the exact nesting passed to assert_privacy_safe in run_block.
    block = {
        "schema": "hol-guard.native-qualification-block.v1",
        "additional_scenarios": {
            "schema": "hol-guard.additional-installed-scenarios.v1",
            "priority_approval": side,
        },
    }
    published = json.loads(json.dumps(assert_privacy_safe(block)))
    approved = published["additional_scenarios"]["priority_approval"]
    assert approved["codex_fault_proofs"] == side["codex_fault_proofs"]
    retry = approved["codex_fault_proofs"]["ambiguous_completion_retry"]
    assert retry["case_passed"] is retry["bindings_validated"] is True
    assert retry["native_invocations"] == retry["resident_route_count"] == retry["verified_committed_receipts"] == 3
    assert retry["other_route_count"] == 0
    assert retry["authority_records"] == retry["authority_claimed"] == 1
    assert retry["claimed_authority_verified"] is True
    assert retry["post_attempts"] == retry["completion_calls"] == retry["completed_allow_count"] == 2
    assert retry["distinct_post_digests"] == retry["replayed_completion_count"] == 1
    assert retry["dropped_response_count"] == retry["delivered_response_count"] == 1
    policy = approved["codex_fault_proofs"]["stricter_policy_pending"]
    assert policy["before_generation"] == 1 and policy["after_generation"] == 2
    assert policy["before_policy_digest"] != policy["after_policy_digest"]
    assert policy["first_request_digest"] != policy["last_request_digest"]
    assert policy["delivery"] == "deny" and policy["authority_claimed"] == 0
    # Even one extra public wrapper leaves the flat scalar fields intact.
    wrapped = json.loads(json.dumps(assert_privacy_safe({"run_block": block})))
    assert (
        wrapped["run_block"]["additional_scenarios"]["priority_approval"]["codex_fault_proofs"]
        == side["codex_fault_proofs"]
    )
    assert "truncated" not in json.dumps(approved["codex_fault_proofs"])


def test_failed_flat_proof_preserves_unknown_counts_instead_of_inventing_zero():
    proof = scenarios._flat_fault_proof({"passed": False, "status": "failed"})
    assert proof["case_passed"] is proof["bindings_validated"] is False
    for name in (
        "native_invocations",
        "resident_route_count",
        "other_route_count",
        "post_attempts",
        "authority_records",
        "authority_claimed",
        "completion_calls",
        "response_count",
    ):
        assert proof[name] is None
