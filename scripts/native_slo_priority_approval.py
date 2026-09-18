"""Retain real registered approval flows and bounded Codex continuation faults.

Every scenario owns a fresh installed daemon and uses the actual generated
registration. Instrumented faults are semantic evidence only. A failing older
arm remains a failure and cannot prevent collecting the other scenarios.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from scripts.native_slo_approval_fault_fixture import SCENARIOS
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_launcher_corpus import (
    _run_registered,
    installed_expectation,
    run_registered_approval_corpus,
    validate_installed_response,
)
from scripts.native_slo_launcher_review import approved_review_case
from scripts.native_slo_priority_launchers import LauncherSession, install_priority_launchers
from scripts.native_slo_workloads import build_cases


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError("qualification_approval_fault_" + reason)


def _is_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(length) + "}", value) is not None


def _generation_increased(before: Mapping[str, object], after: Mapping[str, object]) -> bool:
    old, new = before.get("generation"), after.get("generation")
    return type(old) is int and type(new) is int and new > old


def _matches_binding(receipt: Mapping[str, object], binding: Mapping[str, object]) -> bool:
    return all(
        receipt.get(receipt_key) == binding.get(binding_key)
        for receipt_key, binding_key in (
            ("policy_generation", "generation"),
            ("policy_digest", "policy_digest"),
            ("runtime_identity", "runtime_identity"),
        )
    )


def validate_fault_evidence(scenario: str, result: Mapping[str, Any]) -> str:
    """Return the required delivered verdict from independent fault witnesses."""
    _require(scenario in SCENARIOS and result.get("scenario") == scenario, "scenario_mismatch")
    _require(
        _is_hex(result.get("request_id"), 32)
        and result.get("state") == "resolved"
        and result.get("resolution") == "allow"
        and result.get("approval_durable") is True
        and result.get("matching") == "exact_identity_and_new_row"
        and result.get("authority") == "ordinary_local_review"
        and result.get("binding_present") is True
        and result.get("native_completion_available") is True
        and result.get("witness_overflow") is False
        and result.get("settled") is True
        and result.get("revalidation_routes") == {}
        and result.get("continuation_capability") == "suspended-response",
        "authority_or_scope_unproven",
    )
    fault = result.get("fault")
    _require(
        isinstance(fault, Mapping)
        and fault.get("applied") is True
        and fault.get("pending_observed") is True
        and fault.get("original_wait_present") is True
        and fault.get("original_wait_live") is True
        and "unsupported" not in fault,
        "not_applied_to_original_wait",
    )
    assert isinstance(fault, Mapping)
    before = fault.get("binding_before")
    native = result.get("native_witnesses")
    expected_count = 1 if scenario == "approval_wait_expiry" else 3 if scenario == "ambiguous_completion_retry" else 2
    _require(
        isinstance(before, Mapping)
        and isinstance(native, list)
        and len(native) == expected_count
        and all(
            isinstance(row, Mapping)
            and row.get("rust_authority") is True
            and row.get("receipt_valid") is True
            and row.get("program_binding_present") is True
            and row.get("committed") is True
            and row.get("commit_binding_valid") is True
            for row in native
        ),
        "native_receipts_unproven",
    )
    assert isinstance(native, list) and isinstance(before, Mapping)
    _require(
        [row.get("evaluation_index") for row in native] == list(range(expected_count))
        and all(type(row.get("evaluation_index")) is int for row in native)
        and all(_is_hex(row.get(key), 64) for row in native for key in ("decision_id", "request_digest"))
        and _matches_binding(native[0], before)
        and native[0].get("decision") == "deny"
        and native[0].get("policy_action") == native[0].get("minimum_action") == "review"
        and result.get("whole_operation_routes") == {"native_resident": expected_count},
        "fresh_native_route_conservation_failed",
    )
    # Receipt identity is deterministic. Exact retries may produce the same
    # receipt identity; freshness comes from distinct actual calls and route
    # conservation, with the committed receipt checked for every call.
    expected_allow = scenario == "ambiguous_completion_retry"
    if scenario in {"resident_restart_pending", "stricter_policy_pending"}:
        after = fault.get("binding_after")
        _require(
            fault.get("acknowledged") is True and isinstance(after, Mapping) and _matches_binding(native[-1], after),
            "acknowledgment_unproven",
        )
        assert isinstance(after, Mapping)
        if scenario == "stricter_policy_pending":
            _require(
                fault.get("mutation_returned") is True
                and fault.get("effective_action") == "block"
                and _generation_increased(before, after)
                and after.get("policy_digest") != before.get("policy_digest")
                and native[-1].get("decision") == "deny"
                and native[-1].get("policy_action") == native[-1].get("minimum_action") == "block",
                "stricter_generation_unproven",
            )
        else:
            _require(
                fault.get("contained") is True
                and native[-1].get("decision") == "deny"
                and native[-1].get("policy_action") == native[-1].get("minimum_action") == "review",
                "restart_containment_unproven",
            )
            # A renewed generation changes the exact request commitment. A
            # still-identical ACK can continue; a renewed one requires review.
            expected_allow = dict(before) == dict(after)
    elif scenario == "approval_wait_expiry":
        _require(
            fault.get("configured_wait_seconds") == 2
            and fault.get("delay_entered") is True
            and fault.get("original_wait_expired") is True,
            "natural_expiry_unproven",
        )
    posts, responses, completions = result.get("posts"), result.get("responses"), result.get("live_decision")
    attempts = 2 if scenario == "ambiguous_completion_retry" else 1
    _require(
        isinstance(posts, list)
        and isinstance(responses, list)
        and isinstance(completions, list)
        and len(posts) == len(responses) == attempts
        and all(
            isinstance(row, Mapping)
            and row.get("request_id") == result.get("request_id")
            and _is_hex(row.get("body_digest"), 64)
            for row in posts
        )
        and all(isinstance(row, Mapping) for row in [*responses, *completions])
        and len({row.get("body_digest") for row in posts}) == 1,
        "exact_attempts_unproven",
    )
    assert isinstance(completions, list) and isinstance(responses, list)
    expected_claimed = 1 if expected_allow else 0
    _require(
        result.get("local_once")
        == {
            "records": 1,
            "claimed": expected_claimed,
            "unclaimed_verified": not expected_allow,
            "claimed_verified": expected_allow,
        },
        "single_authority_unproven",
    )
    if expected_allow:
        _require(
            len(completions) == attempts
            and result.get("continuation_status") in {"resumed", "sent"}
            and all(
                row.get("completed") is True
                and row.get("request_id") == result.get("request_id")
                and row.get("action") == "allow"
                and row.get("fresh_allow_authorized") is True
                and row.get("replayed") is (index > 0)
                for index, row in enumerate(completions)
            )
            and all(
                row.get("completed") is True and row.get("action") == "allow" and row.get("status") == 200
                for row in responses
            )
            and len({row.get("request_digest") for row in native}) == 1
            and all(
                _matches_binding(row, before)
                and row.get("decision") == "deny"
                and row.get("policy_action") == row.get("minimum_action") == "review"
                for row in native
            ),
            "live_allow_or_replay_unproven",
        )
        if scenario == "ambiguous_completion_retry":
            _require(
                fault.get("completed_response_dropped") is True
                and [row.get("delivered") for row in responses] == [False, True]
                and [row.get("replayed") for row in responses] == [False, True],
                "ambiguous_retry_not_witnessed",
            )
        else:
            _require(responses[0].get("delivered") is True, "allow_delivery_unproven")
    else:
        _require(
            completions == []
            and result.get("continuation_status") not in {"resumed", "sent"}
            and all(
                row.get("completed") is False
                and row.get("status") == 409
                and row.get("error") == "fresh_policy_revalidation_failed"
                and row.get("delivered") is True
                for row in responses
            ),
            "unsafe_or_unexplained_completion",
        )
    return "allow" if expected_allow else "deny"


def _await_fault(session: Any, operation_id: str) -> Mapping[str, Any]:
    deadline = time.monotonic() + 2
    while True:
        result = session.control("launcher_approval_fault_result", operation_id=operation_id)
        if result.get("settled") is True or result.get("state") == "failed" or time.monotonic() >= deadline:
            return result
        time.sleep(0.01)


def _fault_case(runtime: Path, scenario: str, *, receipt_profile: str, report: dict[str, Any]) -> None:
    with DaemonFixture(runtime, policy="normal") as session:
        launcher = next(
            item
            for item in install_priority_launchers(cast(LauncherSession, cast(object, session)))
            if (item.harness, item.event) == ("codex", "PreToolUse")
        )
        original = next(
            case
            for case in build_cases(session.workspace)
            if case.harness == "codex"
            and case.event == "PreToolUse"
            and case.setup == "normal"
            and case.expected.reason_class == "review"
        )
        case = installed_expectation(replace(original, case_id=original.case_id + "-" + scenario))
        report.update(
            registration_sha256=launcher.registration_sha256,
            case_digest=hashlib.sha256(case.case_id.encode()).hexdigest(),
        )
        begun = session.control(
            "launcher_approval_fault_begin",
            scenario=scenario,
            payload=dict(case.payload),
            receipt_profile=receipt_profile,
        )
        report["begin"] = dict(begun)
        operation_id = begun.get("operation_id")
        _require(begun.get("state") == "waiting" and isinstance(operation_id, str), "begin_failed")
        assert isinstance(operation_id, str)
        report["process"] = {}
        try:
            response, _ = _run_registered(
                session, launcher, case, process_evidence=report["process"], approval_wait=True
            )
        except Exception:
            # A process timeout or invalid stdout still retains actual store,
            # native, mutation and completion facts collected on that host.
            report["witness"] = dict(_await_fault(session, operation_id))
            raise
        result = _await_fault(session, operation_id)
        report["witness"] = dict(result)
        report["witness_validation_attempted"] = True
        verdict = validate_fault_evidence(scenario, result)
        report.update(witness_validation_passed=True, expected_delivery=verdict)
        validate_installed_response(
            approved_review_case(case) if verdict == "allow" else case, response, "native_resident"
        )
        report.update(delivery=verdict, stdout_and_exit_checked=True)
    report.update(passed=True, status="validated")


def _flat_fault_proof(report: Mapping[str, Any]) -> dict[str, object]:
    """Keep required facts publishable through the outer block's depth limit.

    Missing observations remain null. Counts refer to observed calls/responses;
    duplicated deterministic receipt IDs never become duplicated authorities.
    Full observations remain in the separately written private case evidence.
    """
    witness = report.get("witness")
    witness = witness if isinstance(witness, Mapping) else {}
    fault = witness.get("fault")
    fault = fault if isinstance(fault, Mapping) else {}
    once = witness.get("local_once")
    once = once if isinstance(once, Mapping) else {}
    routes = witness.get("whole_operation_routes")
    route_counts = (
        cast(Mapping[str, int], routes)
        if isinstance(routes, Mapping)
        and all(isinstance(key, str) and type(value) is int for key, value in routes.items())
        else None
    )

    def rows(name: str) -> list[Mapping[str, Any]] | None:
        value = witness.get(name)
        return value if isinstance(value, list) and all(isinstance(row, Mapping) for row in value) else None

    native, posts, responses, completions = (
        rows(name) for name in ("native_witnesses", "posts", "responses", "live_decision")
    )
    proof: dict[str, object] = {
        "case_passed": report.get("passed") is True,
        "status": report.get("status"),
        "headline_timing_eligible": False,
        "witness_validation_attempted": report.get("witness_validation_attempted") is True,
        "bindings_validated": report.get("witness_validation_passed") is True,
        "expected_delivery": report.get("expected_delivery"),
        "delivery": report.get("delivery"),
        "approval_request_id": witness.get("request_id"),
        "approval_durable": witness.get("approval_durable"),
        "approval_binding_digest": witness.get("binding_digest"),
        "native_completion_available": witness.get("native_completion_available"),
        "continuation_status": witness.get("continuation_status"),
        "fault_applied": fault.get("applied"),
        "pending_observed": fault.get("pending_observed"),
        "original_wait_present": fault.get("original_wait_present"),
        "original_wait_live": fault.get("original_wait_live"),
        "original_wait_expired": fault.get("original_wait_expired"),
        "configured_wait_seconds": fault.get("configured_wait_seconds"),
        "resident_contained": fault.get("contained"),
        "policy_mutation_returned": fault.get("mutation_returned"),
        "policy_acknowledged": fault.get("acknowledged"),
        "completed_response_dropped": fault.get("completed_response_dropped"),
        "native_invocations": len(native) if native is not None else None,
        "distinct_receipt_identities": len({row.get("decision_id") for row in native}) if native is not None else None,
        "verified_committed_receipts": sum(row.get("commit_binding_valid") is True for row in native)
        if native is not None
        else None,
        "resident_route_count": route_counts.get("native_resident", 0) if route_counts is not None else None,
        "other_route_count": sum(value for key, value in route_counts.items() if key != "native_resident")
        if route_counts is not None
        else None,
        "authority_records": once.get("records"),
        "authority_claimed": once.get("claimed"),
        "unclaimed_authority_verified": once.get("unclaimed_verified"),
        "claimed_authority_verified": once.get("claimed_verified"),
        "post_attempts": len(posts) if posts is not None else None,
        "distinct_post_digests": len({row.get("body_digest") for row in posts}) if posts is not None else None,
        "completion_calls": len(completions) if completions is not None else None,
        "completed_allow_count": sum(
            row.get("completed") is True and row.get("action") == "allow" for row in completions
        )
        if completions is not None
        else None,
        "replayed_completion_count": sum(row.get("replayed") is True for row in completions)
        if completions is not None
        else None,
        "response_count": len(responses) if responses is not None else None,
        "dropped_response_count": sum(row.get("delivered") is False for row in responses)
        if responses is not None
        else None,
        "delivered_response_count": sum(row.get("delivered") is True for row in responses)
        if responses is not None
        else None,
        "stdout_and_exit_checked": report.get("stdout_and_exit_checked") is True,
        "witness_overflow": witness.get("witness_overflow"),
    }
    for position in ("before", "after"):
        binding = fault.get("binding_" + position)
        for key in ("generation", "policy_digest", "runtime_identity"):
            proof[position + "_" + key] = binding.get(key) if isinstance(binding, Mapping) else None
    for position, row in (("first", native[0] if native else None), ("last", native[-1] if native else None)):
        proof[position + "_request_digest"] = row.get("request_digest") if row is not None else None
    failure = report.get("failure")
    if isinstance(failure, Mapping):
        proof["failure_reason"] = failure.get("reason")
        proof["failure_digest"] = failure.get("diagnostic_digest")
    return assert_privacy_safe(proof)


def run_priority_approval_scenarios(
    runtime: Path, *, evidence_file: Path, receipt_profile: str = "candidate"
) -> dict[str, object]:
    evidence_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        ordinary = run_registered_approval_corpus(
            runtime, evidence_file=evidence_file.with_name(evidence_file.stem + "-ordinary.jsonl")
        )
        ordinary["passed"] = ordinary.get("implemented_scope_passed") is True
    except Exception as error:
        ordinary = {"passed": False, "failure": failure_evidence(error)}
    scenarios: dict[str, dict[str, Any]] = {}
    with evidence_file.open("x", encoding="utf-8") as stream:
        evidence_file.chmod(0o600)
        for scenario in SCENARIOS:
            report: dict[str, Any] = {
                "scenario": scenario,
                "status": "offered",
                "passed": False,
                "headline_timing_eligible": False,
            }
            stream.write(json.dumps(report, separators=(",", ":")) + "\n")
            stream.flush()
            try:
                _fault_case(runtime, scenario, receipt_profile=receipt_profile, report=report)
            except Exception as error:
                report.update(passed=False, status="failed", failure=failure_evidence(error))
            safe = assert_privacy_safe(report)
            scenarios[scenario] = safe
            stream.write(json.dumps(safe, separators=(",", ":")) + "\n")
            stream.flush()
    passed = ordinary.get("passed") is True and all(row.get("passed") is True for row in scenarios.values())
    return assert_privacy_safe(
        {
            "schema": "hol-guard.priority-approval-scenarios.v1",
            "scope": "priority_approval",
            "boundary": "INSTALLED_LAUNCHER",
            "passed": passed,
            "implemented_scope_passed": passed,
            "headline_timing_eligible": False,
            "ordinary_review": ordinary,
            "codex_faults": scenarios,
            "codex_fault_proofs": {scenario: _flat_fault_proof(row) for scenario, row in scenarios.items()},
            "expiry_scope": "original_browser_wait_deadline",
            "stored_approval_ttl_seconds": 900,
            "stored_approval_ttl_exercised": False,
            "reviewed_tool_execution": "outside_registered_hook_scope",
        }
    )
