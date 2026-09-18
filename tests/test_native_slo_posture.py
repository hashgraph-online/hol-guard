"""Source-only posture oracle/accounting tests; no installed ACK is fabricated."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_mixed_load import PrivateLedger
from scripts.native_slo_posture import _pages, run_posture_scenarios
from scripts.native_slo_posture_witness import (
    POSTURE_ROUTES,
    PostureWitness,
    binding_key,
    posture_case,
    receipt_intrinsic_matches,
    validate_delivery,
)
from scripts.native_slo_workloads import _availability_expected
from tests.test_native_decision_receipt import _receipt


def _response(fields: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in fields.items():
        if "." in name:
            parent, key = name.split(".")
            result.setdefault(parent, {})[key] = value
        else:
            result[name] = value
    return result


def _context(mode: str = "enforce") -> dict[str, Any]:
    return {
        "binding": {"generation": 1, "policy_digest": "b" * 64, "runtime_identity": "d" * 64, "mode": mode},
        "receipt_present": True,
        "observe_argument_valid": True,
        "native_valid": True,
        "receipt_binding_valid": True,
    }


@pytest.mark.parametrize("harness,event", POSTURE_ROUTES)
@pytest.mark.parametrize("mode", ("enforce", "observe"))
def test_intrinsic_block_and_delivered_mode_are_distinct_frozen_contracts(harness: str, event: str, mode: str) -> None:
    case = posture_case(harness, event, mode)
    context = _context(mode)
    assert case.native_expected is not None and case.native_expected.fields["decision"] == "deny"
    assert case.native_expected.fields["policy_action"] == "block"
    assert case.expected.fields["policy_action"] == ("warn" if mode == "observe" else "block")
    assert (
        validate_delivery(
            case=case,
            response=_response(case.expected.fields),
            context=context,
            known_bindings={binding_key(context["binding"])},
            required=binding_key(context["binding"]),
        )
        == "native_resident"
    )
    wrong = posture_case(harness, event, "observe" if mode == "enforce" else "enforce")
    with pytest.raises(AssertionError):
        validate_delivery(
            case=case,
            response=_response(wrong.expected.fields),
            context=context,
            known_bindings={binding_key(context["binding"])},
            required=None,
        )


@pytest.mark.parametrize("field", ("observe_argument_valid", "native_valid", "receipt_binding_valid"))
def test_invalid_mode_receipt_or_result_cannot_be_hidden_by_matching_delivery(field: str) -> None:
    context = _context()
    context[field] = False
    case = posture_case("claude-code", "PreToolUse")
    with pytest.raises(AssertionError, match="binding or result mismatch"):
        validate_delivery(
            case=case,
            response=_response(case.expected.fields),
            context=context,
            known_bindings={binding_key(context["binding"])},
            required=None,
        )


@pytest.mark.parametrize("fault", ("unknown", "stale_after_ack", "native_during_required_unavailable"))
def test_receipt_must_match_authenticated_history_and_exact_probe_generation(fault: str) -> None:
    context = _context()
    case = posture_case("codex", "PreToolUse")
    known = set() if fault == "unknown" else {binding_key(context["binding"])}
    required = (
        binding_key({**context["binding"], "generation": 2})
        if fault == "stale_after_ack"
        else "unavailable"
        if fault == "native_during_required_unavailable"
        else None
    )
    with pytest.raises(AssertionError):
        validate_delivery(
            case=case,
            response=_response(case.expected.fields),
            context=context,
            known_bindings=known,
            required=required,
        )


@pytest.mark.parametrize("harness,event", POSTURE_ROUTES)
def test_only_explicit_unavailable_semantics_count_as_unavailable(harness: str, event: str) -> None:
    case = posture_case(harness, event)
    expected = _availability_expected(harness, event, "native_policy_not_ready")
    response = _response(expected.fields)
    assert (
        validate_delivery(case=case, response=response, context=None, known_bindings=set(), required="unavailable")
        == "native_fail_safe"
    )
    for invalid in (
        {},
        {**response, "reason_code": "daemon_capacity"},
        {**response, "policy_action": "block"},
        {**response, "observe_mode": True},
    ):
        with pytest.raises(AssertionError):
            validate_delivery(case=case, response=invalid, context=None, known_bindings=set(), required=None)
    with pytest.raises(AssertionError, match="no native receipt"):
        validate_delivery(
            case=case,
            response=response,
            context=None,
            known_bindings=set(),
            required=binding_key(_context()["binding"]),
        )


def test_native_wrapper_preserves_real_result_and_validates_durable_receipt(tmp_path: Path) -> None:
    # The edge is a declared source double. Receipt validation, actual SQLite,
    # evidence writer/journal and observational wrapper execute unchanged.
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    case = posture_case("claude-code", "PostToolUse", "observe")
    assert case.native_expected is not None
    receipt = _receipt(**case.native_expected.fields)
    edge = {"receipt": receipt, "result": dict(case.native_expected.fields)}
    calls = []

    def native(**kwargs):
        calls.append(kwargs)
        return edge

    worker = SimpleNamespace(_review_raw_hook_native=native)
    session = SimpleNamespace(
        store=store,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer)),
    )
    witness = PostureWitness(session, receipt_profile="candidate").__enter__()
    try:
        binding = _context("observe")["binding"]
        assert (
            worker._review_raw_hook_native(
                payload={"tool_use_id": "mixed-load-0"},
                harness=case.harness,
                event=case.event,
                policy_snapshot=binding,
                observe_mode=True,
            )
            is edge
        )
        assert len(calls) == 1 and calls[0]["policy_snapshot"] is binding
        context = witness.context("mixed-load-0")
        assert context is not None and context["receipt_binding_valid"] is True
        assert context["observe_argument_valid"] is True and context["native_valid"] is True
        assert receipt["observe_mode"] is False
        assert writer.submit_native_decision_receipt(receipt) is True
        assert writer.stop(timeout_seconds=3)
        witness.reconcile(verify_all=True)
        assert witness.report()["committed"] == 1
        observed = witness.row("mixed-load-0")
        assert observed is not None and observed["commit_binding_valid"] is True
    finally:
        writer.stop(timeout_seconds=3)
        witness.close()
    assert worker._review_raw_hook_native is native


@pytest.mark.parametrize(
    "field,value",
    (
        ("decision", "allow"),
        ("policy_action", "allow"),
        ("reason_code", "other"),
        ("model_output_action", "allow_original"),
        ("observe_mode", True),
        ("observed_policy_action", "block"),
        ("reviewed_output_sha256", "a" * 64),
    ),
)
def test_well_formed_receipt_cannot_disagree_with_the_intrinsic_native_result(field: str, value: object) -> None:
    case = posture_case("claude-code", "PostToolUse", "observe")
    assert case.native_expected is not None
    receipt = _receipt(**case.native_expected.fields)
    assert receipt_intrinsic_matches(receipt, case)
    receipt = _receipt(**{**case.native_expected.fields, field: value})
    assert not receipt_intrinsic_matches(receipt, case)


class _Session:
    def __init__(self, group: int, failure: str = "") -> None:
        self.group, self.failure = group, failure
        self.operations = []
        self.attempted = self.native = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.failure == "cleanup" and self.group == 0:
            raise RuntimeError("source modeled cleanup failure")

    def control(self, operation, **kwargs):
        self.operations.append((operation, kwargs))
        if operation == "posture_start":
            return {"status": "completed", "starting_authority_authenticated": True}
        if operation == "posture_phase":
            self.attempted += 8
            self.native += 4
            return {
                "status": "completed",
                "passed": not (self.group == 0 and self.failure == "phase"),
                "attempted": 8,
                "native_receipts": 4,
                "route_conservation": True,
                "overlapping_http_calls": 4,
                "starting_authority_authenticated": True,
                "short_lived_acknowledged": True,
            }
        if operation == "posture_finish":
            return {
                "status": "completed",
                "passed": True,
                "attempted": self.attempted + int(self.failure == "count_mismatch" and self.group == 0),
                "native_receipts": self.native,
                "committed": self.native - int(self.failure == "uncommitted" and self.group == 0),
                "bindings_validated": True,
                "distinct_receipts": True,
                "writer_drained": True,
            }
        if operation == "posture_page":
            return {
                "status": "completed",
                "rows": [
                    {"attempt": f"mixed-load-{index}"}
                    for index in range(kwargs["offset"], min(self.attempted, kwargs["offset"] + 32))
                ],
                "total": self.attempted,
            }
        raise AssertionError(operation)


def _run(tmp_path: Path, failure: str = ""):
    sessions = []

    def factory(runtime, **kwargs):
        assert runtime == Path("never-executed-runtime") and kwargs == {"policy": "normal"}
        session = _Session(len(sessions), failure)
        sessions.append(session)
        return session

    report = run_posture_scenarios(
        Path("never-executed-runtime"), evidence_file=tmp_path / "posture.jsonl", fixture_factory=factory
    )
    return cast(dict[str, Any], report), sessions


def test_orchestration_retains_four_independent_groups_and_exact_mode_sequence(tmp_path: Path) -> None:
    report, sessions = _run(tmp_path)
    assert report["passed"] is True and report["headline_timing_eligible"] is False
    assert report["ordinary_tool_execution_claimed"] is False
    assert len(sessions) == 4
    assert [args["transition"] for operation, args in sessions[0].operations if operation == "posture_phase"] == [
        "enforce_to_watch",
        "watch_restart",
        "watch_to_enforce",
    ]
    assert all(session.operations[-1][0] == "posture_page" for session in sessions)
    assert report["evidence"]["records"] > 6


@pytest.mark.parametrize("failure", ("phase", "cleanup", "count_mismatch", "uncommitted"))
def test_failed_phase_or_cleanup_is_retained_without_blocking_independent_groups(tmp_path: Path, failure: str) -> None:
    report, sessions = _run(tmp_path, failure)
    assert report["passed"] is False
    assert report["groups"]["mode_round_trip"]["passed"] is False
    assert report["groups"]["expired_authority"]["passed"] is True
    if failure == "phase":
        assert len([operation for operation, _ in sessions[0].operations if operation == "posture_phase"]) == 1
        assert report["proofs"]["enforce_to_watch"]["passed"] is False


def test_required_flat_proof_survives_actual_outer_aggregate_and_json_roundtrip(tmp_path: Path) -> None:
    report, _ = _run(tmp_path)
    wrapped = {"run_block": {"additional_scenarios": {"posture_transitions": deepcopy(report)}}}
    published = json.loads(json.dumps(assert_privacy_safe(wrapped)))["run_block"]["additional_scenarios"][
        "posture_transitions"
    ]
    for name, original in report["proofs"].items():
        assert published["proofs"][name] == original
    for name, original in report["groups"].items():
        for field in ("passed", "committed", "bindings_validated", "distinct_receipts", "writer_drained"):
            assert published["groups"][name][field] == original[field]
    assert published["headline_timing_eligible"] is False


@pytest.mark.parametrize(
    "page",
    (
        {"status": "completed", "rows": [], "total": 1},
        {"status": "completed", "rows": [1], "total": 1},
        {"status": "completed", "rows": [{"attempt": "mixed-load-1"}], "total": 1},
        {"status": "completed", "rows": [], "total": 1025},
        {"status": "failed", "rows": [], "total": 0},
    ),
)
def test_bad_or_incomplete_evidence_page_cannot_be_a_pass(page: dict[str, object]) -> None:
    with pytest.raises(RuntimeError):
        _pages(
            SimpleNamespace(control=lambda *_a, **_k: page),
            cast(PrivateLedger, cast(object, SimpleNamespace(write=lambda _row: None))),
            "source",
        )
