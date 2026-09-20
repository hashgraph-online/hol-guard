from __future__ import annotations

import copy
import hashlib

import pytest

from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes, validate_native_decision_receipt
from scripts.native_slo_workspace_decision import (
    authority_projection,
    finite_time,
    join_decisions,
    receipt_projection,
)
from tests.native_workspace_request_fixtures import row, snapshot


def _join(rows, authority, *, accepted=10.0, declared=None, complete=True):
    return join_decisions(
        rows,
        authority=authority_projection(authority),
        action="block",
        accepted_ms=accepted,
        declared_attempts=declared or [value["attempt"] for value in rows],
        observation_complete=complete,
    )


def _reseal(value):
    native = value["native_receipt"]
    native["decision_id"] = hashlib.sha256(canonical_receipt_bytes(native)).hexdigest()
    assert validate_native_decision_receipt(native) == native
    value["committed_receipt"] = copy.deepcopy(native)
    value["witness_decision_id"] = native["decision_id"]


def test_first_post_acceptance_request_keeps_earlier_offered_completion_distinct():
    authority = snapshot()
    before = row(authority, 0, offered=9, finished=11)
    after = row(authority, 1, offered=10, finished=12)
    original = copy.deepcopy((before, after, authority))
    result = _join([before, after], authority)
    assert result["passed"] is True
    assert result["first_native_completion_after_acceptance"]["attempts"] == ["mixed-policy-0"]
    assert result["first_completion_of_post_acceptance_request"]["attempts"] == ["mixed-policy-1"]
    assert result["rows"][0]["accepted_to_offer_ms"] == -1
    assert result["rows"][1]["accepted_to_offer_ms"] == 0
    assert result["internal_rust_decision_time_observed"] is False
    assert result["qualification_complete"] is False
    assert (before, after, authority) == original


def test_entry_after_acceptance_cannot_relabel_an_earlier_offer():
    authority = snapshot()
    value = row(authority, offered=9, finished=12)
    value["review_entered_ms"] = 11
    result = _join([value], authority)
    assert result["rows"][0]["passed"] is True
    assert result["first_native_completion_after_acceptance"] is not None
    assert result["first_completion_of_post_acceptance_request"] is None
    assert result["passed"] is False


def test_a_failed_earlier_sample_cannot_be_dropped_to_select_later_success():
    authority = snapshot()
    first, second = row(authority), row(authority, 1, offered=23, finished=25)
    first["writer_admitted"] = False
    result = _join([first, second], authority)
    assert result["passed"] is False
    assert result["rows"][0]["checks"]["original_witness_matches"] is False
    assert result["rows"][1]["passed"] is True
    assert result["observed_requests"] == 2


def test_missing_declared_attempt_does_not_shrink_the_cohort():
    authority = snapshot()
    result = _join([row(authority)], authority, declared=["mixed-policy-0", "mixed-policy-1"])
    assert result["passed"] is False and result["exact_attempts"] is False
    assert result["declared_requests"] == 2 and result["observed_requests"] == 1


@pytest.mark.parametrize("duplicate", ["attempt", "decision_id", "request_id"])
def test_duplicate_causal_identities_are_not_unique_requests(duplicate):
    authority = snapshot()
    first, second = row(authority), row(authority, 1, offered=23, finished=25)
    if duplicate == "attempt":
        second["attempt"] = first["attempt"]
    elif duplicate == "decision_id":
        second["native_receipt"] = copy.deepcopy(first["native_receipt"])
        second["committed_receipt"] = copy.deepcopy(first["committed_receipt"])
        second["witness_decision_id"] = first["witness_decision_id"]
    else:
        second["native_receipt"]["request_id"] = first["native_receipt"]["request_id"]
        second["native_receipt"]["reason_code"] = "second_controlled_decision"
        _reseal(second)
    result = _join([first, second], authority, declared=["mixed-policy-0", "mixed-policy-1"])
    assert result["passed"] is False
    key = {
        "attempt": "exact_attempts",
        "decision_id": "unique_receipt_identities",
        "request_id": "unique_native_request_ids",
    }[duplicate]
    assert result[key] is False


def test_equal_completion_stamps_retain_both_ties_without_claiming_unique_first():
    authority = snapshot()
    result = _join([row(authority), row(authority, 1)], authority)
    assert result["passed"] is False
    assert result["first_completion_of_post_acceptance_request"]["attempts"] == [
        "mixed-policy-0",
        "mixed-policy-1",
    ]
    assert result["first_completion_of_post_acceptance_request"]["unique_observed_first"] is False


@pytest.mark.parametrize(
    "field,replacement,check",
    [
        ("policy_generation", 8, "receipt_authority_matches"),
        ("policy_digest", "4" * 64, "receipt_authority_matches"),
        ("runtime_identity", "4" * 64, "receipt_authority_matches"),
        ("rule_digest", "4" * 64, "receipt_authority_matches"),
        ("harness", "codex", "receipt_semantics_match"),
        ("event_name", "PostToolUse", "receipt_semantics_match"),
        ("workspace_bound", False, "receipt_semantics_match"),
        ("observe_mode", True, "receipt_semantics_match"),
        ("policy_action", "allow", "receipt_semantics_match"),
        ("decision", "allow", "receipt_semantics_match"),
        ("model_output_action", "allow_original", "receipt_semantics_match"),
    ],
)
def test_valid_but_wrong_receipt_authority_or_semantics_cannot_join(field, replacement, check):
    authority = snapshot()
    value = row(authority)
    value["native_receipt"][field] = replacement
    _reseal(value)
    result = _join([value], authority)
    assert result["rows"][0]["checks"]["validated_native_receipt"] is True
    assert result["rows"][0]["checks"][check] is False
    assert result["passed"] is False


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("program_digest", "4" * 64),
        ("catalog_digest", "4" * 64),
        ("trust_digest", "4" * 64),
        ("control_revision", 5),
        ("managed_control_revision", 3),
        ("control_effective_digest", "4" * 64),
    ],
)
def test_each_valid_changed_command_authority_field_is_rejected(field, replacement):
    authority = snapshot()
    value = row(authority)
    value["native_receipt"]["command_extensions"][field] = replacement
    _reseal(value)
    result = _join([value], authority)
    assert result["rows"][0]["checks"]["validated_native_receipt"] is True
    assert result["rows"][0]["checks"]["receipt_command_controls_match"] is False
    assert result["passed"] is False


@pytest.mark.parametrize(
    "field,replacement,check",
    [
        ("review_calls", True, "one_completed_review"),
        ("review_calls", 2, "one_completed_review"),
        ("request_returned", False, "one_completed_request"),
        ("request_scope_matches", False, "request_scope_matches"),
        ("workspace_index", True, "request_scope_matches"),
        ("request_binding_matches", False, "request_binding_matches"),
        ("authority_readback_before", False, "authenticated_readbacks_match"),
        ("authority_readback_after", False, "authenticated_readbacks_match"),
        ("delivered_decision", "allow", "delivery_matches"),
        ("writer_admitted", False, "original_witness_matches"),
        ("witness_committed", False, "original_witness_matches"),
        ("witness_commit_binding_valid", False, "original_witness_matches"),
        ("committed_row_count", 0, "unique_committed_readback"),
        ("committed_row_count", 2, "unique_committed_readback"),
        ("committed_row_count", True, "unique_committed_readback"),
        ("capture_faults", 1, "capture_faults_absent"),
        ("capture_faults", False, "capture_faults_absent"),
    ],
)
def test_missing_or_ambiguous_observation_is_not_complete(field, replacement, check):
    authority = snapshot()
    value = row(authority)
    value[field] = replacement
    result = _join([value], authority)
    assert result["rows"][0]["checks"][check] is False
    assert result["passed"] is False


@pytest.mark.parametrize("target", ["native_receipt", "committed_receipt"])
def test_stale_receipt_identity_is_revalidated_even_when_capture_flag_is_true(target):
    authority = snapshot()
    value = row(authority)
    value[target]["command_extensions"]["observations_digest"] = "4" * 64
    result = _join([value], authority)
    assert result["passed"] is False
    assert validate_native_decision_receipt(value[target]) is None


@pytest.mark.parametrize("stamp", [float("nan"), float("inf"), float("-inf"), True, -1, 2**63, 10**1000])
def test_nonfinite_or_out_of_range_monotonic_endpoint_is_rejected(stamp):
    authority = snapshot()
    value = row(authority)
    value["native_finished_ms"] = stamp
    result = _join([value], authority)
    assert result["rows"][0]["checks"]["bounded_monotonic_order"] is False
    assert result["passed"] is False


def test_backwards_clock_and_expired_wall_observation_are_separate_failures():
    authority = snapshot()
    value = row(authority)
    value["review_returned_ms"] = value["review_entered_ms"] - 1
    value["review_returned_wall_ms"] = authority["expires_at_ms"]
    result = _join([value], authority)
    assert result["rows"][0]["checks"]["bounded_monotonic_order"] is False
    assert result["rows"][0]["checks"]["observed_wall_lifetime"] is False
    assert result["passed"] is False


def test_incomplete_capture_cannot_be_promoted_by_otherwise_valid_rows():
    authority = snapshot()
    result = _join([row(authority)], authority, complete=False)
    assert result["rows"][0]["passed"] is True
    assert result["passed"] is False


def test_receipt_capture_detaches_the_full_validated_nested_binding():
    authority = snapshot()
    native = row(authority)["native_receipt"]
    captured = receipt_projection(native)
    assert captured == native and captured is not native
    native["command_extensions"]["control_revision"] += 1
    assert captured["command_extensions"]["control_revision"] == 4
    assert validate_native_decision_receipt(captured) == captured


@pytest.mark.parametrize("attempt", ["mixed-policy-00", "mixed-policy-32", "mixed-load-0", "", None])
def test_join_declaration_uses_exact_bounded_existing_witness_attempt_ids(attempt):
    authority = snapshot()
    with pytest.raises(ValueError, match="declared bounds"):
        _join([row(authority)], authority, declared=[attempt])


def test_malformed_observed_attempt_is_retained_as_a_failed_exact_set():
    authority = snapshot()
    value = row(authority)
    value["attempt"] = None
    result = _join([value], authority, declared=["mixed-policy-0"])
    assert result["exact_attempts"] is False and result["passed"] is False


def test_join_rejects_unbounded_extra_authority_fields():
    authority = snapshot()
    expected = authority_projection(authority)
    expected["extra"] = "not admitted"
    with pytest.raises(ValueError, match="join authority invalid"):
        join_decisions(
            [row(authority)],
            authority=expected,
            action="block",
            accepted_ms=10,
            declared_attempts=["mixed-policy-0"],
            observation_complete=True,
        )


def test_clock_predicate_rejects_bool_and_huge_integer_without_overflow():
    assert finite_time(0) and finite_time(1.5)
    assert not finite_time(True) and not finite_time(10**1000)
