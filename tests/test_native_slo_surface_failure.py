"""Failure enrichment cannot change verdicts or export private case material."""

from __future__ import annotations

import hashlib
import json

import pytest

from scripts import native_slo_surface_failure as diagnostic
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError, failure_evidence


def _arguments():
    return {
        "case_id": "input.codex.PreToolUse.empty",
        "registration_digest": "a" * 64,
        "stage": "witness",
        "expected_route": "native_resident",
        "observed_route": "native_fail_safe",
        "routes_before": {"native_resident": 4, "native_fail_safe": 0},
        "routes_after": {"native_resident": 4, "native_fail_safe": 1},
    }


def _witness():
    return {
        "native_result": {"decision": "deny", "reason_code": "private arbitrary reason", "reason": "/private/path"},
        "native_call_diagnostic": {
            "schema": "hol-guard.native-call-diagnostic.v1",
            "client_after_state": "absent",
            "edge_binding_observed": False,
        },
        "native_call_count": 1,
        "native_completed_call_count": 1,
        "policy_refusal_diagnostic": {
            "schema": "hol-guard.policy-refusal-diagnostic.v1",
            "capture_context": "original_policy_refusal_reason",
            "publisher_error_state": "known",
            "publisher_error_value": "native_client_pool_exhausted",
            "publisher_error_digest": "b" * 64,
            "publisher_error_digest_complete": True,
        },
        "policy_refusal_count": 1,
        "approval_request_id": "private-row-identity",
        "stdout": "private response bytes",
        "setup": {"path": "/private/home"},
    }


def test_existing_witness_preserves_primary_error_and_combined_six_level_envelope():
    original = RuntimeError("priority_launcher_input_route_mismatch")
    enriched = diagnostic.enrich_surface_failure(original, **_arguments(), evidence=_witness())
    assert isinstance(enriched, FixtureFailureError)
    detail = failure_evidence(enriched)
    assert str(enriched) == str(original)
    assert detail["category"] == "RuntimeError"
    assert detail["diagnostic_digest"] == hashlib.sha256(str(original).encode()).hexdigest()
    assert detail["witness_capture"] == "existing_case_result"
    # This is the actual aggregate nesting. No extra context wrapper may push
    # verdict/native/refusal fields beyond the unchanged six-level sanitizer.
    aggregate = assert_privacy_safe({"additional_scenarios": {"priority_input": {"failure": detail}}})
    retained = aggregate["additional_scenarios"]["priority_input"]["failure"]
    assert retained["native_call_count"] == 1
    assert retained["native_call_diagnostic"]["edge_binding_observed"] is False
    assert retained["policy_refusal_count"] == 1
    assert retained["policy_refusal_diagnostic"]["publisher_error_digest_complete"] is True
    assert retained["observed_semantics"]["native"]["decision"] == "deny"
    raw = json.dumps(aggregate)
    assert "truncated" not in raw
    for private in (
        "private arbitrary reason",
        "/private/path",
        "private-row-identity",
        "private response bytes",
        "/private/home",
    ):
        assert private not in raw


def test_postfailure_observer_runs_once_without_overwriting_primary_assertion():
    original = AssertionError("registered_surface_native_route_mismatch")
    calls = []

    def read():
        calls.append("after_failure")
        raise RuntimeError("private observer error /home/example")

    enriched = diagnostic.enrich_surface_failure(original, **_arguments(), read_evidence=read)
    assert isinstance(enriched, FixtureFailureError)
    assert calls == ["after_failure"]
    assert str(enriched) == str(original)
    assert enriched.detail["category"] == "AssertionError"
    assert enriched.detail["diagnostic_digest"] == hashlib.sha256(str(original).encode()).hexdigest()
    assert enriched.detail["witness_capture"] == "after_failure"
    assert enriched.detail["witness_available"] is False
    assert "private observer" not in json.dumps(enriched.detail)


def test_existing_witness_never_triggers_an_additional_observer_read():
    def unexpected():
        raise AssertionError("must not read the observer twice")

    original = RuntimeError("priority_launcher_input_route_mismatch")
    enriched = diagnostic.enrich_surface_failure(
        original, **_arguments(), evidence=_witness(), read_evidence=unexpected
    )
    assert isinstance(enriched, FixtureFailureError)
    assert "witness_read_failure" not in enriched.detail


def test_enrichment_or_privacy_failure_returns_identical_original(monkeypatch):
    original = AssertionError("registered_surface_native_route_mismatch")

    def reject(*_args, **_kwargs):
        raise ValueError("unchanged privacy validation rejected enrichment")

    monkeypatch.setattr(diagnostic, "contextual_failure", reject)
    assert diagnostic.enrich_surface_failure(original, **_arguments(), evidence=_witness()) is original


@pytest.mark.parametrize(
    "field,value", [("case_id", "/private path"), ("registration_digest", "bad"), ("stage", "private")]
)
def test_untrusted_case_metadata_returns_original(field, value):
    original = RuntimeError("priority_launcher_input_route_mismatch")
    arguments = {**_arguments(), field: value}
    assert diagnostic.enrich_surface_failure(original, **arguments, evidence=_witness()) is original


def test_unknown_route_labels_do_not_escape():
    original = RuntimeError("priority_launcher_input_route_mismatch")
    arguments = {
        **_arguments(),
        "observed_route": "private route label",
        "routes_after": {"private route label": 1, "native_resident": 4},
    }
    enriched = diagnostic.enrich_surface_failure(original, **arguments, evidence=_witness())
    assert isinstance(enriched, FixtureFailureError)
    assert enriched.detail["observed_route"] == "unrecognized"
    assert enriched.detail["unrecognized_routes_after"] == 1
    assert enriched.detail["routes_after"] == {"native_resident": 4}
    assert "private route label" not in json.dumps(enriched.detail)
