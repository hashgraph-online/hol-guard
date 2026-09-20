from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_semantic_diagnostic import semantic_diagnostic
from scripts.native_slo_workloads import build_cases


def test_actual_verdict_codes_survive_but_arbitrary_response_values_do_not(tmp_path: Path) -> None:
    cases = build_cases(tmp_path)
    private = "/home/private/credential-value"
    report = semantic_diagnostic(
        {"policy_action": "block", "reason_code": "no_output_to_review", "reason": private, "output": private},
        {"decision": "deny", "minimum_action": private, "reason_code": private, "findings": [private]},
        cases,
    )
    assert report["delivered"] == {
        "available": True,
        "policy_action": "block",
        "reason_code": "no_output_to_review",
        "reason_code_digest": hashlib.sha256(b'"no_output_to_review"').hexdigest(),
    }
    native = report["native"]
    assert native["decision"] == "deny"
    assert len(native["minimum_action_digest"]) == len(native["reason_code_digest"]) == 64
    assert private not in json.dumps(assert_privacy_safe(report))
    assert "findings" not in native


def test_missing_native_verdict_cannot_be_reported_as_completed(tmp_path: Path) -> None:
    report = semantic_diagnostic({}, None, build_cases(tmp_path))
    assert report == {"delivered": {"available": True}, "native": {"available": False}}


def test_frozen_sensitive_reason_retains_exact_identifier_after_export(tmp_path: Path) -> None:
    report = assert_privacy_safe(semantic_diagnostic({}, {"reason_code": "output_secret_match"}, build_cases(tmp_path)))
    assert report["native"]["reason_code"] == "redacted"
    assert report["native"]["reason_code_digest"] == hashlib.sha256(b'"output_secret_match"').hexdigest()
