"""Behavior tests for typed Guard runtime risk signals."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.signals import (
    RiskSignalV2,
    confidence_label_from_score,
    severity_label_from_score,
)
from codex_plugin_scanner.guard.types import GuardSignal


def test_risk_signal_v2_round_trips_to_dict_payload() -> None:
    signal = RiskSignalV2(
        signal_id="secret:env-read",
        category="secret",
        severity="high",
        confidence="strong",
        detector="guard-risk-v2",
        title="Can read local environment secrets",
        plain_reason="can read local environment secrets",
        technical_detail="matched `.env` and process.env access",
        evidence_ref="artifact",
        redaction_level="summary",
        false_positive_hint="Read-only source search is lower risk when data is not sent elsewhere.",
        advisory_id="HOL-2026-0001",
    )

    payload = signal.to_dict()

    assert payload == {
        "signal_id": "secret:env-read",
        "category": "secret",
        "severity": "high",
        "confidence": "strong",
        "detector": "guard-risk-v2",
        "title": "Can read local environment secrets",
        "plain_reason": "can read local environment secrets",
        "technical_detail": "matched `.env` and process.env access",
        "evidence_ref": "artifact",
        "redaction_level": "summary",
        "false_positive_hint": "Read-only source search is lower risk when data is not sent elsewhere.",
        "advisory_id": "HOL-2026-0001",
    }
    assert RiskSignalV2.from_dict(payload) == signal


def test_runtime_package_lazy_exports_cache_runner_attribute() -> None:
    import codex_plugin_scanner.guard.runtime as runtime

    runtime.__dict__.pop("guard_run", None)

    first = runtime.guard_run
    second = runtime.guard_run

    assert first is second
    assert runtime.__dict__["guard_run"] is first


def test_runtime_package_reports_missing_lazy_export_from_runtime_module() -> None:
    import codex_plugin_scanner.guard.runtime as runtime

    export_name = "missing_runner_export"
    runtime.__all__.append(export_name)
    try:
        with pytest.raises(AttributeError, match=r"runtime.*missing_runner_export.*runner"):
            getattr(runtime, export_name)
    finally:
        runtime.__all__.remove(export_name)


def test_risk_signal_v2_rejects_whitespace_only_required_strings() -> None:
    with pytest.raises(ValueError, match="signal_id"):
        RiskSignalV2.from_dict(
            {
                "signal_id": "   ",
                "category": "secret",
                "severity": "high",
                "confidence": "strong",
                "detector": "guard-risk-v2",
                "title": "Secret",
                "plain_reason": "can read local secrets",
                "technical_detail": None,
                "evidence_ref": "artifact",
                "redaction_level": "summary",
                "false_positive_hint": None,
                "advisory_id": None,
            }
        )


def test_severity_label_from_score_maps_numeric_boundaries() -> None:
    assert severity_label_from_score(0) == "info"
    assert severity_label_from_score(2) == "info"
    assert severity_label_from_score(3) == "low"
    assert severity_label_from_score(4) == "low"
    assert severity_label_from_score(5) == "medium"
    assert severity_label_from_score(6) == "medium"
    assert severity_label_from_score(7) == "high"
    assert severity_label_from_score(8) == "high"
    assert severity_label_from_score(9) == "critical"
    assert severity_label_from_score(10) == "critical"


def test_confidence_label_from_score_maps_boundaries() -> None:
    assert confidence_label_from_score(0.0) == "weak"
    assert confidence_label_from_score(0.49) == "weak"
    assert confidence_label_from_score(0.5) == "likely"
    assert confidence_label_from_score(0.84) == "likely"
    assert confidence_label_from_score(0.85) == "strong"
    assert confidence_label_from_score(1.0) == "strong"


def test_risk_signal_v2_adapts_existing_guard_signal() -> None:
    legacy = GuardSignal(
        signal_id="policy:bypass:approval-policy-forced-to-never",
        family="policy",
        severity=9,
        confidence=0.9,
        evidence_source="artifact",
        matched_text='approval_policy = "never"',
        explanation="contains guard bypass intent",
        remediation="Block and require manual investigation.",
        rule_version="guard-risk-v2",
    )

    signal = RiskSignalV2.from_guard_signal(legacy)

    assert signal.signal_id == legacy.signal_id
    assert signal.category == "bypass"
    assert signal.severity == "critical"
    assert signal.confidence == "strong"
    assert signal.detector == "guard-risk-v2"
    assert signal.title == "Contains guard bypass intent"
    assert signal.plain_reason == "contains guard bypass intent"
    assert signal.technical_detail == 'matched artifact evidence: approval_policy = "never"'
    assert signal.evidence_ref == "artifact"
    assert signal.redaction_level == "summary"
    assert signal.false_positive_hint == "Block and require manual investigation."
