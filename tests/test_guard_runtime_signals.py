"""Behavior tests for typed Guard runtime risk signals."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.signals import (
    RiskSignalV2,
)


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
