"""Typed risk-signal projection for recorded package evaluation reasons."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .signals import RiskSeverityLabel, RiskSignalV2


def _package_reason_signals(reasons: Sequence[object]) -> tuple[RiskSignalV2, ...]:
    signals: list[RiskSignalV2] = []
    for reason in reasons:
        if not isinstance(reason, Mapping):
            continue
        code = _optional_text(reason.get("code")) or "package-risk"
        message = _optional_text(reason.get("message")) or code.replace("_", " ")
        severity = _package_signal_severity(_optional_text(reason.get("severity")))
        signals.append(
            RiskSignalV2(
                signal_id=f"supply-chain.{code}",
                category="supply_chain",
                severity=severity,
                confidence="strong" if severity in {"high", "critical"} else "likely",
                detector=_optional_text(reason.get("source")) or "guard.supply-chain",
                title=message,
                plain_reason=message,
                technical_detail=message,
                evidence_ref=None,
                redaction_level="summary",
                false_positive_hint=(
                    "Review the package request or add a scoped exception only for a verified false positive."
                ),
                advisory_id=None,
            )
        )
    return tuple(signals)


def _package_signal_severity(value: str | None) -> RiskSeverityLabel:
    match value:
        case "info":
            return "info"
        case "low":
            return "low"
        case "medium":
            return "medium"
        case "high":
            return "high"
        case "critical":
            return "critical"
        case _:
            return "medium"


def _optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
