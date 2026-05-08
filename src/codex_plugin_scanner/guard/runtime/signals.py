"""Typed runtime risk signals for Guard decisions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from codex_plugin_scanner.guard.types import GuardSignal

RiskSignalCategory = Literal[
    "secret",
    "network",
    "prompt",
    "mcp",
    "skill",
    "supply_chain",
    "encoded",
    "persistence",
    "bypass",
    "false_positive",
    "filesystem",
    "execution",
    "publisher",
    "policy",
    "provenance",
]
RiskSeverityLabel = Literal["info", "low", "medium", "high", "critical"]
RiskConfidenceLabel = Literal["weak", "likely", "strong"]
RiskRedactionLevel = Literal["none", "summary", "redacted"]
RiskSignalSource = Literal["native", "cisco_mcp", "cisco_skill", "threat_intel", "runtime_detector"]
ScannerStatusLabel = Literal["enabled", "skipped", "unavailable", "failed", "timed_out"]

_FAMILY_CATEGORY: dict[str, RiskSignalCategory] = {
    "network": "network",
    "filesystem": "filesystem",
    "secret": "secret",
    "execution": "execution",
    "publisher": "publisher",
    "prompt": "prompt",
    "policy": "policy",
    "provenance": "provenance",
}


@dataclass(frozen=True, slots=True)
class RiskSignalV2:
    """Product-facing risk signal with stable labels and explainable evidence."""

    signal_id: str
    category: RiskSignalCategory
    severity: RiskSeverityLabel
    confidence: RiskConfidenceLabel
    detector: str
    title: str
    plain_reason: str
    technical_detail: str | None
    evidence_ref: str | None
    redaction_level: RiskRedactionLevel
    false_positive_hint: str | None
    advisory_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_id": self.signal_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "detector": self.detector,
            "title": self.title,
            "plain_reason": self.plain_reason,
            "technical_detail": self.technical_detail,
            "evidence_ref": self.evidence_ref,
            "redaction_level": self.redaction_level,
            "false_positive_hint": self.false_positive_hint,
            "advisory_id": self.advisory_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> RiskSignalV2:
        return cls(
            signal_id=_required_string(payload, "signal_id"),
            category=_parse_category(payload.get("category")),
            severity=_parse_severity(payload.get("severity")),
            confidence=_parse_confidence(payload.get("confidence")),
            detector=_required_string(payload, "detector"),
            title=_required_string(payload, "title"),
            plain_reason=_required_string(payload, "plain_reason"),
            technical_detail=_optional_string(payload, "technical_detail"),
            evidence_ref=_optional_string(payload, "evidence_ref"),
            redaction_level=_parse_redaction_level(payload.get("redaction_level")),
            false_positive_hint=_optional_string(payload, "false_positive_hint"),
            advisory_id=_optional_string(payload, "advisory_id"),
        )

    @classmethod
    def from_guard_signal(cls, signal: GuardSignal) -> RiskSignalV2:
        return cls(
            signal_id=signal.signal_id,
            category=_category_from_guard_signal(signal),
            severity=severity_label_from_score(signal.severity),
            confidence=confidence_label_from_score(signal.confidence),
            detector=signal.rule_version,
            title=_title_from_reason(signal.explanation),
            plain_reason=signal.explanation,
            technical_detail=_technical_detail_from_guard_signal(signal),
            evidence_ref=signal.evidence_source,
            redaction_level="summary",
            false_positive_hint=signal.remediation,
            advisory_id=None,
        )


@dataclass(frozen=True, slots=True)
class GuardRiskSignalV3:
    """Scanner-aware risk signal with durable local evidence references."""

    signal_id: str
    source: RiskSignalSource
    source_version: str
    category: RiskSignalCategory
    severity: RiskSeverityLabel
    confidence: RiskConfidenceLabel
    title: str
    plain_language_summary: str
    technical_detail: str | None
    evidence_ref: str | None
    scanner_name: str | None
    scanner_status: ScannerStatusLabel
    scanner_rule_id: str | None
    redaction_level: RiskRedactionLevel
    source_path: str | None
    source_line: int | None
    data_source: str | None
    data_sink: str | None
    recommended_action: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "signal_id": self.signal_id,
            "source": self.source,
            "source_version": self.source_version,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "plain_language_summary": self.plain_language_summary,
            "technical_detail": self.technical_detail,
            "evidence_ref": self.evidence_ref,
            "scanner_name": self.scanner_name,
            "scanner_status": self.scanner_status,
            "scanner_rule_id": self.scanner_rule_id,
            "redaction_level": self.redaction_level,
            "source_path": self.source_path,
            "source_line": self.source_line,
            "data_source": self.data_source,
            "data_sink": self.data_sink,
            "recommended_action": self.recommended_action,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardRiskSignalV3:
        return cls(
            signal_id=_required_string(payload, "signal_id"),
            source=_parse_source(payload.get("source")),
            source_version=_required_string(payload, "source_version"),
            category=_parse_category(payload.get("category")),
            severity=_parse_severity(payload.get("severity")),
            confidence=_parse_confidence(payload.get("confidence")),
            title=_required_string(payload, "title"),
            plain_language_summary=_required_string(payload, "plain_language_summary"),
            technical_detail=_optional_string(payload, "technical_detail"),
            evidence_ref=_optional_string(payload, "evidence_ref"),
            scanner_name=_optional_string(payload, "scanner_name"),
            scanner_status=_parse_scanner_status(payload.get("scanner_status")),
            scanner_rule_id=_optional_string(payload, "scanner_rule_id"),
            redaction_level=_parse_redaction_level(payload.get("redaction_level")),
            source_path=_optional_string(payload, "source_path"),
            source_line=_optional_int(payload, "source_line"),
            data_source=_optional_string(payload, "data_source"),
            data_sink=_optional_string(payload, "data_sink"),
            recommended_action=_optional_string(payload, "recommended_action"),
        )


def severity_label_from_score(score: int | float) -> RiskSeverityLabel:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 5:
        return "medium"
    if score >= 3:
        return "low"
    return "info"


def confidence_label_from_score(score: float) -> RiskConfidenceLabel:
    if score >= 0.85:
        return "strong"
    if score >= 0.5:
        return "likely"
    return "weak"


def _category_from_guard_signal(signal: GuardSignal) -> RiskSignalCategory:
    signal_id = signal.signal_id.lower()
    if ":bypass:" in signal_id or signal_id.startswith("policy:bypass"):
        return "bypass"
    if ":encoded:" in signal_id:
        return "encoded"
    return _FAMILY_CATEGORY.get(signal.family, "policy")


def _technical_detail_from_guard_signal(signal: GuardSignal) -> str | None:
    if signal.matched_text is None:
        return None
    return f"matched {signal.evidence_source} evidence: {signal.matched_text}"


def _title_from_reason(reason: str) -> str:
    stripped = reason.strip()
    if not stripped:
        return "Guard risk signal"
    return f"{stripped[0].upper()}{stripped[1:]}"


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_string(payload: Mapping[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null")
    return value


def _optional_int(payload: Mapping[str, object], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, int):
        raise ValueError(f"{key} must be an integer or null")
    return value


def _parse_source(value: object) -> RiskSignalSource:
    match value:
        case "native":
            return "native"
        case "cisco_mcp":
            return "cisco_mcp"
        case "cisco_skill":
            return "cisco_skill"
        case "threat_intel":
            return "threat_intel"
        case "runtime_detector":
            return "runtime_detector"
        case _:
            raise ValueError("source must be a known risk signal source")


def _parse_category(value: object) -> RiskSignalCategory:
    match value:
        case "secret":
            return "secret"
        case "network":
            return "network"
        case "prompt":
            return "prompt"
        case "mcp":
            return "mcp"
        case "skill":
            return "skill"
        case "supply_chain":
            return "supply_chain"
        case "encoded":
            return "encoded"
        case "persistence":
            return "persistence"
        case "bypass":
            return "bypass"
        case "false_positive":
            return "false_positive"
        case "filesystem":
            return "filesystem"
        case "execution":
            return "execution"
        case "publisher":
            return "publisher"
        case "policy":
            return "policy"
        case "provenance":
            return "provenance"
        case _:
            raise ValueError("category must be a known risk signal category")


def _parse_severity(value: object) -> RiskSeverityLabel:
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
            raise ValueError("severity must be a known severity label")


def _parse_confidence(value: object) -> RiskConfidenceLabel:
    match value:
        case "weak":
            return "weak"
        case "likely":
            return "likely"
        case "strong":
            return "strong"
        case _:
            raise ValueError("confidence must be a known confidence label")


def _parse_redaction_level(value: object) -> RiskRedactionLevel:
    match value:
        case "none":
            return "none"
        case "summary":
            return "summary"
        case "redacted":
            return "redacted"
        case _:
            raise ValueError("redaction_level must be a known redaction level")


def _parse_scanner_status(value: object) -> ScannerStatusLabel:
    match value:
        case "enabled":
            return "enabled"
        case "skipped":
            return "skipped"
        case "unavailable":
            return "unavailable"
        case "failed":
            return "failed"
        case "timed_out":
            return "timed_out"
        case _:
            raise ValueError("scanner_status must be a known scanner status")
