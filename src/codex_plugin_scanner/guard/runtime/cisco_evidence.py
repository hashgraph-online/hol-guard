"""Cisco scanner evidence adapters for Guard runtime signals."""

from __future__ import annotations

import re
from hashlib import sha256

from codex_plugin_scanner.guard.runtime.scanner_cache import scanner_cache_key
from codex_plugin_scanner.guard.runtime.signals import (
    GuardRiskSignalV3,
    RiskConfidenceLabel,
    RiskSeverityLabel,
    RiskSignalCategory,
    RiskSignalSource,
    ScannerStatusLabel,
)
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import Finding, Severity

_LONG_SECRET_LIKE_TOKEN = re.compile(r"\b[A-Za-z0-9_./+=-]{32,}\b")
_MAX_TEXT_LENGTH = 280
__all__ = ["cisco_finding_to_risk_signal", "scanner_cache_key"]


def cisco_finding_to_risk_signal(
    finding: Finding,
    *,
    scanner_status: CiscoIntegrationStatus,
    scanner_name: str | None = None,
    source_version: str = "unknown",
) -> GuardRiskSignalV3:
    source = _source_from_finding(finding)
    category = _category_from_finding(finding, source)
    display_name = scanner_name or _scanner_name_from_source(source)
    evidence_ref = _evidence_ref(finding)
    return GuardRiskSignalV3(
        signal_id=_signal_id(finding),
        source=source,
        source_version=source_version,
        category=category,
        severity=_severity_label(finding.severity),
        confidence=_confidence_label(finding.severity),
        title=_safe_text(finding.title, fallback="Cisco scanner finding"),
        plain_language_summary=_safe_text(
            finding.description,
            fallback=f"{display_name} reported a potential {category} risk.",
        ),
        technical_detail=f"{display_name} rule {finding.rule_id} reported {finding.category} evidence.",
        evidence_ref=evidence_ref,
        scanner_name=display_name,
        scanner_status=_status_label(scanner_status),
        scanner_rule_id=finding.rule_id,
        redaction_level="summary",
        source_path=finding.file_path,
        source_line=finding.line_number,
        data_source=None,
        data_sink=None,
        recommended_action=_safe_optional_text(finding.remediation),
    )


def _signal_id(finding: Finding) -> str:
    source = finding.source or "cisco-scanner"
    path = finding.file_path or "unknown"
    if finding.line_number is not None:
        return f"{source}:{finding.rule_id}:{path}:{finding.line_number}"
    payload = "|".join(
        (
            finding.rule_id,
            path,
            finding.title,
            finding.description,
            finding.remediation or "",
        )
    )
    suffix = sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"{source}:{finding.rule_id}:{path}:{suffix}"


def _source_from_finding(finding: Finding) -> RiskSignalSource:
    source = finding.source.lower()
    if "mcp" in source:
        return "cisco_mcp"
    if "skill" in source:
        return "cisco_skill"
    if "mcp" in finding.category.lower():
        return "cisco_mcp"
    if "skill" in finding.category.lower():
        return "cisco_skill"
    return "native"


def _category_from_finding(finding: Finding, source: RiskSignalSource) -> RiskSignalCategory:
    if source == "cisco_mcp":
        return "mcp"
    if source == "cisco_skill":
        return "skill"
    category = finding.category.lower()
    if "secret" in category:
        return "secret"
    if "network" in category:
        return "network"
    if "prompt" in category:
        return "prompt"
    if "supply" in category:
        return "supply_chain"
    return "policy"


def _scanner_name_from_source(source: RiskSignalSource) -> str:
    if source == "cisco_mcp":
        return "Cisco MCP scanner"
    if source == "cisco_skill":
        return "Cisco skill scanner"
    return "Cisco scanner"


def _severity_label(severity: Severity) -> RiskSeverityLabel:
    match severity:
        case Severity.CRITICAL:
            return "critical"
        case Severity.HIGH:
            return "high"
        case Severity.MEDIUM:
            return "medium"
        case Severity.LOW:
            return "low"
        case Severity.INFO:
            return "info"


def _confidence_label(severity: Severity) -> RiskConfidenceLabel:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "strong"
    if severity is Severity.MEDIUM:
        return "likely"
    return "weak"


def _status_label(status: CiscoIntegrationStatus) -> ScannerStatusLabel:
    match status:
        case CiscoIntegrationStatus.ENABLED:
            return "enabled"
        case CiscoIntegrationStatus.SKIPPED:
            return "skipped"
        case CiscoIntegrationStatus.UNAVAILABLE:
            return "unavailable"
        case CiscoIntegrationStatus.FAILED:
            return "failed"
        case CiscoIntegrationStatus.TIMED_OUT:
            return "timed_out"


def _evidence_ref(finding: Finding) -> str | None:
    if finding.file_path is None:
        return None
    if finding.line_number is None:
        return finding.file_path
    return f"{finding.file_path}:{finding.line_number}"


def _safe_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    return _safe_text(value, fallback="")


def _safe_text(value: str, *, fallback: str) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        return fallback
    redacted = _LONG_SECRET_LIKE_TOKEN.sub("[redacted]", normalized)
    if len(redacted) <= _MAX_TEXT_LENGTH:
        return redacted
    return f"{redacted[: _MAX_TEXT_LENGTH - 1].rstrip()}…"
