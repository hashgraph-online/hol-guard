"""Codex Plugin Scanner - types and data classes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Severity levels for actionable findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """A structured finding emitted by a check or external scanner."""

    rule_id: str
    severity: Severity
    category: str
    title: str
    description: str
    remediation: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    source: str = "native"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of an individual check."""

    name: str
    passed: bool
    points: int
    max_points: int
    message: str
    findings: tuple[Finding, ...] = ()
    applicable: bool = True


@dataclass(frozen=True, slots=True)
class CategoryResult:
    """A category containing multiple checks."""

    name: str
    checks: tuple[CheckResult, ...]


@dataclass(frozen=True, slots=True)
class IntegrationResult:
    """Status of an optional scanning integration."""

    name: str
    status: str
    message: str
    findings_count: int = 0
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Runtime options that change scanner behavior."""

    cisco_skill_scan: str = "auto"
    cisco_policy: str = "balanced"


@dataclass(frozen=True, slots=True)
class ScanSkipTarget:
    """A marketplace entry that was not scanned as a local plugin target."""

    name: str
    reason: str
    source_path: str | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Full result of scanning a plugin directory."""

    score: int
    grade: str
    categories: tuple[CategoryResult, ...]
    timestamp: str
    plugin_dir: str
    findings: tuple[Finding, ...] = ()
    severity_counts: dict[str, int] = field(default_factory=dict)
    integrations: tuple[IntegrationResult, ...] = ()
    scope: str = "plugin"
    plugin_name: str | None = None
    plugin_results: tuple[ScanResult, ...] = ()
    skipped_targets: tuple[ScanSkipTarget, ...] = ()
    marketplace_file: str | None = None


def get_grade(score: int) -> str:
    """Convert a numeric score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def severity_from_value(value: str | Severity) -> Severity:
    """Normalize external severity strings into the local enum."""

    if isinstance(value, Severity):
        return value
    normalized = value.strip().lower()
    try:
        return Severity(normalized)
    except ValueError:
        return Severity.INFO


def build_severity_counts(findings: tuple[Finding, ...]) -> dict[str, int]:
    """Count findings by severity."""

    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def max_severity(findings: tuple[Finding, ...]) -> Severity | None:
    """Return the most severe finding, if any."""

    if not findings:
        return None
    return max(findings, key=lambda finding: SEVERITY_ORDER[finding.severity]).severity


GRADE_LABELS: dict[str, str] = {
    "A": "Excellent",
    "B": "Good",
    "C": "Acceptable",
    "D": "Needs Improvement",
    "F": "Failing",
}
