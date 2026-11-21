"""Contributor triage metadata, never an admission or suppression mechanism."""

from __future__ import annotations

from collections import Counter

from .models import SEVERITY_ORDER, Finding, ScanResult
from .version import __version__

REVIEW_STEPS = (
    "Keep the full scan report, scanner version, source revision and scan run together.",
    "Report suspected false positives to the scanner project with the rule, location, "
    "intended behavior and a reproducer. "
    "For catalog submissions, use the existing submission PR. "
    "Do not publish real secrets or private source.",
    "A maintainer must distinguish a detector defect from a source problem, "
    "a risky capability or an infrastructure failure.",
    "Scanner maintainers own detector fixes and releases; catalog operators own their pinned scanner updates. "
    "Contributors need not maintain a scanner fork.",
    "Keep the score and severity gates unchanged; do not disable rules or trust a submitter-provided baseline.",
    "Repeat the scan on the exact source revision with the reviewed scanner release and unchanged policy. "
    "Catalog submissions require a new centralized scan.",
)


def contributor_review_lines(findings: tuple[Finding, ...]) -> tuple[str, ...]:
    """Render trusted guidance without interpolating untrusted finding text."""
    if not findings:
        return ()
    return (
        "",
        "### Contributor review pathway",
        "",
        "A finding can require investigation without proving malicious intent. "
        "Review does not grant approval or change the scan result.",
        "",
        *(f"{index}. {step}" for index, step in enumerate(REVIEW_STEPS, start=1)),
    )


def build_contributor_review(result: ScanResult) -> dict[str, object]:
    """Group identical evidence for triage while preserving all original findings.

    Group numbers refer only to this report. They are not source-bound
    attestations, review decisions, stable suppressions or authorization tokens.
    No source files are read and no submitted instructions are executed.
    """
    counts = Counter(result.findings)
    ordered = sorted(
        counts,
        key=lambda finding: (
            -SEVERITY_ORDER[finding.severity],
            finding.rule_id,
            finding.file_path is not None,
            finding.file_path or "",
            finding.line_number is not None,
            finding.line_number or 0,
            finding.source,
            finding.category,
            finding.title,
            finding.description,
            finding.remediation is not None,
            finding.remediation or "",
        ),
    )
    return {
        "schemaVersion": "contributor-review.v1",
        "purpose": "report-only",
        "automaticApproval": False,
        "sourceBoundAttestation": False,
        "scannerVersion": __version__,
        "findingCount": len(result.findings),
        "distinctEvidenceCount": len(counts),
        "groups": [
            {
                "reportGroup": index,
                "ruleId": finding.rule_id,
                "severity": finding.severity.value,
                "filePath": finding.file_path,
                "lineNumber": finding.line_number,
                "source": finding.source,
                "category": finding.category,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "occurrences": counts[finding],
                "disposition": "not-adjudicated",
            }
            for index, finding in enumerate(ordered, start=1)
        ],
        "steps": list(REVIEW_STEPS) if result.findings else [],
    }
