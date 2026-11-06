"""Fail-closed results shared by security checks."""

from __future__ import annotations

from ..models import CheckResult, Finding, Severity


class ScanInputUnreadableError(RuntimeError):
    """Raised when filesystem traversal cannot cover the requested input."""


def unreadable_scan_input_failure(
    name: str,
    *,
    max_points: int,
    path: str | None = None,
    reason: str | None = None,
) -> CheckResult:
    subject = path or "plugin directory tree"
    detail = f": {reason}" if reason else ""
    return CheckResult(
        name=name,
        passed=False,
        points=0,
        max_points=max_points,
        message=f"Security analysis incomplete: could not safely read {subject}{detail}.",
        findings=(
            Finding(
                rule_id="SCAN_INPUT_UNREADABLE",
                severity=Severity.MEDIUM,
                category="security",
                title="Security scan input could not be read safely",
                description=f"The scanner could not complete analysis of {subject}{detail}.",
                remediation=(
                    "Ensure every scanned path is readable, regular where applicable, and contained within the plugin."
                ),
                file_path=path,
            ),
        ),
    )
