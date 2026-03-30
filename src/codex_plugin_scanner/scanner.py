"""Codex Plugin Scanner - core scanning engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .checks.best_practices import run_best_practice_checks
from .checks.code_quality import run_code_quality_checks
from .checks.manifest import run_manifest_checks
from .checks.marketplace import run_marketplace_checks
from .checks.operational_security import run_operational_security_checks
from .checks.security import run_security_checks
from .checks.skill_security import resolve_skill_security_context, run_skill_security_checks
from .integrations.cisco_skill_scanner import CiscoIntegrationStatus
from .models import (
    CategoryResult,
    IntegrationResult,
    ScanOptions,
    ScanResult,
    build_severity_counts,
    get_grade,
)


def _build_integration_results(
    skill_security_context,
) -> tuple[IntegrationResult, ...]:
    if skill_security_context.skip_message:
        return (
            IntegrationResult(
                name="cisco-skill-scanner",
                status=CiscoIntegrationStatus.SKIPPED,
                message=skill_security_context.skip_message,
            ),
        )

    summary = skill_security_context.summary
    if summary is None:
        return (
            IntegrationResult(
                name="cisco-skill-scanner",
                status=CiscoIntegrationStatus.SKIPPED,
                message="Cisco scan context unavailable.",
            ),
        )

    metadata = {"policy": summary.policy_name}
    if summary.analyzers_used:
        metadata["analyzers"] = ",".join(summary.analyzers_used)
    return (
        IntegrationResult(
            name="cisco-skill-scanner",
            status=summary.status,
            message=summary.message,
            findings_count=summary.total_findings,
            metadata=metadata,
        ),
    )


def scan_plugin(plugin_dir: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Scan a Codex plugin directory and return a scored result.

    Args:
        plugin_dir: Path to the plugin directory to scan.

    Returns:
        ScanResult with score 0-100, grade A-F, and per-category breakdowns.
    """
    resolved = Path(plugin_dir).resolve()
    scan_options = options or ScanOptions()
    skill_security_context = resolve_skill_security_context(resolved, scan_options)

    categories: list[CategoryResult] = [
        CategoryResult(name="Manifest Validation", checks=run_manifest_checks(resolved)),
        CategoryResult(name="Security", checks=run_security_checks(resolved)),
        CategoryResult(name="Operational Security", checks=run_operational_security_checks(resolved)),
        CategoryResult(name="Best Practices", checks=run_best_practice_checks(resolved)),
        CategoryResult(name="Marketplace", checks=run_marketplace_checks(resolved)),
        CategoryResult(
            name="Skill Security",
            checks=run_skill_security_checks(resolved, scan_options, skill_security_context),
        ),
        CategoryResult(name="Code Quality", checks=run_code_quality_checks(resolved)),
    ]

    earned_points = sum(check.points for category in categories for check in category.checks)
    max_points = sum(check.max_points for category in categories for check in category.checks)
    score = 100 if max_points == 0 else round((earned_points / max_points) * 100)
    grade = get_grade(score)
    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)
    severity_counts = build_severity_counts(findings)
    integrations = _build_integration_results(skill_security_context)

    return ScanResult(
        score=score,
        grade=grade,
        categories=tuple(categories),
        timestamp=datetime.now(timezone.utc).isoformat(),
        plugin_dir=str(resolved),
        findings=findings,
        severity_counts=severity_counts,
        integrations=integrations,
    )
