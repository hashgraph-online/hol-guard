"""Shared helpers for scanner profiles."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .checks.best_practices import (
    check_no_env_files,
    check_readme,
    check_skill_frontmatter,
    check_skills_directory,
)
from .checks.code_quality import run_code_quality_checks
from .checks.mcp_security import resolve_mcp_security_context, run_mcp_security_checks
from .checks.operational_security import run_operational_security_checks
from .checks.security import run_security_checks
from .integrations.cisco_skill_scanner import CiscoIntegrationStatus
from .models import (
    CategoryResult,
    CheckResult,
    IntegrationResult,
    PackageSummary,
    ScanOptions,
    ScanResult,
    build_severity_counts,
    get_grade,
)


def build_skill_integration_results(
    skill_security_context,
    package_label: str = "",
) -> tuple[IntegrationResult, ...]:
    integration_name = "cisco-skill-scanner" if not package_label else f"cisco-skill-scanner[{package_label}]"
    if skill_security_context.skip_message:
        return (
            IntegrationResult(
                name=integration_name,
                status=CiscoIntegrationStatus.SKIPPED,
                message=skill_security_context.skip_message,
            ),
        )

    summary = skill_security_context.summary
    if summary is None:
        return (
            IntegrationResult(
                name=integration_name,
                status=CiscoIntegrationStatus.SKIPPED,
                message="Cisco scan context unavailable.",
            ),
        )

    metadata = {"policy": summary.policy_name}
    if summary.analyzers_used:
        metadata["analyzers"] = ",".join(summary.analyzers_used)
    return (
        IntegrationResult(
            name=integration_name,
            status=summary.status,
            message=summary.message,
            findings_count=summary.total_findings,
            metadata=metadata,
        ),
    )


def build_mcp_integration_results(
    mcp_security_context,
    package_label: str = "",
) -> tuple[IntegrationResult, ...]:
    integration_name = "cisco-mcp-scanner" if not package_label else f"cisco-mcp-scanner[{package_label}]"
    if mcp_security_context.skip_message:
        return (
            IntegrationResult(
                name=integration_name,
                status=CiscoIntegrationStatus.SKIPPED,
                message=mcp_security_context.skip_message,
            ),
        )

    summary = mcp_security_context.summary
    if summary is None:
        return (
            IntegrationResult(
                name=integration_name,
                status=CiscoIntegrationStatus.SKIPPED,
                message="Cisco MCP scan context unavailable.",
            ),
        )

    metadata = {
        "scan_mode": summary.scan_mode,
        "targets_scanned": str(summary.targets_scanned),
    }
    if summary.analyzers_used:
        metadata["analyzers"] = ",".join(summary.analyzers_used)
    return (
        IntegrationResult(
            name=integration_name,
            status=summary.status,
            message=summary.message,
            findings_count=summary.total_findings,
            metadata=metadata,
        ),
    )


def build_integration_results(
    skill_security_context,
    mcp_security_context,
    package_label: str = "",
) -> tuple[IntegrationResult, ...]:
    return build_skill_integration_results(
        skill_security_context,
        package_label,
    ) + build_mcp_integration_results(
        mcp_security_context,
        package_label,
    )


def score_categories(categories: tuple[CategoryResult, ...]) -> int:
    earned_points = sum(check.points for category in categories for check in category.checks)
    max_points = sum(check.max_points for category in categories for check in category.checks)
    return 100 if max_points == 0 else round((earned_points / max_points) * 100)


def _run_generic_best_practice_checks(target_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_readme(target_dir),
        check_skills_directory(target_dir),
        check_skill_frontmatter(target_dir),
        check_no_env_files(target_dir),
    )


def scan_generic_target(target_dir: Path, options: ScanOptions) -> ScanResult:
    mcp_security_context = resolve_mcp_security_context(target_dir, options)
    categories = (
        CategoryResult(
            name="Security",
            checks=run_security_checks(target_dir)
            + run_mcp_security_checks(
                target_dir,
                options,
                mcp_security_context,
            ),
        ),
        CategoryResult(
            name="Operational Security",
            checks=run_operational_security_checks(target_dir),
        ),
        CategoryResult(
            name="Best Practices",
            checks=_run_generic_best_practice_checks(target_dir),
        ),
        CategoryResult(
            name="Code Quality",
            checks=run_code_quality_checks(target_dir),
        ),
    )
    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)
    score = score_categories(categories)
    return ScanResult(
        score=score,
        grade=get_grade(score),
        categories=categories,
        timestamp=datetime.now(timezone.utc).isoformat(),
        plugin_dir=str(target_dir),
        findings=findings,
        severity_counts=build_severity_counts(findings),
        integrations=build_mcp_integration_results(mcp_security_context),
        scope="repository",
        ecosystems=("generic",),
        packages=(
            PackageSummary(
                ecosystem="generic",
                package_kind="standalone-repository",
                root_path=str(target_dir),
            ),
        ),
    )
