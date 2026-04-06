"""Codex Plugin Scanner - core scanning engine."""

from __future__ import annotations

from dataclasses import replace
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
    CheckResult,
    Finding,
    IntegrationResult,
    ScanOptions,
    ScanResult,
    build_severity_counts,
    get_grade,
)
from .repo_detect import LocalPluginTarget, discover_scan_targets
from .trust_scoring import build_plugin_trust_report, build_repository_trust_report


def _build_integration_results(skill_security_context) -> tuple[IntegrationResult, ...]:
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


def _score_categories(categories: tuple[CategoryResult, ...]) -> int:
    earned_points = sum(check.points for category in categories for check in category.checks)
    max_points = sum(check.max_points for category in categories for check in category.checks)
    return 100 if max_points == 0 else round((earned_points / max_points) * 100)


def _rebase_finding(finding: Finding, plugin_dir: Path, repo_root: Path) -> Finding:
    if not finding.file_path:
        return finding
    rebased_path = (plugin_dir / finding.file_path).resolve().relative_to(repo_root).as_posix()
    return replace(finding, file_path=rebased_path)


def _rebase_check_result(check: CheckResult, plugin_dir: Path, repo_root: Path) -> CheckResult:
    return replace(
        check,
        findings=tuple(_rebase_finding(finding, plugin_dir, repo_root) for finding in check.findings),
    )


def _rebase_plugin_result(plugin_result: ScanResult, plugin_target: LocalPluginTarget, repo_root: Path) -> ScanResult:
    rebased_categories = tuple(
        CategoryResult(
            name=category.name,
            checks=tuple(_rebase_check_result(check, plugin_target.plugin_dir, repo_root) for check in category.checks),
        )
        for category in plugin_result.categories
    )
    rebased_integrations = tuple(
        replace(integration, name=f"{plugin_target.name} / {integration.name}")
        for integration in plugin_result.integrations
    )
    rebased_findings = tuple(
        _rebase_finding(finding, plugin_target.plugin_dir, repo_root) for finding in plugin_result.findings
    )
    return replace(
        plugin_result,
        categories=rebased_categories,
        findings=rebased_findings,
        severity_counts=build_severity_counts(rebased_findings),
        integrations=rebased_integrations,
        plugin_name=plugin_target.name,
    )


def _scan_single_plugin(plugin_dir: Path, options: ScanOptions) -> ScanResult:
    skill_security_context = resolve_skill_security_context(plugin_dir, options)
    categories: list[CategoryResult] = [
        CategoryResult(name="Manifest Validation", checks=run_manifest_checks(plugin_dir)),
        CategoryResult(name="Security", checks=run_security_checks(plugin_dir)),
        CategoryResult(name="Operational Security", checks=run_operational_security_checks(plugin_dir)),
        CategoryResult(name="Best Practices", checks=run_best_practice_checks(plugin_dir)),
        CategoryResult(name="Marketplace", checks=run_marketplace_checks(plugin_dir)),
        CategoryResult(
            name="Skill Security",
            checks=run_skill_security_checks(plugin_dir, options, skill_security_context),
        ),
        CategoryResult(name="Code Quality", checks=run_code_quality_checks(plugin_dir)),
    ]

    score = _score_categories(tuple(categories))
    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)
    trust_report = build_plugin_trust_report(plugin_dir, tuple(categories), skill_security_context)
    return ScanResult(
        score=score,
        grade=get_grade(score),
        categories=tuple(categories),
        timestamp=datetime.now(timezone.utc).isoformat(),
        plugin_dir=str(plugin_dir),
        findings=findings,
        severity_counts=build_severity_counts(findings),
        integrations=_build_integration_results(skill_security_context),
        scope="plugin",
        trust_report=trust_report,
    )


def _build_repository_categories(
    repo_root: Path,
    plugin_results: tuple[ScanResult, ...],
) -> tuple[CategoryResult, ...]:
    categories: list[CategoryResult] = [
        CategoryResult(name="Repository Marketplace", checks=run_marketplace_checks(repo_root)),
        CategoryResult(name="Repository Operational Security", checks=run_operational_security_checks(repo_root)),
    ]
    for plugin_result in plugin_results:
        for category in plugin_result.categories:
            if category.name in {"Marketplace", "Operational Security"}:
                continue
            plugin_name = plugin_result.plugin_name or Path(plugin_result.plugin_dir).name
            categories.append(CategoryResult(name=f"{plugin_name} · {category.name}", checks=category.checks))
    return tuple(categories)


def _scan_repository(repo_root: Path, options: ScanOptions) -> ScanResult:
    discovery = discover_scan_targets(repo_root)
    plugin_results = tuple(
        _rebase_plugin_result(_scan_single_plugin(target.plugin_dir, options), target, repo_root)
        for target in discovery.local_plugins
    )
    categories = _build_repository_categories(repo_root, plugin_results)
    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)
    repo_scores = [plugin.score for plugin in plugin_results]
    repo_category_score = _score_categories(categories[:2]) if categories[:2] else 100
    if categories[:2]:
        repo_scores.append(repo_category_score)
    score = min(repo_scores) if repo_scores else 0
    trust_report = build_repository_trust_report(
        tuple(plugin.trust_report for plugin in plugin_results if plugin.trust_report is not None)
    )
    return ScanResult(
        score=score,
        grade=get_grade(score),
        categories=categories,
        timestamp=datetime.now(timezone.utc).isoformat(),
        plugin_dir=str(repo_root),
        findings=findings,
        severity_counts=build_severity_counts(findings),
        integrations=tuple(integration for plugin in plugin_results for integration in plugin.integrations),
        scope="repository",
        plugin_results=plugin_results,
        skipped_targets=discovery.skipped_targets,
        marketplace_file=str(discovery.marketplace_file) if discovery.marketplace_file else None,
        trust_report=trust_report,
    )


def scan_plugin(plugin_dir: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Scan a Codex plugin directory or repo marketplace root."""

    resolved = Path(plugin_dir).resolve()
    scan_options = options or ScanOptions()
    discovery = discover_scan_targets(resolved)
    if discovery.scope == "repository":
        return _scan_repository(resolved, scan_options)
    return _scan_single_plugin(resolved, scan_options)
