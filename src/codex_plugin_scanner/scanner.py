"""Codex Plugin Scanner - core scanning engine."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .checks.best_practices import run_best_practice_checks
from .checks.claude import run_claude_checks
from .checks.code_quality import run_code_quality_checks
from .checks.gemini import run_gemini_checks
from .checks.manifest import run_manifest_checks
from .checks.marketplace import run_marketplace_checks
from .checks.opencode import run_opencode_checks
from .checks.operational_security import run_operational_security_checks
from .checks.security import run_security_checks
from .checks.skill_security import resolve_skill_security_context, run_skill_security_checks
from .ecosystems.detect import detect_packages
from .ecosystems.registry import get_default_adapters, resolve_ecosystem
from .ecosystems.types import Ecosystem, NormalizedPackage, PackageCandidate
from .integrations.cisco_skill_scanner import CiscoIntegrationStatus
from .models import (
    CategoryResult,
    CheckResult,
    Finding,
    IntegrationResult,
    PackageSummary,
    ScanOptions,
    ScanResult,
    build_severity_counts,
    get_grade,
)
from .repo_detect import LocalPluginTarget, discover_scan_targets
from .trust_scoring import build_plugin_trust_report, build_repository_trust_report


def _build_integration_results(skill_security_context, package_label: str = "") -> tuple[IntegrationResult, ...]:
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


def _score_categories(categories: tuple[CategoryResult, ...]) -> int:
    earned_points = sum(check.points for category in categories for check in category.checks)
    max_points = sum(check.max_points for category in categories for check in category.checks)
    return 100 if max_points == 0 else round((earned_points / max_points) * 100)


def _build_adapter_map() -> dict[Ecosystem, object]:
    adapters = get_default_adapters()
    return {adapter.ecosystem_id: adapter for adapter in adapters}


def _build_candidate_fallback(resolved: Path, requested: Ecosystem | None) -> list[PackageCandidate]:
    if requested is not None:
        return [
            PackageCandidate(
                ecosystem=requested,
                package_kind="workspace-bundle",
                root_path=resolved,
                manifest_path=None,
                detection_reason="fallback to requested ecosystem at scan root",
            )
        ]
    return [
        PackageCandidate(
            ecosystem=Ecosystem.CODEX,
            package_kind="single-plugin",
            root_path=resolved,
            manifest_path=resolved / ".codex-plugin" / "plugin.json",
            detection_reason="legacy codex fallback at scan root",
        )
    ]


def _category_prefix(scan_root: Path, package: NormalizedPackage, package_count: int) -> str:
    if package_count == 1 and package.root_path.resolve() == scan_root.resolve():
        return ""
    try:
        relative_root = package.root_path.resolve().relative_to(scan_root.resolve())
        relative_label = "." if str(relative_root) == "." else str(relative_root)
    except ValueError:
        relative_label = str(package.root_path)
    return f"[{package.ecosystem.value}:{relative_label}] "


def _is_path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _summarize_package(package: NormalizedPackage) -> PackageSummary:
    return PackageSummary(
        ecosystem=package.ecosystem.value,
        package_kind=package.package_kind,
        root_path=str(package.root_path),
        manifest_path=str(package.manifest_path) if package.manifest_path is not None else None,
        name=package.name,
        version=package.version,
    )


def _rebase_finding(finding: Finding, plugin_dir: Path, repo_root: Path) -> Finding:
    if not finding.file_path:
        return finding
    file_path = Path(finding.file_path)
    resolved_path = file_path.resolve() if file_path.is_absolute() else (plugin_dir / file_path).resolve()
    try:
        rebased_path = resolved_path.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return finding
    return replace(finding, file_path=rebased_path)


def _rebase_check_result(check: CheckResult, plugin_dir: Path, repo_root: Path) -> CheckResult:
    return replace(
        check,
        findings=tuple(_rebase_finding(finding, plugin_dir, repo_root) for finding in check.findings),
    )


def _maybe_rebase_checks(
    checks: tuple[CheckResult, ...],
    plugin_dir: Path,
    repo_root: Path,
    enabled: bool,
) -> tuple[CheckResult, ...]:
    if not enabled:
        return checks
    return tuple(_rebase_check_result(check, plugin_dir, repo_root) for check in checks)


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
        ecosystems=("codex",),
        packages=(
            PackageSummary(
                ecosystem="codex",
                package_kind="single-plugin",
                root_path=str(plugin_dir),
                manifest_path=str(plugin_dir / ".codex-plugin" / "plugin.json"),
                name=None,
                version=None,
            ),
        ),
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
    ecosystems = tuple(sorted({ecosystem for plugin in plugin_results for ecosystem in plugin.ecosystems})) or (
        "codex",
    )
    packages = tuple(summary for plugin in plugin_results for summary in plugin.packages)
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
        ecosystems=ecosystems,
        packages=packages,
    )


def _scan_mixed_packages(scan_root: Path, packages: list[NormalizedPackage], options: ScanOptions) -> ScanResult:
    package_count = len(packages)
    scan_root_resolved = scan_root.resolve()
    categories: list[CategoryResult] = []
    integrations: list[IntegrationResult] = []
    plugin_results: list[ScanResult] = []
    skipped_targets = []
    codex_trust_reports = []
    processed_packages: list[NormalizedPackage] = []
    codex_marketplace_roots = tuple(
        package.root_path.resolve()
        for package in packages
        if package.ecosystem == Ecosystem.CODEX and package.package_kind == "marketplace"
    )

    for package in packages:
        package_root = package.root_path.resolve()
        if (
            package.ecosystem == Ecosystem.CODEX
            and package.package_kind == "single-plugin"
            and any(
                package_root != marketplace_root and _is_path_within(package_root, marketplace_root)
                for marketplace_root in codex_marketplace_roots
            )
        ):
            continue
        needs_rebase = package_root != scan_root_resolved
        prefix = _category_prefix(scan_root, package, package_count)

        if package.ecosystem == Ecosystem.CODEX:
            if package.package_kind == "marketplace":
                codex_repo_result = _scan_repository(package_root, options)
                codex_categories = list(codex_repo_result.categories)
                codex_integrations = list(codex_repo_result.integrations)
                if prefix:
                    codex_categories = [
                        CategoryResult(name=f"{prefix}{category.name}", checks=category.checks)
                        for category in codex_categories
                    ]
                    codex_integrations = [
                        replace(
                            integration,
                            name=f"{package.ecosystem.value}:{package_root.name} / {integration.name}",
                        )
                        for integration in codex_integrations
                    ]
                categories.extend(codex_categories)
                integrations.extend(codex_integrations)
                if codex_repo_result.trust_report is not None:
                    codex_trust_reports.append(codex_repo_result.trust_report)
                plugin_results.extend(codex_repo_result.plugin_results)
                skipped_targets.extend(codex_repo_result.skipped_targets)
                processed_packages.append(package)
                continue

            codex_result = _scan_single_plugin(package_root, options)
            package_name = package.name or package_root.name
            if needs_rebase:
                codex_plugin_result = _rebase_plugin_result(
                    codex_result,
                    LocalPluginTarget(name=package_name, plugin_dir=package_root, source_path="./"),
                    scan_root_resolved,
                )
            else:
                codex_plugin_result = replace(codex_result, plugin_name=package_name)
            codex_categories = [
                CategoryResult(
                    name=category.name,
                    checks=_maybe_rebase_checks(category.checks, package_root, scan_root_resolved, needs_rebase),
                )
                for category in codex_result.categories
            ]
            codex_integrations = list(codex_result.integrations)
            if prefix:
                codex_categories = [
                    CategoryResult(name=f"{prefix}{category.name}", checks=category.checks)
                    for category in codex_categories
                ]
                codex_integrations = [
                    replace(
                        integration,
                        name=f"{package.ecosystem.value}:{package_root.name} / {integration.name}",
                    )
                    for integration in codex_integrations
                ]
            categories.extend(codex_categories)
            integrations.extend(codex_integrations)
            if codex_result.trust_report is not None:
                codex_trust_reports.append(codex_result.trust_report)
            plugin_results.append(codex_plugin_result)
            processed_packages.append(package)
            continue

        if package.ecosystem == Ecosystem.CLAUDE:
            claude_checks = _maybe_rebase_checks(
                run_claude_checks(package),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            security_checks = _maybe_rebase_checks(
                run_security_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            operational_checks = _maybe_rebase_checks(
                run_operational_security_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            quality_checks = _maybe_rebase_checks(
                run_code_quality_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            categories.extend(
                (
                    CategoryResult(name=f"{prefix}Claude Plugin", checks=claude_checks),
                    CategoryResult(name=f"{prefix}Security", checks=security_checks),
                    CategoryResult(name=f"{prefix}Operational Security", checks=operational_checks),
                    CategoryResult(name=f"{prefix}Code Quality", checks=quality_checks),
                )
            )
            processed_packages.append(package)
            continue

        if package.ecosystem == Ecosystem.GEMINI:
            gemini_checks = _maybe_rebase_checks(
                run_gemini_checks(package),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            security_checks = _maybe_rebase_checks(
                run_security_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            operational_checks = _maybe_rebase_checks(
                run_operational_security_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            quality_checks = _maybe_rebase_checks(
                run_code_quality_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            categories.extend(
                (
                    CategoryResult(name=f"{prefix}Gemini Extension", checks=gemini_checks),
                    CategoryResult(name=f"{prefix}Security", checks=security_checks),
                    CategoryResult(name=f"{prefix}Operational Security", checks=operational_checks),
                    CategoryResult(name=f"{prefix}Code Quality", checks=quality_checks),
                )
            )
            processed_packages.append(package)
            continue

        if package.ecosystem == Ecosystem.OPENCODE:
            opencode_checks = _maybe_rebase_checks(
                run_opencode_checks(package),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            security_checks = _maybe_rebase_checks(
                run_security_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            operational_checks = _maybe_rebase_checks(
                run_operational_security_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            quality_checks = _maybe_rebase_checks(
                run_code_quality_checks(package_root),
                package_root,
                scan_root_resolved,
                needs_rebase,
            )
            categories.extend(
                (
                    CategoryResult(name=f"{prefix}OpenCode Plugin", checks=opencode_checks),
                    CategoryResult(name=f"{prefix}Security", checks=security_checks),
                    CategoryResult(name=f"{prefix}Operational Security", checks=operational_checks),
                    CategoryResult(name=f"{prefix}Code Quality", checks=quality_checks),
                )
            )
            processed_packages.append(package)

    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)
    score = _score_categories(tuple(categories))
    trust_report = build_repository_trust_report(tuple(codex_trust_reports)) if codex_trust_reports else None
    reported_packages = tuple(processed_packages) if processed_packages else tuple(packages)
    marketplace_candidates = tuple(
        package
        for package in reported_packages
        if package.ecosystem == Ecosystem.CODEX and package.package_kind == "marketplace"
    )
    scope = "repository" if marketplace_candidates or len(reported_packages) > 1 else "plugin"
    marketplace_file = str(marketplace_candidates[0].manifest_path) if len(marketplace_candidates) == 1 else None
    return ScanResult(
        score=score,
        grade=get_grade(score),
        categories=tuple(categories),
        timestamp=datetime.now(timezone.utc).isoformat(),
        plugin_dir=str(scan_root),
        findings=findings,
        severity_counts=build_severity_counts(findings),
        integrations=tuple(integrations),
        scope=scope,
        plugin_results=tuple(plugin_results),
        skipped_targets=tuple(skipped_targets),
        marketplace_file=marketplace_file,
        trust_report=trust_report,
        ecosystems=tuple(sorted({package.ecosystem.value for package in reported_packages})),
        packages=tuple(_summarize_package(package) for package in reported_packages),
    )


def _scan_non_repository_target(target_dir: Path, options: ScanOptions) -> ScanResult:
    requested_ecosystem = resolve_ecosystem(options.ecosystem)
    candidates = detect_packages(target_dir, requested_ecosystem)
    if not candidates:
        candidates = _build_candidate_fallback(target_dir, requested_ecosystem)

    adapter_map = _build_adapter_map()
    packages = [adapter_map[candidate.ecosystem].parse(candidate) for candidate in candidates]

    if (
        len(packages) == 1
        and packages[0].ecosystem == Ecosystem.CODEX
        and packages[0].root_path.resolve() == target_dir.resolve()
    ):
        codex_result = _scan_single_plugin(target_dir, options)
        summary = _summarize_package(packages[0])
        return replace(codex_result, ecosystems=("codex",), packages=(summary,))

    return _scan_mixed_packages(target_dir, packages, options)


def scan_plugin(plugin_dir: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Scan a plugin directory or repository root."""

    resolved = Path(plugin_dir).resolve()
    scan_options = options or ScanOptions()
    requested_ecosystem = resolve_ecosystem(scan_options.ecosystem)
    discovery = discover_scan_targets(resolved)
    if discovery.scope == "repository":
        if requested_ecosystem == Ecosystem.CODEX:
            return _scan_repository(resolved, scan_options)
        if requested_ecosystem is None:
            detected_candidates = detect_packages(resolved)
            if not detected_candidates or all(
                candidate.ecosystem == Ecosystem.CODEX for candidate in detected_candidates
            ):
                return _scan_repository(resolved, scan_options)
    return _scan_non_repository_target(resolved, scan_options)
