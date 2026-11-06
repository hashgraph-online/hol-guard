"""Suppression-aware scan result transforms."""

from __future__ import annotations

from dataclasses import replace
from fnmatch import fnmatch

from codex_plugin_scanner.models import ScanResult, build_severity_counts


def apply_suppressions(
    result: ScanResult,
    *,
    enabled_rules: frozenset[str],
    disabled_rules: frozenset[str],
    baseline_ids: frozenset[str],
    ignore_paths: tuple[str, ...],
) -> ScanResult:
    def include_finding(finding) -> bool:
        if finding.rule_id in baseline_ids or finding.rule_id in disabled_rules:
            return False
        if enabled_rules and finding.rule_id not in enabled_rules:
            return False
        return not (finding.file_path and any(fnmatch(finding.file_path, pattern) for pattern in ignore_paths))

    categories = []
    for category in result.categories:
        checks = []
        for check in category.checks:
            filtered = tuple(finding for finding in check.findings if include_finding(finding))
            if check.findings and not filtered:
                checks.append(
                    replace(
                        check,
                        findings=filtered,
                        passed=True,
                        points=check.max_points,
                        message=f"{check.message} (all findings suppressed)",
                    )
                )
            else:
                checks.append(replace(check, findings=filtered))
        categories.append(replace(category, checks=tuple(checks)))

    findings = tuple(finding for finding in result.findings if include_finding(finding))
    return replace(
        result,
        categories=tuple(categories),
        findings=findings,
        severity_counts=build_severity_counts(findings),
    )


def compute_effective_score(result: ScanResult) -> int:
    earned = sum(check.points for category in result.categories for check in category.checks)
    maximum = sum(check.max_points for category in result.categories for check in category.checks)
    if maximum == 0:
        return 100
    return round((earned / maximum) * 100)


def apply_severity_overrides(result: ScanResult, overrides: dict[str, str] | None) -> ScanResult:
    if not overrides:
        return result

    from codex_plugin_scanner.models import severity_from_value

    def adjust(finding):
        override = overrides.get(finding.rule_id)
        if not override:
            return finding
        return replace(finding, severity=severity_from_value(override))

    categories = []
    for category in result.categories:
        checks = []
        for check in category.checks:
            checks.append(replace(check, findings=tuple(adjust(f) for f in check.findings)))
        categories.append(replace(category, checks=tuple(checks)))

    findings = tuple(adjust(f) for f in result.findings)
    return replace(
        result,
        categories=tuple(categories),
        findings=findings,
        severity_counts=build_severity_counts(findings),
    )
