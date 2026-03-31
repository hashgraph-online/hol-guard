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
        if finding.file_path and any(fnmatch(finding.file_path, pattern) for pattern in ignore_paths):
            return False
        return True

    categories = []
    for category in result.categories:
        checks = []
        for check in category.checks:
            filtered = tuple(finding for finding in check.findings if include_finding(finding))
            checks.append(replace(check, findings=filtered))
        categories.append(replace(category, checks=tuple(checks)))

    findings = tuple(finding for finding in result.findings if include_finding(finding))
    return replace(
        result,
        categories=tuple(categories),
        findings=findings,
        severity_counts=build_severity_counts(findings),
    )


def compute_effective_score(raw_score: int, findings_count: int) -> int:
    penalty = min(findings_count, 50)
    return max(0, raw_score - penalty)
