"""Structured report formatters for scan results."""

from __future__ import annotations

import json

from .models import GRADE_LABELS, SEVERITY_ORDER, Finding, ScanResult, Severity, severity_from_value
from .version import __version__


def _sorted_findings(findings: tuple[Finding, ...]) -> list[Finding]:
    return sorted(findings, key=lambda finding: SEVERITY_ORDER[finding.severity], reverse=True)


def build_json_payload(
    result: ScanResult,
    *,
    profile: str = "default",
    policy_pass: bool = True,
    verify_pass: bool = True,
    raw_score: int | None = None,
    effective_score: int | None = None,
) -> dict[str, object]:
    """Convert a scan result into a JSON-serializable payload."""

    payload = {
        "schema_version": "scan-result.v1",
        "tool_version": __version__,
        "profile": profile,
        "policy_pass": policy_pass,
        "verify_pass": verify_pass,
        "scope": result.scope,
        "score": result.score,
        "raw_score": result.score if raw_score is None else raw_score,
        "effective_score": result.score if effective_score is None else effective_score,
        "grade": result.grade,
        "summary": {
            "gradeLabel": GRADE_LABELS.get(result.grade, "Unknown"),
            "findings": result.severity_counts,
            "integrations": [
                {
                    "name": integration.name,
                    "status": integration.status,
                    "message": integration.message,
                    "findingsCount": integration.findings_count,
                    "metadata": integration.metadata,
                }
                for integration in result.integrations
            ],
        },
        "categories": [
            {
                "name": category.name,
                "score": sum(check.points for check in category.checks),
                "max": sum(check.max_points for check in category.checks),
                "checks": [
                    {
                        "name": check.name,
                        "passed": check.passed,
                        "points": check.points,
                        "maxPoints": check.max_points,
                        "message": check.message,
                        "findings": [
                            {
                                "ruleId": finding.rule_id,
                                "severity": finding.severity.value,
                                "title": finding.title,
                                "description": finding.description,
                                "remediation": finding.remediation,
                                "filePath": finding.file_path,
                                "lineNumber": finding.line_number,
                                "source": finding.source,
                            }
                            for finding in check.findings
                        ],
                    }
                    for check in category.checks
                ],
            }
            for category in result.categories
        ],
        "findings": [
            {
                "ruleId": finding.rule_id,
                "severity": finding.severity.value,
                "category": finding.category,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "filePath": finding.file_path,
                "lineNumber": finding.line_number,
                "source": finding.source,
            }
            for finding in _sorted_findings(result.findings)
        ],
        "timestamp": result.timestamp,
        "pluginDir": result.plugin_dir,
    }
    if result.scope == "repository":
        payload["repository"] = {
            "marketplaceFile": result.marketplace_file,
            "localPluginCount": len(result.plugin_results),
        }
        payload["plugins"] = [
            {
                "name": plugin.plugin_name or plugin.plugin_dir.rsplit("/", 1)[-1],
                "pluginDir": plugin.plugin_dir,
                "score": plugin.score,
                "grade": plugin.grade,
                "summary": {
                    "findings": plugin.severity_counts,
                    "integrations": [
                        {
                            "name": integration.name,
                            "status": integration.status,
                            "message": integration.message,
                            "findingsCount": integration.findings_count,
                            "metadata": integration.metadata,
                        }
                        for integration in plugin.integrations
                    ],
                },
            }
            for plugin in result.plugin_results
        ]
        payload["skippedTargets"] = [
            {
                "name": skipped.name,
                "reason": skipped.reason,
                "sourcePath": skipped.source_path,
            }
            for skipped in result.skipped_targets
        ]
    return payload


def format_json(
    result: ScanResult,
    *,
    profile: str = "default",
    policy_pass: bool = True,
    verify_pass: bool = True,
    raw_score: int | None = None,
    effective_score: int | None = None,
) -> str:
    """Render a scan result as indented JSON."""

    return json.dumps(
        build_json_payload(
            result,
            profile=profile,
            policy_pass=policy_pass,
            verify_pass=verify_pass,
            raw_score=raw_score,
            effective_score=effective_score,
        ),
        indent=2,
    )


def format_markdown(result: ScanResult) -> str:
    """Render a scan result as a markdown report."""

    lines = [
        "# Codex Plugin Scanner Report",
        "",
        f"- {'Repository' if result.scope == 'repository' else 'Plugin'}: `{result.plugin_dir}`",
        f"- Score: **{result.score}/100**",
        f"- Grade: **{result.grade} - {GRADE_LABELS.get(result.grade, 'Unknown')}**",
        "",
        "## Findings Summary",
        "",
    ]
    for severity in Severity:
        lines.append(f"- {severity.value.title()}: {result.severity_counts.get(severity.value, 0)}")

    if result.scope == "repository":
        lines += ["", "## Local Plugins", ""]
        for plugin in result.plugin_results:
            lines.append(f"- **{plugin.plugin_name or plugin.plugin_dir}**: {plugin.score}/100 ({plugin.grade})")
        if result.skipped_targets:
            lines += ["", "## Skipped Marketplace Entries", ""]
            for skipped in result.skipped_targets:
                source_path = f" (`{skipped.source_path}`)" if skipped.source_path else ""
                lines.append(f"- **{skipped.name}**{source_path}: {skipped.reason}")

    lines += ["", "## Categories", ""]
    for category in result.categories:
        category_score = sum(check.points for check in category.checks)
        category_max = sum(check.max_points for check in category.checks)
        lines.append(f"- **{category.name}**: {category_score}/{category_max}")

    top_findings = _sorted_findings(result.findings)[:10]
    lines += ["", "## Top Findings", ""]
    if not top_findings:
        lines.append("- No findings detected.")
    else:
        for finding in top_findings:
            path = f" (`{finding.file_path}`)" if finding.file_path else ""
            lines.append(f"- **{finding.severity.value.upper()}** {finding.title}{path}")
            lines.append(f"  - {finding.description}")
            if finding.remediation:
                lines.append(f"  - Remediation: {finding.remediation}")

    lines += ["", "## Integration Status", ""]
    for integration in result.integrations:
        lines.append(f"- **{integration.name}**: `{integration.status}` - {integration.message}")

    return "\n".join(lines)


def format_sarif(result: ScanResult) -> str:
    """Render a scan result as SARIF 2.1.0 JSON."""

    sorted_findings = _sorted_findings(result.findings)
    rules = []
    seen_rules: set[str] = set()
    for finding in sorted_findings:
        if finding.rule_id in seen_rules:
            continue
        rules.append(
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.remediation or "Review and remediate this finding."},
                "properties": {
                    "tags": [finding.category, finding.source],
                    "precision": "high",
                    "problem.severity": finding.severity.value,
                },
            }
        )
        seen_rules.add(finding.rule_id)

    results = []
    for finding in sorted_findings:
        level = "note"
        if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.HIGH]:
            level = "error"
        elif SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.MEDIUM]:
            level = "warning"

        result_entry: dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {"text": finding.description},
            "properties": {
                "severity": finding.severity.value,
                "category": finding.category,
                "source": finding.source,
            },
        }
        if finding.file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                }
            }
            if finding.line_number:
                location["physicalLocation"]["region"] = {"startLine": finding.line_number}
            result_entry["locations"] = [location]
        results.append(result_entry)

    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "codex-plugin-scanner",
                        "informationUri": "https://github.com/hashgraph-online/codex-plugin-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def should_fail_for_severity(result: ScanResult, threshold: str | None) -> bool:
    """Return True when the result contains a finding at or above the threshold."""

    if not threshold or threshold.lower() == "none":
        return False
    threshold_severity = severity_from_value(threshold)
    return any(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold_severity] for finding in result.findings)
