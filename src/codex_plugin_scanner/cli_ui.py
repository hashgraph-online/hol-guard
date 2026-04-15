"""Human-friendly CLI rendering helpers."""

from __future__ import annotations

import sys
from pathlib import Path

from .models import GRADE_LABELS, ScanResult, Severity
from .version import __version__


def build_plain_text(result: ScanResult) -> str:
    """Render a scan result as human-readable text."""

    if getattr(result, "scope", "plugin") == "repository":
        trust_total = result.trust_report.total if getattr(result, "trust_report", None) else 0.0
        lines = [
            f"🔗 Plugin Scanner v{__version__}",
            f"Scanning repository: {result.plugin_dir}",
            f"Marketplace: {result.marketplace_file or 'not found'}",
            f"Local plugins scanned: {len(result.plugin_results)}",
            f"Skipped marketplace entries: {len(result.skipped_targets)}",
            f"Trust: {trust_total}/100",
            "",
            "Per-plugin scores:",
        ]
        for plugin in result.plugin_results:
            plugin_name = plugin.plugin_name or Path(plugin.plugin_dir).name
            plugin_trust = plugin.trust_report.total if getattr(plugin, "trust_report", None) else 0.0
            lines.append(f"  - {plugin_name}: {plugin.score}/100 ({plugin.grade}), trust {plugin_trust}/100")
        if result.skipped_targets:
            lines += ["", "Skipped entries:"]
            for skipped in result.skipped_targets:
                source_path = f" [{skipped.source_path}]" if skipped.source_path else ""
                lines.append(f"  - {skipped.name}{source_path}: {skipped.reason}")
        lines.append("")
    else:
        trust_total = result.trust_report.total if getattr(result, "trust_report", None) else 0.0
        lines = [
            f"🔗 Plugin Scanner v{__version__}",
            f"Scanning: {result.plugin_dir}",
            f"Trust: {trust_total}/100",
            "",
        ]
        ecosystems = getattr(result, "ecosystems", ())
        packages = getattr(result, "packages", ())
        if ecosystems:
            lines.append(f"Ecosystems: {', '.join(ecosystems)}")
        if packages:
            lines.append(f"Detected packages: {len(packages)}")
        if ecosystems or packages:
            lines.append("")
    for category in result.categories:
        cat_score = sum(check.points for check in category.checks)
        cat_max = sum(check.max_points for check in category.checks)
        lines.append(f"── {category.name} ({cat_score}/{cat_max}) ──")
        for check in category.checks:
            icon = "✅" if check.passed else "⚠️"
            points = f"+{check.points}" if check.passed else "+0"
            lines.append(f"  {icon} {check.name:<42} {points}")
        lines.append("")
    counts = ", ".join(f"{severity.value}:{result.severity_counts.get(severity.value, 0)}" for severity in Severity)
    lines += [f"Findings: {counts}", ""]
    if getattr(result, "trust_report", None) and result.trust_report.domains:
        lines.append("Trust Provenance:")
        for domain in result.trust_report.domains:
            lines.append(f"  - {domain.label}: {domain.score}/100 ({domain.spec_id})")
        lines.append("")
    if result.integrations:
        lines.append("Integration Status:")
        for integration in result.integrations:
            lines.append(f"  - {integration.name}: {integration.status} - {integration.message}")
        lines.append("")
    separator = "━" * 37
    label = GRADE_LABELS.get(result.grade, "Unknown")
    lines += [separator, f"Final Score: {result.score}/100 ({result.grade} - {label})", separator]
    return "\n".join(lines)


def build_verification_text(payload: dict[str, object]) -> str:
    """Render verification payloads in a human-readable format."""

    verify_pass = bool(payload.get("verify_pass"))
    status = "PASS" if verify_pass else "FAIL"
    lines = [f"Verification: {status}", ""]
    cases = payload.get("cases", [])
    if not isinstance(cases, list):
        return "\n".join(lines)
    for case in cases:
        if not isinstance(case, dict):
            continue
        icon = "✅" if case.get("passed") else "⚠️"
        component = case.get("component", "unknown")
        name = case.get("name", "unnamed")
        message = case.get("message", "")
        lines.append(f"{icon} {component}: {name} - {message}")
    return "\n".join(lines)


def build_cli_epilog(program_name: str, *, include_guard: bool) -> str:
    """Return shared top-level help examples."""

    lines = [
        "Common workflows:",
        f"  {program_name} scan ./my-plugin",
        f"  {program_name} scan ./my-plugin --format json --output report.json",
        f"  {program_name} lint ./my-plugin --fix",
        f"  {program_name} verify ./my-plugin --online",
    ]
    if include_guard:
        lines.extend(
            [
                f"  {program_name} guard start",
                f"  {program_name} guard bootstrap codex",
            ]
        )
    lines.extend(
        [
            "",
            "Automation:",
            "  Use --format json or --json in CI when another tool will parse stdout.",
        ]
    )
    return "\n".join(lines)


def build_scan_help_epilog(program_name: str) -> str:
    """Return scan-specific help examples."""

    return "\n".join(
        [
            "Common workflows:",
            f"  {program_name} scan ./my-plugin",
            f"  {program_name} scan ./my-plugin --format json --output report.json",
            f"  {program_name} scan ./plugins --ecosystem codex",
            "",
            "Automation:",
            "  Use --format json or --json in CI when another tool will parse stdout.",
        ]
    )


def emit_scan_provenance(*, profile: str, config_path: Path | None, baseline_path: Path | None) -> None:
    """Emit lightweight provenance for human-readable scan flows."""

    lines = [f"Policy profile: {profile}"]
    if config_path is not None:
        lines.append(f"Using config: {config_path}")
    if baseline_path is not None and baseline_path.exists():
        lines.append(f"Using baseline: {baseline_path}")
    elif baseline_path is not None:
        lines.append(f"Baseline not found: {baseline_path}")
    print("\n".join(lines), file=sys.stderr)


def emit_hint(message: str) -> None:
    """Emit a single hint line to stderr."""

    print(f"hint: {message}", file=sys.stderr)
