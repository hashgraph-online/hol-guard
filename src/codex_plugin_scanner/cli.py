"""Codex Plugin Scanner - CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import GRADE_LABELS, ScanOptions, Severity
from .reporting import format_json as render_json
from .reporting import format_markdown, format_sarif, should_fail_for_severity
from .scanner import scan_plugin

__version__ = "1.1.0"


def format_text(result) -> str:
    """Format scan result as plain terminal output."""
    lines = [f"🔗 Codex Plugin Scanner v{__version__}", f"Scanning: {result.plugin_dir}", ""]
    for category in result.categories:
        cat_score = sum(c.points for c in category.checks)
        cat_max = sum(c.max_points for c in category.checks)
        lines.append(f"── {category.name} ({cat_score}/{cat_max}) ──")
        for check in category.checks:
            icon = "✅" if check.passed else "⚠️"
            pts = f"+{check.points}" if check.passed else "+0"
            lines.append(f"  {icon} {check.name:<42} {pts}")
        lines.append("")
    counts = ", ".join(f"{severity.value}:{result.severity_counts.get(severity.value, 0)}" for severity in Severity)
    lines += [f"Findings: {counts}", ""]
    if result.findings:
        lines.append("Top Findings:")
        for finding in result.findings[:5]:
            location = f" ({finding.file_path})" if finding.file_path else ""
            lines.append(f"  - {finding.severity.value.upper()} {finding.title}{location}")
        lines.append("")
    separator = "━" * 37
    label = GRADE_LABELS.get(result.grade, "Unknown")
    lines += [separator, f"Final Score: {result.score}/100 ({result.grade} - {label})", separator]
    return "\n".join(lines)


def format_json(result) -> str:
    """Format scan result as JSON."""
    return render_json(result)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns exit code."""
    parser = argparse.ArgumentParser(
        prog="codex-plugin-scanner",
        description="Scan a Codex plugin directory for best practices and security",
    )
    parser.add_argument("plugin_dir", help="Path to the plugin directory to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "sarif"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("--output", "-o", help="Write the report to a file")
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Exit with code 1 if score is below this threshold (default: 0)",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=("none", "critical", "high", "medium", "low", "info"),
        default="none",
        help="Exit with code 1 if any finding is at or above the selected severity.",
    )
    parser.add_argument(
        "--cisco-skill-scan",
        choices=("auto", "on", "off"),
        default="auto",
        help="Run Cisco skill-scanner automatically when available, require it, or disable it.",
    )
    parser.add_argument(
        "--cisco-policy",
        choices=("permissive", "balanced", "strict"),
        default="balanced",
        help="Cisco skill-scanner policy preset to use when the integration runs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1

    output_format = "json" if args.json else args.format
    if args.output and not args.json and args.format == "text":
        output_format = "json"
    result = scan_plugin(
        args.plugin_dir,
        ScanOptions(cisco_skill_scan=args.cisco_skill_scan, cisco_policy=args.cisco_policy),
    )

    if output_format == "json":
        output = format_json(result)
    elif output_format == "markdown":
        output = format_markdown(result)
    elif output_format == "sarif":
        output = format_sarif(result)
    else:
        output = format_text(result)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output, encoding="utf-8")
        print(f"Report written to {out_path}")
    elif output:
        print(output)

    if result.score < args.min_score:
        print(
            f"Score {result.score} is below minimum threshold {args.min_score}",
            file=sys.stderr,
        )
        return 1

    if should_fail_for_severity(result, args.fail_on_severity):
        print(
            f'Findings met or exceeded the "{args.fail_on_severity}" severity threshold.',
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())  # pragma: no cover
