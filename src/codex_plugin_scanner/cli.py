"""Codex Plugin Scanner - CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

from .config import load_baseline_rule_ids, load_scanner_config
from .lint_fixes import apply_safe_autofixes
from .models import GRADE_LABELS, ScanOptions, Severity, build_severity_counts
from .policy import evaluate_policy, resolve_profile
from .quality_artifact import build_quality_artifact, write_quality_artifact
from .reporting import format_json as render_json
from .reporting import format_markdown, format_sarif, should_fail_for_severity
from .rules import get_rule_spec, list_rule_specs
from .scanner import scan_plugin
from .verification import build_doctor_report, verify_plugin
from .version import __version__


def _build_plain_text(result) -> str:
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


def _build_rich_text(result) -> str:
    lines = [f"[bold cyan]🔗 Codex Plugin Scanner v{__version__}[/bold cyan]"]
    lines.append(f"Scanning: {result.plugin_dir}")
    lines.append("")
    for category in result.categories:
        cat_score = sum(c.points for c in category.checks)
        cat_max = sum(c.max_points for c in category.checks)
        lines.append(f"[bold yellow]── {category.name} ({cat_score}/{cat_max}) ──[/bold yellow]")
        for check in category.checks:
            icon = "✅" if check.passed else "⚠️"
            style = "[green]" if check.passed else "[red]"
            pts = f"[green]+{check.points}[/green]" if check.passed else "[red]+0[/red]"
            lines.append(f"  {icon} {style}{check.name:<42}[/]{pts}")
        lines.append("")
    separator = "━" * 37
    grade = result.grade
    gc = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}.get(grade, "red")
    label = GRADE_LABELS.get(grade, "Unknown")
    lines += [
        f"[bold]{separator}[/bold]",
        f"Final Score: [bold]{result.score}[/bold]/100 ([{gc}]{grade} - {label}[/{gc}])",
        f"[bold]{separator}[/bold]",
    ]
    return "\n".join(lines)


def format_text(result) -> str:
    return _build_plain_text(result)


def format_json(result, *, profile: str = "default", policy_pass: bool = True, verify_pass: bool = True) -> str:
    return render_json(result, profile=profile, policy_pass=policy_pass, verify_pass=verify_pass)


def _add_common_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", choices=("default", "public-marketplace", "strict-security"))
    parser.add_argument("--config", help="Path to .codex-plugin-scanner.toml")
    parser.add_argument("--baseline", help="Path to baseline suppression file")
    parser.add_argument("--strict", action="store_true", help="Fail if any finding is present")
    parser.add_argument("--diff-base", help="Reserved for future diff-aware gating")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codex-plugin-scanner", description="Scan and lint Codex plugin directories")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run full weighted scan")
    scan_parser.add_argument("plugin_dir", help="Path to the plugin directory to scan")
    scan_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    scan_parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    scan_parser.add_argument("--output", "-o", help="Write the report to a file")
    _add_common_policy_args(scan_parser)
    scan_parser.add_argument("--min-score", type=int, default=0)
    scan_parser.add_argument("--fail-on-severity", choices=("none", "critical", "high", "medium", "low", "info"), default="none")
    scan_parser.add_argument("--cisco-skill-scan", choices=("auto", "on", "off"), default="auto")
    scan_parser.add_argument("--cisco-policy", choices=("permissive", "balanced", "strict"), default="balanced")

    lint_parser = subparsers.add_parser("lint", help="Run rule-level lint evaluation")
    lint_parser.add_argument("plugin_dir", nargs="?", default=".", help="Path to plugin directory")
    _add_common_policy_args(lint_parser)
    lint_parser.add_argument("--format", choices=("text", "json"), default="text")
    lint_parser.add_argument("--list-rules", action="store_true")
    lint_parser.add_argument("--explain", metavar="RULE_ID")
    lint_parser.add_argument("--fix", action="store_true", help="Apply safe deterministic autofixes")

    verify_parser = subparsers.add_parser("verify", help="Run runtime verification checks")
    verify_parser.add_argument("plugin_dir", nargs="?", default=".", help="Path to plugin directory")
    verify_parser.add_argument("--profile", choices=("default", "public-marketplace", "strict-security"))
    verify_parser.add_argument("--online", action="store_true", help="Enable online remote checks")
    verify_parser.add_argument("--format", choices=("text", "json"), default="text")

    submit_parser = subparsers.add_parser("submit", help="Emit artifact after scan+verify+policy pass")
    submit_parser.add_argument("plugin_dir", nargs="?", default=".", help="Path to plugin directory")
    submit_parser.add_argument("--profile", choices=("default", "public-marketplace", "strict-security"))
    submit_parser.add_argument("--config", help="Path to .codex-plugin-scanner.toml")
    submit_parser.add_argument("--baseline", help="Path to baseline suppression file")
    submit_parser.add_argument("--attest", required=True, help="Artifact output path")
    submit_parser.add_argument("--online", action="store_true", help="Enable online verify mode")

    doctor_parser = subparsers.add_parser("doctor", help="Emit component diagnostics")
    doctor_parser.add_argument("plugin_dir", nargs="?", default=".", help="Path to plugin directory")
    doctor_parser.add_argument("--component", choices=("all", "manifest", "marketplace", "mcp"), default="all")
    doctor_parser.add_argument("--bundle", help="Optional path to write doctor JSON report")

    return parser


def _resolve_legacy_args(argv: list[str] | None) -> list[str] | None:
    if not argv:
        return argv
    if argv[0] in {"scan", "lint", "verify", "submit", "doctor", "--version", "-h", "--help"}:
        return argv
    return ["scan", *argv]


def _print_lint_rules() -> None:
    for spec in list_rule_specs():
        print(f"{spec.rule_id}\t{spec.category}\t{spec.default_severity.value}\tfixable={spec.fixable}")


def _print_lint_explain(rule_id: str) -> int:
    spec = get_rule_spec(rule_id)
    if spec is None:
        print(f"Unknown rule id: {rule_id}", file=sys.stderr)
        return 1
    print(json.dumps({
        "rule_id": spec.rule_id,
        "category": spec.category,
        "default_severity": spec.default_severity.value,
        "weight": spec.weight,
        "docs_slug": spec.docs_slug,
        "fixable": spec.fixable,
        "profiles": list(spec.profiles),
    }, indent=2))
    return 0


def _apply_rule_filters(result, *, enabled: frozenset[str], disabled: frozenset[str], baseline_ids: frozenset[str]):
    findings = tuple(
        finding
        for finding in result.findings
        if finding.rule_id not in baseline_ids
        and finding.rule_id not in disabled
        and (not enabled or finding.rule_id in enabled)
    )
    return replace(result, findings=findings, severity_counts=build_severity_counts(findings))


def _resolve_policy_profile(args: argparse.Namespace, plugin_dir: Path) -> tuple[str, frozenset[str], frozenset[str], frozenset[str]]:
    config = load_scanner_config(plugin_dir, getattr(args, "config", None))
    profile = resolve_profile(getattr(args, "profile", None) or config.profile)
    baseline_path = getattr(args, "baseline", None) or config.baseline_file
    baseline_ids = load_baseline_rule_ids(plugin_dir, baseline_path)
    return profile, config.enabled_rules, config.disabled_rules, baseline_ids


def _scan_with_policy(args: argparse.Namespace, plugin_dir: Path):
    profile, enabled_rules, disabled_rules, baseline_ids = _resolve_policy_profile(args, plugin_dir)
    result = scan_plugin(
        plugin_dir,
        ScanOptions(cisco_skill_scan=getattr(args, "cisco_skill_scan", "auto"), cisco_policy=getattr(args, "cisco_policy", "balanced")),
    )
    result = _apply_rule_filters(result, enabled=enabled_rules, disabled=disabled_rules, baseline_ids=baseline_ids)
    policy_eval = evaluate_policy(result.findings, profile)
    return result, profile, policy_eval


def _run_scan(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1

    result, profile, policy_eval = _scan_with_policy(args, resolved)

    output_format = "json" if args.json else args.format
    if args.output and not args.json and args.format == "text":
        output_format = "json"

    if output_format == "json":
        output = format_json(result, profile=profile, policy_pass=policy_eval.policy_pass, verify_pass=True)
    elif output_format == "markdown":
        output = format_markdown(result)
    elif output_format == "sarif":
        output = format_sarif(result)
    else:
        plain = _build_plain_text(result)
        try:
            from rich.console import Console

            Console().print(_build_rich_text(result))
        except ImportError:
            print(plain)
        output = plain

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output, encoding="utf-8")
        print(f"Report written to {out_path}")
    elif output_format != "text":
        print(output)

    if result.score < args.min_score:
        print(f"Score {result.score} is below minimum threshold {args.min_score}", file=sys.stderr)
        return 1
    if should_fail_for_severity(result, args.fail_on_severity):
        print(f'Findings met or exceeded the "{args.fail_on_severity}" severity threshold.', file=sys.stderr)
        return 1
    if args.strict and result.findings:
        print("Strict mode failed because findings were present.", file=sys.stderr)
        return 1
    if not policy_eval.policy_pass:
        print(f'Policy profile "{profile}" failed.', file=sys.stderr)
        return 1
    return 0


def _run_lint(args: argparse.Namespace) -> int:
    if args.list_rules:
        _print_lint_rules()
        return 0
    if args.explain:
        return _print_lint_explain(args.explain)

    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1

    if args.fix:
        changes = apply_safe_autofixes(resolved)
        if changes:
            print("Applied fixes:")
            for change in changes:
                print(f"- {change}")
        else:
            print("No autofix changes were necessary.")

    result, profile, policy_eval = _scan_with_policy(args, resolved)

    if args.format == "json":
        print(json.dumps({
            "profile": profile,
            "policy_pass": policy_eval.policy_pass,
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "title": finding.title,
                    "description": finding.description,
                    "fixable": bool(get_rule_spec(finding.rule_id).fixable) if get_rule_spec(finding.rule_id) else False,
                }
                for finding in result.findings
            ],
        }, indent=2))
    else:
        print(f"Lint profile: {profile}")
        print(f"Policy pass: {'yes' if policy_eval.policy_pass else 'no'}")
        if not result.findings:
            print("No lint findings.")
        else:
            for finding in result.findings:
                spec = get_rule_spec(finding.rule_id)
                fixable = " (fixable)" if spec and spec.fixable else ""
                print(f"- {finding.rule_id} [{finding.severity.value}] {finding.title}{fixable}")

    if args.strict and result.findings:
        return 1
    return 0 if policy_eval.policy_pass else 1


def _run_verify(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    verification = verify_plugin(resolved, online=args.online)
    if args.format == "json":
        print(json.dumps({
            "verify_pass": verification.verify_pass,
            "cases": [asdict(case) for case in verification.cases],
        }, indent=2))
    else:
        print(f"Verify pass: {'yes' if verification.verify_pass else 'no'}")
        for case in verification.cases:
            icon = "✅" if case.passed else "❌"
            print(f"{icon} [{case.component}] {case.name}: {case.message}")
    return 0 if verification.verify_pass else 1


def _run_submit(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1

    result, profile, policy_eval = _scan_with_policy(args, resolved)
    verification = verify_plugin(resolved, online=args.online)

    if result.score < 60 or not policy_eval.policy_pass or not verification.verify_pass:
        print("Submission blocked: scan/policy/verify gates did not all pass.", file=sys.stderr)
        return 1

    artifact = build_quality_artifact(resolved, result, verification, policy_eval, profile)
    target = Path(args.attest)
    write_quality_artifact(target, artifact)
    print(f"Submission artifact written to {target}")
    return 0


def _run_doctor(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1

    report = build_doctor_report(resolved, args.component)
    rendered = json.dumps(report, indent=2)
    if args.bundle:
        bundle_path = Path(args.bundle)
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_text(rendered, encoding="utf-8")
        print(f"Doctor report written to {bundle_path}")
    else:
        print(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    effective_argv = _resolve_legacy_args(argv)
    parser = _build_parser()
    args = parser.parse_args(effective_argv)

    if args.command in {None, "scan"}:
        return _run_scan(args)
    if args.command == "lint":
        return _run_lint(args)
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "submit":
        return _run_submit(args)
    if args.command == "doctor":
        return _run_doctor(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
