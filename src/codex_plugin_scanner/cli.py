"""Codex Plugin Scanner - CLI entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from dataclasses import asdict, replace
from pathlib import Path

from .config import ConfigError, load_baseline_rule_ids, load_scanner_config
from .lint_fixes import apply_safe_autofixes
from .models import GRADE_LABELS, ScanOptions, Severity, get_grade
from .policy import POLICY_PROFILES, build_rule_inventory, evaluate_policy, resolve_profile
from .quality_artifact import build_quality_artifact, write_quality_artifact
from .reporting import format_json as render_json
from .reporting import format_markdown, format_sarif, should_fail_for_severity
from .rules import get_rule_spec, list_rule_specs
from .scanner import scan_plugin
from .suppressions import apply_severity_overrides, apply_suppressions, compute_effective_score
from .verification import build_doctor_report, build_verification_payload, verify_plugin
from .version import __version__


def _build_plain_text(result) -> str:
    if getattr(result, "scope", "plugin") == "repository":
        trust_total = result.trust_report.total if getattr(result, "trust_report", None) else 0.0
        lines = [
            f"🔗 Codex Plugin Scanner v{__version__}",
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
            f"🔗 Codex Plugin Scanner v{__version__}",
            f"Scanning: {result.plugin_dir}",
            f"Trust: {trust_total}/100",
            "",
        ]
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
    if getattr(result, "trust_report", None) and result.trust_report.domains:
        lines.append("Trust Provenance:")
        for domain in result.trust_report.domains:
            lines.append(f"  - {domain.label}: {domain.score}/100 ({domain.spec_id})")
        lines.append("")
    separator = "━" * 37
    label = GRADE_LABELS.get(result.grade, "Unknown")
    lines += [separator, f"Final Score: {result.score}/100 ({result.grade} - {label})", separator]
    return "\n".join(lines)


def format_text(result) -> str:
    return _build_plain_text(result)


def _build_verification_text(payload: dict[str, object]) -> str:
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


def format_json(
    result,
    *,
    profile: str = "default",
    policy_pass: bool = True,
    verify_pass: bool = True,
    raw_score: int | None = None,
    effective_score: int | None = None,
) -> str:
    return render_json(
        result,
        profile=profile,
        policy_pass=policy_pass,
        verify_pass=verify_pass,
        raw_score=raw_score,
        effective_score=effective_score,
    )


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
    scan_parser.add_argument("plugin_dir")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    scan_parser.add_argument("--output", "-o")
    _add_common_policy_args(scan_parser)
    scan_parser.add_argument("--min-score", type=int, default=0)
    scan_parser.add_argument(
        "--fail-on-severity",
        choices=("none", "critical", "high", "medium", "low", "info"),
        default="none",
    )
    scan_parser.add_argument("--cisco-skill-scan", choices=("auto", "on", "off"), default="auto")
    scan_parser.add_argument("--cisco-policy", choices=("permissive", "balanced", "strict"), default="balanced")

    lint_parser = subparsers.add_parser("lint", help="Run rule-level lint evaluation")
    lint_parser.add_argument("plugin_dir", nargs="?", default=".")
    _add_common_policy_args(lint_parser)
    lint_parser.add_argument("--format", choices=("text", "json"), default="text")
    lint_parser.add_argument("--list-rules", action="store_true")
    lint_parser.add_argument("--explain")
    lint_parser.add_argument("--fix", action="store_true")

    verify_parser = subparsers.add_parser("verify", help="Run runtime verification checks")
    verify_parser.add_argument("plugin_dir", nargs="?", default=".")
    verify_parser.add_argument("--online", action="store_true")
    verify_parser.add_argument("--format", choices=("text", "json"), default="text")

    submit_parser = subparsers.add_parser("submit", help="Emit artifact after scan+verify+policy pass")
    submit_parser.add_argument("plugin_dir", nargs="?", default=".")
    submit_parser.add_argument("--profile", choices=("default", "public-marketplace", "strict-security"))
    submit_parser.add_argument("--config")
    submit_parser.add_argument("--baseline")
    submit_parser.add_argument("--attest", required=True)
    submit_parser.add_argument("--online", action="store_true")
    submit_parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        help="Override the minimum score gate. Defaults to the selected policy profile minimum.",
    )

    doctor_parser = subparsers.add_parser("doctor", help="Emit component diagnostics")
    doctor_parser.add_argument("plugin_dir", nargs="?", default=".")
    doctor_parser.add_argument(
        "--component",
        choices=("all", "manifest", "marketplace", "mcp", "skills", "apps", "assets"),
        default="all",
    )
    doctor_parser.add_argument("--bundle")

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
    print(json.dumps(asdict(spec), indent=2, default=str))
    return 0


def _resolve_policy_profile(args: argparse.Namespace, plugin_dir: Path):
    try:
        config = load_scanner_config(plugin_dir, getattr(args, "config", None))
        baseline_path = getattr(args, "baseline", None) or config.baseline_file
        baseline_ids = load_baseline_rule_ids(plugin_dir, baseline_path)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise

    profile = resolve_profile(getattr(args, "profile", None) or config.profile)
    return profile, config, baseline_ids


def _scan_with_policy(args: argparse.Namespace, plugin_dir: Path):
    profile, config, baseline_ids = _resolve_policy_profile(args, plugin_dir)
    raw_result = scan_plugin(
        plugin_dir,
        ScanOptions(
            cisco_skill_scan=getattr(args, "cisco_skill_scan", "auto"),
            cisco_policy=getattr(args, "cisco_policy", "balanced"),
        ),
    )
    result = apply_suppressions(
        raw_result,
        enabled_rules=config.enabled_rules,
        disabled_rules=config.disabled_rules,
        baseline_ids=baseline_ids,
        ignore_paths=config.ignore_paths,
    )
    result = apply_severity_overrides(result, config.severity_overrides)
    executed_rules = {
        spec.rule_id for spec in list_rule_specs() if not config.enabled_rules or spec.rule_id in config.enabled_rules
    }
    executed_rules -= set(config.disabled_rules)
    inventory = build_rule_inventory(result.findings, executed_rules)
    policy_eval = evaluate_policy(result.findings, profile, rule_inventory=inventory)
    effective_score = compute_effective_score(result)
    result = replace(result, score=effective_score, grade=get_grade(effective_score))
    return raw_result, result, profile, policy_eval, effective_score


def _run_scan(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    try:
        raw_result, result, profile, policy_eval, effective_score = _scan_with_policy(args, resolved)
    except ConfigError:
        return 1

    output_format = "json" if args.json else args.format
    if args.output and not args.json and args.format == "text":
        output_format = "json"
    if output_format == "json":
        output = format_json(
            result,
            profile=profile,
            policy_pass=policy_eval.policy_pass,
            verify_pass=True,
            raw_score=raw_result.score,
            effective_score=effective_score,
        )
    elif output_format == "markdown":
        output = format_markdown(result)
    elif output_format == "sarif":
        output = format_sarif(result)
    else:
        output = _build_plain_text(result)
        print(output)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    elif output_format != "text":
        print(output)

    min_score = args.min_score
    if result.score < min_score:
        print(f"Score {result.score} is below threshold {min_score}", file=sys.stderr)
        return 1
    if should_fail_for_severity(result, args.fail_on_severity):
        print(
            f'Findings met or exceeded the "{args.fail_on_severity}" severity threshold.',
            file=sys.stderr,
        )
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
        for change in apply_safe_autofixes(resolved):
            print(f"- {change}")

    try:
        _raw, result, profile, policy_eval, effective_score = _scan_with_policy(args, resolved)
    except ConfigError:
        return 1

    payload = {
        "profile": profile,
        "policy_pass": policy_eval.policy_pass,
        "effective_score": effective_score,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "category": finding.category,
                "title": finding.title,
                "description": finding.description,
                "fixable": bool((spec := get_rule_spec(finding.rule_id)) and spec.fixable),
            }
            for finding in result.findings
        ],
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"Lint profile: {profile} | policy_pass={policy_eval.policy_pass} | effective_score={effective_score}")
        for finding in result.findings:
            print(f"- {finding.rule_id} [{finding.severity.value}] {finding.title}")

    if args.strict and result.findings:
        return 1
    return 0 if policy_eval.policy_pass else 1


def _run_verify(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    verification = verify_plugin(resolved, online=args.online)
    payload = build_verification_payload(verification)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(_build_verification_text(payload))
    return 0 if verification.verify_pass else 1


def _run_submit(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    try:
        raw_result, result, profile, policy_eval, _effective_score = _scan_with_policy(args, resolved)
    except ConfigError:
        return 1
    if getattr(result, "scope", "plugin") != "plugin":
        print(
            "Submission requires a single plugin directory. Target one plugin path instead of a repo marketplace root.",
            file=sys.stderr,
        )
        return 1
    verification = verify_plugin(resolved, online=args.online)
    min_score = args.min_score if args.min_score is not None else POLICY_PROFILES[profile].min_score
    if result.score < min_score or not policy_eval.policy_pass or not verification.verify_pass:
        print("Submission blocked: scan/policy/verify gates did not all pass.", file=sys.stderr)
        return 1
    artifact = build_quality_artifact(
        resolved,
        result,
        verification,
        policy_eval,
        profile,
        raw_score=raw_result.score,
    )
    write_quality_artifact(Path(args.attest), artifact)
    print(f"Submission artifact written to {args.attest}")
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
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("doctor-report.json", rendered)
            zf.writestr("environment.txt", f"cwd={resolved}\npython={sys.version}\nos={os.name}\n")
            zf.writestr(
                "workspace-manifest.txt",
                f"workspace={report.get('workspace', '')}\ncomponent={args.component}\n",
            )
            zf.writestr(
                "command-metadata.json",
                json.dumps({"command": "doctor", "component": args.component}, indent=2),
            )
            zf.writestr("stdout.log", str(report.get("stdout_log", "")))
            zf.writestr("stderr.log", str(report.get("stderr_log", "")))
            zf.writestr("timeout-markers.txt", str(report.get("timeout_markers", "none\n")))
        print(f"Doctor bundle written to {bundle_path}")
    else:
        print(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(_resolve_legacy_args(argv))
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
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
