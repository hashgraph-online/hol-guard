"""Scanner command runners for the combined CLI."""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path

from .cli_ui import build_plain_text, build_verification_text, emit_hint, emit_scan_provenance
from .config import DEFAULT_CONFIG_FILES, ConfigError, load_baseline_rule_ids, load_scanner_config
from .lint_fixes import apply_safe_autofixes
from .models import ScanOptions, get_grade
from .policy import POLICY_PROFILES, build_rule_inventory, evaluate_policy, resolve_profile
from .quality_artifact import build_quality_artifact, write_quality_artifact
from .reporting import format_json as render_json
from .reporting import format_markdown, format_sarif, should_fail_for_severity
from .rules import get_rule_spec, list_rule_specs
from .scanner import scan_plugin
from .suppressions import apply_severity_overrides, apply_suppressions, compute_effective_score
from .verification import build_doctor_report, build_verification_payload, verify_plugin

RuleSpecLookup = Callable[[str], object | None]


def _format_scan_json(
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


def _print_lint_rules() -> None:
    for spec in list_rule_specs():
        print(f"{spec.rule_id}\t{spec.category}\t{spec.default_severity.value}\tfixable={spec.fixable}")


def _print_lint_explain(rule_id: str, *, get_rule_spec_fn: RuleSpecLookup = get_rule_spec) -> int:
    spec = get_rule_spec_fn(rule_id)
    if spec is None:
        print(f"Unknown rule id: {rule_id}", file=sys.stderr)
        emit_hint("run `lint --list-rules` to inspect the available rule identifiers.")
        return 1
    print(json.dumps(asdict(spec), indent=2, default=str))
    return 0


def _resolve_scanner_config_path(plugin_dir: Path, config_path: str | None) -> Path | None:
    if config_path:
        candidate = Path(config_path)
        return candidate if candidate.is_absolute() else (plugin_dir / candidate)
    for name in DEFAULT_CONFIG_FILES:
        candidate = plugin_dir / name
        if candidate.exists():
            return candidate
    return None


def _resolve_baseline_path(plugin_dir: Path, baseline_path: str | None) -> Path | None:
    if not baseline_path:
        return None
    candidate = Path(baseline_path)
    return candidate if candidate.is_absolute() else (plugin_dir / candidate)


def _resolve_policy_profile(args: argparse.Namespace, plugin_dir: Path):
    config_path = _resolve_scanner_config_path(plugin_dir, getattr(args, "config", None))
    try:
        config = load_scanner_config(plugin_dir, getattr(args, "config", None))
        baseline_path = getattr(args, "baseline", None) or config.baseline_file
        baseline_ids = load_baseline_rule_ids(plugin_dir, baseline_path)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise

    profile = resolve_profile(getattr(args, "profile", None) or config.profile)
    return profile, config, baseline_ids, config_path, _resolve_baseline_path(plugin_dir, baseline_path)


def _scan_with_policy(args: argparse.Namespace, plugin_dir: Path):
    profile, config, baseline_ids, config_path, baseline_path = _resolve_policy_profile(args, plugin_dir)
    raw_result = scan_plugin(
        plugin_dir,
        ScanOptions(
            cisco_skill_scan=getattr(args, "cisco_skill_scan", "auto"),
            cisco_mcp_scan=getattr(args, "cisco_mcp_scan", "auto"),
            cisco_policy=getattr(args, "cisco_policy", "balanced"),
            ecosystem=getattr(args, "ecosystem", "auto"),
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
    return raw_result, result, profile, policy_eval, effective_score, config_path, baseline_path


def run_scan(args: argparse.Namespace) -> int:
    plugin_dir = getattr(args, "plugin_dir", ".")
    resolved = Path(plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    try:
        raw_result, result, profile, policy_eval, effective_score, config_path, baseline_path = _scan_with_policy(
            args,
            resolved,
        )
    except ConfigError:
        return 1

    output_format = "json" if args.json else args.format
    if output_format == "text":
        emit_scan_provenance(profile=profile, config_path=config_path, baseline_path=baseline_path)
    if output_format == "json":
        output = _format_scan_json(
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
        output = build_plain_text(result)
        print(output)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    elif output_format != "text":
        print(output)

    min_score = args.min_score
    if result.score < min_score:
        print(f"Score {result.score} is below threshold {min_score}", file=sys.stderr)
        if output_format == "text":
            emit_hint(
                "review the highest-severity findings above, then rerun with --format json if you need automation."
            )
        return 1
    if should_fail_for_severity(result, args.fail_on_severity):
        print(
            f'Findings met or exceeded the "{args.fail_on_severity}" severity threshold.',
            file=sys.stderr,
        )
        emit_hint("adjust --fail-on-severity only if your policy allows reporting without a blocking gate.")
        return 1
    if args.strict and result.findings:
        print("Strict mode failed because findings were present.", file=sys.stderr)
        emit_hint("rerun without --strict to inspect findings without turning the report into a failing gate.")
        return 1
    if not policy_eval.policy_pass:
        print(f'Policy profile "{profile}" failed.', file=sys.stderr)
        emit_hint("use a different --profile only when that matches your documented review policy.")
        return 1
    return 0


def run_lint(args: argparse.Namespace, *, get_rule_spec_fn: RuleSpecLookup = get_rule_spec) -> int:
    if args.list_rules:
        _print_lint_rules()
        return 0
    if args.explain:
        return _print_lint_explain(args.explain, get_rule_spec_fn=get_rule_spec_fn)

    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    if args.fix:
        for change in apply_safe_autofixes(resolved):
            print(f"- {change}")

    try:
        _raw, result, profile, policy_eval, effective_score, _config_path, _baseline_path = _scan_with_policy(
            args,
            resolved,
        )
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
                "fixable": bool((spec := get_rule_spec_fn(finding.rule_id)) and spec.fixable),
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


def run_verify(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    verification = verify_plugin(resolved, online=args.online)
    payload = build_verification_payload(verification)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(build_verification_text(payload))
    return 0 if verification.verify_pass else 1


def run_submit(args: argparse.Namespace) -> int:
    resolved = Path(args.plugin_dir).resolve()
    if not resolved.is_dir():
        print(f'Error: "{resolved}" is not a directory.', file=sys.stderr)
        return 1
    try:
        raw_result, result, profile, policy_eval, _effective_score, _config_path, _baseline_path = _scan_with_policy(
            args,
            resolved,
        )
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


def run_doctor(args: argparse.Namespace) -> int:
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
