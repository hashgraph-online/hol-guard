"""GitHub Action entry point for scan and submission workflows."""

from __future__ import annotations

# Keep dependency imports and facade bindings in their original evaluation order.
# ruff: noqa: I001

import argparse as argparse
import json as json
import os as os
import re as re
import secrets as secrets
import sys as sys
from pathlib import Path as Path
from urllib.error import HTTPError as HTTPError, URLError as URLError

from . import __version__ as __version__
from ._scanner_commands import _scan_with_policy as _scan_with_policy
from .action_environment import drop_external_analyzer_credentials as drop_external_analyzer_credentials
from .cli_ui import build_plain_text as build_plain_text, build_verification_text as build_verification_text
from .config import ConfigError as ConfigError, load_scanner_config as load_scanner_config
from .github_reporting import (
    build_scan_pr_comment_body as build_scan_pr_comment_body,
    build_verify_pr_comment_body as build_verify_pr_comment_body,
    load_pull_request_number as load_pull_request_number,
    resolve_pr_comment_config as resolve_pr_comment_config,
    should_manage_pr_comment as should_manage_pr_comment,
    upsert_pr_comment as upsert_pr_comment,
)
from .models import (
    GRADE_LABELS as GRADE_LABELS,
    SEVERITY_ORDER as SEVERITY_ORDER,
    Finding as Finding,
    max_severity as max_severity,
)
from .quality_artifact import (
    build_quality_artifact as build_quality_artifact,
    write_quality_artifact as write_quality_artifact,
)
from .reporting import (
    build_json_payload as build_json_payload,
    format_markdown as format_markdown,
    format_sarif as format_sarif,
    should_fail_for_severity as should_fail_for_severity,
)
from .safe_output import write_text_atomic_no_follow as write_text_atomic_no_follow
from .submission import (
    SubmissionIssue as SubmissionIssue,
    build_submission_issue_body as build_submission_issue_body,
    build_submission_issue_title as build_submission_issue_title,
    build_submission_payload as build_submission_payload,
    create_submission_issue as create_submission_issue,
    find_existing_submission_issue as find_existing_submission_issue,
    normalize_github_api_base_url as normalize_github_api_base_url,
    resolve_submission_metadata as resolve_submission_metadata,
)
from .verification import build_verification_payload as build_verification_payload, verify_plugin as verify_plugin


def _parse_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _read_bool_env(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() == "true"


def _read_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _read_positive_int_env(name: str, *, default: int) -> int:
    raw = _read_env(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _write_outputs(path: str, values: dict[str, str]) -> None:
    with Path(path).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
                raise ValueError(f"invalid GitHub output name: {key}")
            if "\n" not in value and "\r" not in value:
                handle.write(f"{key}={value}\n")
                continue
            delimiter = f"HOL_GUARD_{secrets.token_hex(16)}"
            while delimiter in value:
                delimiter = f"HOL_GUARD_{secrets.token_hex(16)}"
            handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")


def _write_step_summary(path: str, lines: tuple[str, ...]) -> None:
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def _resolve_pr_comment_settings(
    *,
    plugin_dir: str,
    config_path: str,
    trust_repository_policy: bool,
) -> tuple[str, str, int]:
    config = None
    try:
        config = (
            load_scanner_config(Path(plugin_dir).resolve(), config_path or None) if trust_repository_policy else None
        )
    except ConfigError as error:
        print(f"Warning: failed to load scanner config for PR comment settings: {error}", file=sys.stderr)
    pr_comment = resolve_pr_comment_config(
        default_mode=_read_env("PR_COMMENT", "auto"),
        default_style=_read_env("PR_COMMENT_STYLE", "concise"),
        default_max_findings=_read_positive_int_env(
            "PR_COMMENT_MAX_FINDINGS",
            default=5,
        ),
        configured_mode=config.github_pr_comment if config is not None else None,
        configured_style=config.github_pr_comment_style if config is not None else None,
        configured_max_findings=config.github_pr_comment_max_findings if config is not None else None,
    )
    return pr_comment.mode, pr_comment.style, pr_comment.max_findings


def _build_scan_args(
    *,
    plugin_dir: str,
    profile: str,
    config: str,
    baseline: str,
    min_score: int,
    fail_on_severity: str,
    cisco_scan: str,
    cisco_mcp_scan: str,
    cisco_policy: str,
    trust_repository_policy: bool = True,
) -> argparse.Namespace:
    return argparse.Namespace(
        plugin_dir=plugin_dir,
        profile=profile or None,
        config=config or None,
        baseline=baseline or None,
        strict=False,
        diff_base=None,
        min_score=min_score,
        fail_on_severity=fail_on_severity,
        cisco_skill_scan=cisco_scan,
        cisco_mcp_scan=cisco_mcp_scan,
        cisco_policy=cisco_policy,
        trust_repository_policy=trust_repository_policy,
    )


def _render_scan_output(result, *, output_format: str, profile: str, policy_pass: bool, raw_score: int) -> str:
    if output_format == "json":
        return json.dumps(
            build_json_payload(
                result,
                profile=profile,
                policy_pass=policy_pass,
                verify_pass=True,
                raw_score=raw_score,
                effective_score=result.score,
            ),
            indent=2,
        )
    if output_format == "markdown":
        return format_markdown(result)
    if output_format == "sarif":
        return format_sarif(result)
    return build_plain_text(result)


def _render_verify_output(verification, *, output_format: str) -> str:
    payload = build_verification_payload(verification)
    if output_format == "json":
        return json.dumps(payload, indent=2)
    return build_verification_text(payload)


def _render_lint_output(result, *, output_format: str, profile: str, policy_pass: bool) -> str:
    if output_format == "json":
        payload = {
            "profile": profile,
            "policy_pass": policy_pass,
            "effective_score": result.score,
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "title": finding.title,
                    "description": finding.description,
                }
                for finding in result.findings
            ],
        }
        return json.dumps(payload, indent=2)
    lines = [f"Lint profile: {profile} | policy_pass={policy_pass} | effective_score={result.score}"]
    for finding in result.findings:
        lines.append(f"- {finding.rule_id} [{finding.severity.value}] {finding.title}")
    return "\n".join(lines)


def _escape_step_summary_text(value: str) -> str:
    """Normalize scanner-controlled text before embedding it in GitHub-flavored Markdown."""

    text = " ".join(value.split())
    for character in ("\\", "`", "*", "_", "[", "]", "<", ">"):
        text = text.replace(character, f"\\{character}")
    return text


def _build_findings_summary_lines(findings: tuple[Finding, ...]) -> tuple[str, ...]:
    """Render complete, deterministic finding details for the Actions job summary."""

    ordered_findings = sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER[finding.severity],
            finding.rule_id,
            finding.file_path or "",
            finding.line_number or 0,
        ),
    )
    lines = ["", "### Finding details", ""]
    if not ordered_findings:
        lines.append("No findings detected.")
        return tuple(lines)

    for index, finding in enumerate(ordered_findings, start=1):
        title = _escape_step_summary_text(finding.title)
        rule_id = _escape_step_summary_text(finding.rule_id)
        category = _escape_step_summary_text(finding.category)
        source = _escape_step_summary_text(finding.source)
        description = _escape_step_summary_text(finding.description)
        remediation = "Not provided."
        if finding.remediation:
            remediation = _escape_step_summary_text(finding.remediation)
        location = "Not provided."
        if finding.file_path:
            raw_location = finding.file_path
            if finding.line_number is not None:
                raw_location = f"{raw_location}:{finding.line_number}"
            location = _escape_step_summary_text(raw_location)

        lines.extend(
            [
                f"#### {index}. {finding.severity.value.upper()} - {title}",
                "",
                f"- Rule ID: {rule_id}",
                f"- Category: {category}",
                f"- Source: {source}",
                f"- Location: {location}",
                f"- Description: {description}",
                f"- Remediation: {remediation}",
                "",
            ]
        )
    return tuple(lines)


def _build_step_summary_lines(
    *,
    mode: str,
    score: str,
    grade: str,
    grade_label: str,
    max_severity: str,
    findings_total: str,
    report_path: str,
    registry_payload_path: str,
    submission_issues: list[SubmissionIssue],
    submission_eligible: bool,
    verify_pass: bool | None = None,
    scope: str = "plugin",
    local_plugin_count: int | None = None,
    skipped_target_count: int | None = None,
    findings: tuple[Finding, ...] = (),
) -> tuple[str, ...]:
    lines = ["## HOL AI Plugin Scanner", "", f"- Mode: {mode}"]
    lines.append(f"- Scope: {scope}")
    if local_plugin_count is not None:
        lines.append(f"- Local plugins scanned: {local_plugin_count}")
    if skipped_target_count is not None:
        lines.append(f"- Skipped marketplace entries: {skipped_target_count}")
    if score:
        lines.append(f"- Score: {score}/100")
    if grade:
        lines.append(f"- Grade: {grade} - {grade_label}")
    if max_severity:
        lines.append(f"- Max severity: {max_severity}")
    if findings_total:
        lines.append(f"- Findings: {findings_total}")
    if verify_pass is not None:
        lines.append(f"- Verification pass: {'yes' if verify_pass else 'no'}")
    lines.append(f"- Submission eligible: {'yes' if submission_eligible else 'no'}")
    if report_path:
        lines.append(f"- Report: `{report_path}`")
    if registry_payload_path:
        lines.append(f"- Registry payload: `{registry_payload_path}`")
    if submission_issues:
        lines.append(f"- Submission issues: {', '.join(issue.url for issue in submission_issues)}")
    if mode in {"scan", "lint", "submit"}:
        lines.extend(_build_findings_summary_lines(findings))
    return tuple(lines)


def main() -> int:
    """Run with this module namespace, including the Actions ``-m`` entry point."""
    from .action_runner_workflow import run

    return run(sys.modules[__name__])


if __name__ == "__main__":
    raise SystemExit(main())
