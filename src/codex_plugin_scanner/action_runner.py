"""GitHub Action entry point for scan and submission workflows."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .cli import _build_plain_text, _build_verification_text, _scan_with_policy
from .models import GRADE_LABELS, SEVERITY_ORDER, max_severity
from .pr_comments import (
    PRCommentCategory,
    PRCommentConfig,
    PRCommentFinding,
    PRCommentIntegration,
    PRCommentSnapshot,
    publish_pr_comment,
)
from .quality_artifact import build_quality_artifact, write_quality_artifact
from .reporting import build_json_payload, format_markdown, format_sarif, should_fail_for_severity
from .submission import (
    SubmissionIssue,
    build_submission_issue_body,
    build_submission_issue_title,
    build_submission_payload,
    create_submission_issue,
    find_existing_submission_issue,
    resolve_submission_metadata,
)
from .verification import build_verification_payload, verify_plugin


def _parse_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _read_bool_env(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() == "true"


def _read_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _read_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _write_outputs(path: str, values: dict[str, str]) -> None:
    with Path(path).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _write_step_summary(path: str, lines: tuple[str, ...]) -> None:
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def _build_scan_args(
    *,
    plugin_dir: str,
    profile: str,
    config: str,
    baseline: str,
    min_score: int,
    fail_on_severity: str,
    cisco_scan: str,
    cisco_policy: str,
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
        cisco_policy=cisco_policy,
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
    return _build_plain_text(result)


def _render_verify_output(verification, *, output_format: str) -> str:
    payload = build_verification_payload(verification)
    if output_format == "json":
        return json.dumps(payload, indent=2)
    return _build_verification_text(payload)


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
    pr_comment_status: str = "",
    pr_comment_url: str = "",
    pr_comment_reason: str = "",
) -> tuple[str, ...]:
    lines = ["## HOL Codex Plugin Scanner", "", f"- Mode: {mode}"]
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
    if pr_comment_status:
        status_line = f"- PR comment: {pr_comment_status}"
        if pr_comment_url:
            status_line += f" ({pr_comment_url})"
        lines.append(status_line)
        if pr_comment_reason:
            lines.append(f"- PR comment reason: {pr_comment_reason}")
    return tuple(lines)


def _normalize_pr_comment_mode(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"off", "auto", "always"}:
        return normalized
    return "off"


def _normalize_pr_comment_style(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"concise", "full"}:
        return normalized
    return "concise"


def _sorted_findings(result) -> list:
    return sorted(
        result.findings,
        key=lambda finding: (
            -SEVERITY_ORDER[finding.severity],
            finding.category,
            finding.title,
            finding.file_path or "",
            finding.line_number or 0,
        ),
    )


def _build_pr_comment_snapshot_for_scan(
    *,
    mode: str,
    profile: str,
    plugin_dir: str,
    result,
    policy_pass: bool,
    verify_pass: bool | None,
    gate_pass: bool,
    gate_reasons: tuple[str, ...],
    min_score: int,
    fail_on_severity: str,
    score_gate_pass: bool,
    severity_gate_pass: bool,
    submission_eligible: bool,
    submission_issues: list[SubmissionIssue],
    workflow_url: str,
    full_report_markdown: str,
) -> PRCommentSnapshot:
    deduped: list[PRCommentFinding] = []
    seen: set[tuple[str, str, str, str, int | None]] = set()
    for finding in _sorted_findings(result):
        key = (
            finding.rule_id,
            finding.severity.value,
            finding.title,
            finding.file_path or "",
            finding.line_number,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(
            PRCommentFinding(
                severity=finding.severity.value,
                title=finding.title,
                file_path=finding.file_path or "",
                line_number=finding.line_number,
                remediation=finding.remediation or "",
            )
        )
    top_findings = tuple(deduped[:10])
    categories = tuple(
        PRCommentCategory(
            name=category.name,
            score=sum(check.points for check in category.checks),
            max_score=sum(check.max_points for check in category.checks),
        )
        for category in result.categories
    )
    integrations = tuple(
        PRCommentIntegration(
            name=integration.name,
            status=integration.status,
            message=integration.message,
        )
        for integration in result.integrations
    )
    return PRCommentSnapshot(
        mode=mode,
        profile=profile,
        plugin_dir=plugin_dir,
        scope=getattr(result, "scope", "plugin"),
        score=result.score,
        grade=result.grade,
        grade_label=GRADE_LABELS.get(result.grade, "Unknown"),
        max_severity=max_severity(result.findings).value if result.findings else "none",
        findings_total=sum(result.severity_counts.values()),
        severity_counts={key: int(value) for key, value in result.severity_counts.items()},
        min_score=min_score,
        fail_on_severity=fail_on_severity,
        score_gate_pass=score_gate_pass,
        severity_gate_pass=severity_gate_pass,
        policy_pass=policy_pass,
        verify_pass=verify_pass,
        gate_pass=gate_pass,
        gate_reasons=gate_reasons,
        top_findings=top_findings,
        categories=categories,
        integrations=integrations,
        submission_eligible=submission_eligible,
        submission_issues=tuple(issue.url for issue in submission_issues),
        workflow_url=workflow_url,
        full_report_markdown=full_report_markdown,
    )


def _case_severity_label(classification: str) -> str:
    if classification in {"protocol", "spawn-failure", "timeout", "transport", "tls"}:
        return "high"
    if classification in {"schema", "asset-missing", "invalid-json", "missing-manifest"}:
        return "medium"
    return "info"


def _build_pr_comment_snapshot_for_verify(
    *,
    mode: str,
    profile: str,
    plugin_dir: str,
    verification,
    gate_pass: bool,
    gate_reasons: tuple[str, ...],
    fail_on_severity: str,
    workflow_url: str,
    full_report_markdown: str,
) -> PRCommentSnapshot:
    failed_cases = [case for case in verification.cases if not case.passed]
    severity_counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    top_findings: list[PRCommentFinding] = []
    for case in failed_cases:
        severity = _case_severity_label(case.classification)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        top_findings.append(
            PRCommentFinding(
                severity=severity,
                title=f"{case.component}: {case.name}",
                remediation=case.message,
            )
        )
    max_severity_value = "none"
    for severity in ("critical", "high", "medium", "low", "info"):
        if severity_counts.get(severity, 0) > 0:
            max_severity_value = severity
            break
    return PRCommentSnapshot(
        mode=mode,
        profile=profile,
        plugin_dir=plugin_dir,
        scope=getattr(verification, "scope", "plugin"),
        score=None,
        grade="",
        grade_label="",
        max_severity=max_severity_value,
        findings_total=len(failed_cases),
        severity_counts=severity_counts,
        min_score=None,
        fail_on_severity=fail_on_severity,
        score_gate_pass=None,
        severity_gate_pass=None,
        policy_pass=None,
        verify_pass=verification.verify_pass,
        gate_pass=gate_pass,
        gate_reasons=gate_reasons,
        top_findings=tuple(top_findings),
        categories=(),
        integrations=(),
        submission_eligible=None,
        submission_issues=(),
        workflow_url=workflow_url,
        full_report_markdown=full_report_markdown,
    )


def main() -> int:
    mode = _read_env("MODE", "scan")
    plugin_dir = _read_env("PLUGIN_DIR", ".")
    output_format = _read_env("FORMAT", "text")
    output_path = _read_env("OUTPUT")
    write_step_summary = _read_bool_env("WRITE_STEP_SUMMARY", default=True)
    registry_payload_output = _read_env("REGISTRY_PAYLOAD_OUTPUT")
    upload_sarif = _read_bool_env("UPLOAD_SARIF")
    profile = _read_env("PROFILE", "default")
    config = _read_env("CONFIG")
    baseline = _read_env("BASELINE")
    online = _read_bool_env("ONLINE")
    min_score = _read_int_env("MIN_SCORE", 0)
    fail_on = _read_env("FAIL_ON", "none")
    cisco_scan = _read_env("CISCO_SCAN", "auto")
    cisco_policy = _read_env("CISCO_POLICY", "balanced")
    submission_enabled = _read_bool_env("SUBMISSION_ENABLED")
    submission_threshold = _read_int_env("SUBMISSION_SCORE_THRESHOLD", 80)
    submission_repos = _parse_csv(_read_env("SUBMISSION_REPOS"))
    submission_token = _read_env("SUBMISSION_TOKEN").strip()
    submission_labels = _parse_csv(_read_env("SUBMISSION_LABELS"))
    submission_category = _read_env("SUBMISSION_CATEGORY", "Community Plugins")
    submission_plugin_name = _read_env("SUBMISSION_PLUGIN_NAME")
    submission_plugin_url = _read_env("SUBMISSION_PLUGIN_URL")
    submission_plugin_description = _read_env("SUBMISSION_PLUGIN_DESCRIPTION")
    submission_author = _read_env("SUBMISSION_AUTHOR")
    github_repository = _read_env("GITHUB_REPOSITORY")
    github_server_url = _read_env("GITHUB_SERVER_URL", "https://github.com")
    github_sha = _read_env("GITHUB_SHA")
    github_run_id = _read_env("GITHUB_RUN_ID")
    github_api_url = _read_env("GITHUB_API_URL", "https://api.github.com")
    github_event_name = _read_env("GITHUB_EVENT_NAME")
    github_event_path = _read_env("GITHUB_EVENT_PATH")
    github_ref = _read_env("GITHUB_REF")
    pr_comment_mode = _normalize_pr_comment_mode(_read_env("PR_COMMENT", "off"))
    pr_comment_style = _normalize_pr_comment_style(_read_env("PR_COMMENT_STYLE", "concise"))
    pr_comment_header = _read_env("PR_COMMENT_HEADER")
    pr_comment_max_findings = max(0, _read_int_env("PR_COMMENT_MAX_FINDINGS", 3))
    pr_comment_skip_if_unchanged = _read_bool_env("PR_COMMENT_SKIP_IF_UNCHANGED", default=True)
    pr_comment_compare_to_previous = _read_bool_env("PR_COMMENT_COMPARE_TO_PREVIOUS", default=True)
    pr_comment_token = _read_env("PR_COMMENT_TOKEN").strip() or _read_env("GITHUB_TOKEN").strip()

    workflow_url = ""
    if github_repository and github_run_id:
        workflow_url = f"{github_server_url.rstrip('/')}/{github_repository}/actions/runs/{github_run_id}"

    report_path_value = ""
    registry_payload_path_value = ""
    submission_issues: list[SubmissionIssue] = []
    submission_eligible = False
    output_values = {
        "mode": mode,
        "score": "",
        "grade": "",
        "grade_label": "",
        "policy_pass": "",
        "verify_pass": "",
        "max_severity": "",
        "findings_total": "",
        "report_path": "",
        "registry_payload_path": "",
        "submission_eligible": "false",
        "submission_performed": "false",
        "submission_issue_urls": "",
        "submission_issue_numbers": "",
        "pr_comment_status": "",
        "pr_comment_url": "",
        "pr_comment_id": "",
        "pr_comment_reason": "",
        "action_exit_code": "0",
        "action_exit_reason": "",
    }
    verify_pass_for_summary: bool | None = None
    verify_pass_for_comment: bool | None = None
    scan_scope = "plugin"
    local_plugin_count: int | None = None
    skipped_target_count: int | None = None
    gate_reasons: list[str] = []
    snapshot: PRCommentSnapshot | None = None

    if mode in {"scan", "lint", "submit"}:
        args = _build_scan_args(
            plugin_dir=plugin_dir,
            profile=profile,
            config=config,
            baseline=baseline,
            min_score=min_score,
            fail_on_severity=fail_on,
            cisco_scan=cisco_scan,
            cisco_policy=cisco_policy,
        )
        raw_result, result, resolved_profile, policy_eval, _effective_score = _scan_with_policy(
            args,
            Path(plugin_dir).resolve(),
        )
        scan_scope = getattr(result, "scope", "plugin")
        if scan_scope == "repository":
            local_plugin_count = len(result.plugin_results)
            skipped_target_count = len(result.skipped_targets)
        rendered = ""
        verification = None
        artifact_path = ""
        if mode == "scan":
            if upload_sarif:
                if output_format != "sarif":
                    gate_reasons.append("upload_sarif requires format=sarif")
                if not output_path:
                    output_path = "codex-plugin-scanner.sarif"
            rendered = _render_scan_output(
                result,
                output_format=output_format,
                profile=resolved_profile,
                policy_pass=policy_eval.policy_pass,
                raw_score=raw_result.score,
            )
        elif mode == "lint":
            rendered = _render_lint_output(
                result,
                output_format="json" if output_format not in {"json", "text"} else output_format,
                profile=resolved_profile,
                policy_pass=policy_eval.policy_pass,
            )
        else:
            if scan_scope != "plugin":
                gate_reasons.append(
                    "submission mode requires plugin_dir to point at a single plugin directory"
                )
                rendered = _render_scan_output(
                    result,
                    output_format="json" if output_format == "json" else "text",
                    profile=resolved_profile,
                    policy_pass=policy_eval.policy_pass,
                    raw_score=raw_result.score,
                )
            else:
                verification = verify_plugin(Path(plugin_dir).resolve(), online=online)
                artifact_path = output_path or "plugin-quality.json"
                artifact = build_quality_artifact(
                    Path(plugin_dir).resolve(),
                    result,
                    verification,
                    policy_eval,
                    resolved_profile,
                    raw_score=raw_result.score,
                )
                write_quality_artifact(Path(artifact_path), artifact)
                rendered = json.dumps(artifact, indent=2)
                print(f"Submission artifact written to {artifact_path}")
                verify_pass_for_summary = verification.verify_pass
                verify_pass_for_comment = verification.verify_pass

        if output_path and mode != "submit":
            target = Path(output_path)
            target.write_text(rendered, encoding="utf-8")
            print(f"Report written to {target}")
            report_path_value = str(target)
        elif mode == "submit":
            report_path_value = artifact_path
        else:
            print(rendered)

        score_failed = result.score < min_score
        severity_failed = should_fail_for_severity(result, fail_on)
        output_values.update(
            {
                "score": str(result.score),
                "grade": result.grade,
                "grade_label": GRADE_LABELS.get(result.grade, "Unknown"),
                "policy_pass": "true" if policy_eval.policy_pass else "false",
                "verify_pass": "true" if verification is not None and verification.verify_pass else "",
                "max_severity": max_severity(result.findings).value if result.findings else "none",
                "findings_total": str(sum(result.severity_counts.values())),
            }
        )
        verify_pass_for_comment = verification.verify_pass if verification is not None else None

        if submission_enabled or registry_payload_output:
            metadata = resolve_submission_metadata(
                Path(plugin_dir).resolve(),
                result,
                plugin_name=submission_plugin_name,
                plugin_url=submission_plugin_url,
                description=submission_plugin_description,
                author=submission_author,
                category=submission_category,
                github_repository=github_repository or None,
                github_server_url=github_server_url,
            )
            registry_payload = build_submission_payload(
                metadata,
                result,
                source_repository=github_repository,
                source_sha=github_sha,
                workflow_url=workflow_url,
                scanner_version=__version__,
            )
            if registry_payload_output:
                registry_path = Path(registry_payload_output)
                registry_path.write_text(json.dumps(registry_payload, indent=2), encoding="utf-8")
                registry_payload_path_value = str(registry_path)

            verify_for_submission = verification.verify_pass if verification is not None else True
            submission_eligible = (
                submission_enabled
                and result.score >= submission_threshold
                and not severity_failed
                and policy_eval.policy_pass
                and verify_for_submission
            )

            if submission_eligible:
                if not submission_repos:
                    gate_reasons.append("submission is enabled but no submission repositories were configured")
                elif not submission_token:
                    gate_reasons.append("submission is enabled but no submission token was provided")
                elif not metadata.plugin_url:
                    gate_reasons.append("submission metadata is missing a plugin repository URL")
                else:
                    title = build_submission_issue_title(metadata)
                    body = build_submission_issue_body(
                        metadata,
                        result,
                        payload=registry_payload,
                        workflow_url=workflow_url,
                    )
                    for submission_repo in submission_repos:
                        existing = find_existing_submission_issue(
                            submission_repo,
                            metadata.plugin_url,
                            submission_token,
                            api_base_url=github_api_url,
                        )
                        if existing is not None:
                            submission_issues.append(existing)
                            continue
                        submission_issues.append(
                            create_submission_issue(
                                submission_repo,
                                title,
                                body,
                                submission_token,
                                labels=submission_labels,
                                api_base_url=github_api_url,
                            )
                        )

        output_values["submission_eligible"] = "true" if submission_eligible else "false"
        output_values["submission_performed"] = "true" if submission_issues else "false"
        output_values["submission_issue_urls"] = ",".join(issue.url for issue in submission_issues)
        output_values["submission_issue_numbers"] = ",".join(str(issue.number) for issue in submission_issues)

        if score_failed:
            gate_reasons.append(f"score {result.score} is below minimum threshold {min_score}")
        if severity_failed:
            gate_reasons.append(f'findings met or exceeded the "{fail_on}" severity threshold')
        if not policy_eval.policy_pass:
            gate_reasons.append(f'policy profile "{resolved_profile}" failed')
        if mode == "submit" and verification is not None and not verification.verify_pass:
            gate_reasons.append("submission blocked because runtime verification failed")

        gate_pass = not gate_reasons
        snapshot = _build_pr_comment_snapshot_for_scan(
            mode=mode,
            profile=resolved_profile,
            plugin_dir=str(Path(plugin_dir).resolve()),
            result=result,
            policy_pass=policy_eval.policy_pass,
            verify_pass=verify_pass_for_comment,
            gate_pass=gate_pass,
            gate_reasons=tuple(gate_reasons),
            min_score=min_score,
            fail_on_severity=fail_on,
            score_gate_pass=not score_failed,
            severity_gate_pass=not severity_failed,
            submission_eligible=submission_eligible,
            submission_issues=submission_issues,
            workflow_url=workflow_url,
            full_report_markdown=format_markdown(result),
        )

    elif mode == "verify":
        verification = verify_plugin(Path(plugin_dir).resolve(), online=online)
        scan_scope = getattr(verification, "scope", "plugin")
        if scan_scope == "repository":
            local_plugin_count = len(verification.plugin_results)
            skipped_target_count = len(verification.skipped_targets)
        rendered = _render_verify_output(verification, output_format=output_format)
        verify_pass_for_summary = verification.verify_pass
        if output_path:
            target = Path(output_path)
            target.write_text(rendered, encoding="utf-8")
            print(f"Report written to {target}")
            report_path_value = str(target)
        else:
            print(rendered)
        output_values["verify_pass"] = "true" if verification.verify_pass else "false"
        verify_pass_for_summary = verification.verify_pass
        verify_pass_for_comment = verification.verify_pass
        if not verification.verify_pass:
            gate_reasons.append("runtime verification failed")
        snapshot = _build_pr_comment_snapshot_for_verify(
            mode=mode,
            profile=profile,
            plugin_dir=str(Path(plugin_dir).resolve()),
            verification=verification,
            gate_pass=verification.verify_pass,
            gate_reasons=tuple(gate_reasons),
            fail_on_severity=fail_on,
            workflow_url=workflow_url,
            full_report_markdown=rendered,
        )
    else:
        print(f"Unsupported mode: {mode}", file=sys.stderr)
        return 1

    output_values["report_path"] = report_path_value
    output_values["registry_payload_path"] = registry_payload_path_value
    action_exit_code = 0 if not gate_reasons else 1
    action_exit_reason = "; ".join(dict.fromkeys(gate_reasons))

    pr_comment_outcome = publish_pr_comment(
        config=PRCommentConfig(
            mode=pr_comment_mode,
            style=pr_comment_style,
            header=pr_comment_header,
            max_findings=pr_comment_max_findings,
            token=pr_comment_token,
            skip_if_unchanged=pr_comment_skip_if_unchanged,
            compare_to_previous=pr_comment_compare_to_previous,
            api_base_url=github_api_url,
        ),
        snapshot=snapshot
        if snapshot is not None
        else PRCommentSnapshot(
            mode=mode,
            profile=profile,
            plugin_dir=str(Path(plugin_dir).resolve()),
            scope=scan_scope,
            score=None,
            grade="",
            grade_label="",
            max_severity=output_values["max_severity"] or "none",
            findings_total=None,
            severity_counts={severity: 0 for severity in ("critical", "high", "medium", "low", "info")},
            min_score=min_score,
            fail_on_severity=fail_on,
            score_gate_pass=None,
            severity_gate_pass=None,
            policy_pass=True if output_values["policy_pass"] == "true" else None,
            verify_pass=verify_pass_for_comment,
            gate_pass=not gate_reasons,
            gate_reasons=tuple(gate_reasons),
            top_findings=(),
            categories=(),
            integrations=(),
            submission_eligible=submission_eligible,
            submission_issues=tuple(issue.url for issue in submission_issues),
            workflow_url=workflow_url,
            full_report_markdown="",
        ),
        event_name=github_event_name,
        event_path=github_event_path,
        ref=github_ref,
        repository=github_repository,
        head_sha=github_sha,
    )
    output_values["pr_comment_status"] = pr_comment_outcome.status
    output_values["pr_comment_url"] = pr_comment_outcome.url
    output_values["pr_comment_id"] = "" if pr_comment_outcome.comment_id is None else str(pr_comment_outcome.comment_id)
    output_values["pr_comment_reason"] = pr_comment_outcome.reason
    if pr_comment_outcome.status == "failed":
        reason = f"pull request comment failed: {pr_comment_outcome.reason or 'unknown error'}"
        if reason not in gate_reasons:
            gate_reasons.append(reason)
        action_exit_code = 1
        action_exit_reason = "; ".join(dict.fromkeys(gate_reasons))

    output_values["action_exit_code"] = str(action_exit_code)
    output_values["action_exit_reason"] = action_exit_reason

    step_summary_path = _read_env("GITHUB_STEP_SUMMARY")
    if write_step_summary and step_summary_path:
        _write_step_summary(
            step_summary_path,
            _build_step_summary_lines(
                mode=mode,
                score=output_values["score"],
                grade=output_values["grade"],
                grade_label=output_values["grade_label"],
                max_severity=output_values["max_severity"] or "none",
                findings_total=output_values["findings_total"],
                report_path=report_path_value,
                registry_payload_path=registry_payload_path_value,
                submission_issues=submission_issues,
                submission_eligible=submission_eligible,
                verify_pass=verify_pass_for_summary,
                scope=scan_scope,
                local_plugin_count=local_plugin_count,
                skipped_target_count=skipped_target_count,
                pr_comment_status=output_values["pr_comment_status"],
                pr_comment_url=output_values["pr_comment_url"],
                pr_comment_reason=output_values["pr_comment_reason"],
            ),
        )

    github_output = _read_env("GITHUB_OUTPUT")
    if github_output:
        _write_outputs(github_output, output_values)

    if action_exit_code != 0 and action_exit_reason:
        print(action_exit_reason, file=sys.stderr)
    return action_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
