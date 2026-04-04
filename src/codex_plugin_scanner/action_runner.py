"""GitHub Action entry point for scan and submission workflows."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .cli import _build_plain_text, _build_verification_text, _scan_with_policy
from .models import GRADE_LABELS, max_severity
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
    return tuple(lines)


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
    min_score = int(_read_env("MIN_SCORE", "0"))
    fail_on = _read_env("FAIL_ON", "none")
    cisco_scan = _read_env("CISCO_SCAN", "auto")
    cisco_policy = _read_env("CISCO_POLICY", "balanced")
    submission_enabled = _read_bool_env("SUBMISSION_ENABLED")
    submission_threshold = int(_read_env("SUBMISSION_SCORE_THRESHOLD", "80"))
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
    }
    verify_pass_for_summary: bool | None = None
    scan_scope = "plugin"
    local_plugin_count: int | None = None
    skipped_target_count: int | None = None

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
        artifact_path = ""
        verification = None
        if mode == "scan":
            if upload_sarif:
                if output_format != "sarif":
                    print("upload_sarif requires format=sarif.", file=sys.stderr)
                    return 1
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
                print(
                    "Submission mode requires a single plugin directory. "
                    "Point plugin_dir at one plugin instead of a repo marketplace root.",
                    file=sys.stderr,
                )
                return 1
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

        if output_path and mode != "submit":
            target = Path(output_path)
            target.write_text(rendered, encoding="utf-8")
            print(f"Report written to {target}")
            report_path_value = str(target)
        elif mode == "submit":
            report_path_value = artifact_path
        else:
            print(rendered)

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
                    print("Submission is enabled but no submission repositories were configured.", file=sys.stderr)
                    return 1
                if not submission_token:
                    print("Submission is enabled but no submission token was provided.", file=sys.stderr)
                    return 1
                if not metadata.plugin_url:
                    print("Submission metadata is missing a plugin repository URL.", file=sys.stderr)
                    return 1
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

        if result.score < min_score:
            print(f"Score {result.score} is below minimum threshold {min_score}", file=sys.stderr)
            return 1
        if should_fail_for_severity(result, fail_on):
            print(f'Findings met or exceeded the "{fail_on}" severity threshold.', file=sys.stderr)
            return 1
        if not policy_eval.policy_pass:
            print(f'Policy profile "{resolved_profile}" failed.', file=sys.stderr)
            return 1
        if mode == "submit" and verification is not None and not verification.verify_pass:
            print("Submission blocked: runtime verification failed.", file=sys.stderr)
            return 1

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
        return_code = 1 if not verification.verify_pass else 0
        output_values["verify_pass"] = "true" if verification.verify_pass else "false"
    else:
        print(f"Unsupported mode: {mode}", file=sys.stderr)
        return 1

    output_values["report_path"] = report_path_value
    output_values["registry_payload_path"] = registry_payload_path_value

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
            ),
        )

    github_output = _read_env("GITHUB_OUTPUT")
    if github_output:
        _write_outputs(github_output, output_values)

    if mode == "verify":
        return return_code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
