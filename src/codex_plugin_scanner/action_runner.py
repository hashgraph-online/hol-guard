"""GitHub Action entry point for scan and submission workflows."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import __version__
from .cli import format_text
from .models import GRADE_LABELS, ScanOptions, ScanResult, Severity, max_severity
from .reporting import format_json, format_markdown, format_sarif, should_fail_for_severity
from .scanner import scan_plugin
from .submission import (
    SubmissionIssue,
    build_submission_issue_body,
    build_submission_issue_title,
    build_submission_payload,
    create_submission_issue,
    find_existing_submission_issue,
    resolve_submission_metadata,
)


def _parse_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _read_bool_env(name: str) -> bool:
    return os.environ[name].strip().lower() == "true"


def _write_outputs(path: str, values: dict[str, str]) -> None:
    with Path(path).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _write_step_summary(path: str, lines: tuple[str, ...]) -> None:
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def _build_step_summary_lines(
    *,
    result: ScanResult,
    highest_severity: Severity | None,
    report_path: str,
    registry_payload_path: str,
    submission_issues: list[SubmissionIssue],
    submission_eligible: bool,
) -> tuple[str, ...]:
    lines = [
        "## HOL Codex Plugin Scanner",
        "",
        f"- Score: {result.score}/100",
        f"- Grade: {result.grade} - {GRADE_LABELS.get(result.grade, 'Unknown')}",
        f"- Max severity: {(highest_severity.value if highest_severity else 'none')}",
        f"- Findings: {sum(result.severity_counts.values())}",
        f"- Submission eligible: {'yes' if submission_eligible else 'no'}",
    ]
    if report_path:
        lines.append(f"- Report: `{report_path}`")
    if registry_payload_path:
        lines.append(f"- Registry payload: `{registry_payload_path}`")
    if submission_issues:
        issue_urls = ", ".join(issue.url for issue in submission_issues)
        lines.append(f"- Submission issues: {issue_urls}")
    return tuple(lines)


def main() -> int:
    plugin_dir = os.environ["PLUGIN_DIR"]
    output_format = os.environ["FORMAT"]
    output_path = os.environ["OUTPUT"]
    write_step_summary = _read_bool_env("WRITE_STEP_SUMMARY")
    registry_payload_output = os.environ["REGISTRY_PAYLOAD_OUTPUT"]
    min_score = int(os.environ["MIN_SCORE"])
    fail_on = os.environ["FAIL_ON"]
    cisco_scan = os.environ["CISCO_SCAN"]
    cisco_policy = os.environ["CISCO_POLICY"]
    submission_enabled = _read_bool_env("SUBMISSION_ENABLED")
    submission_threshold = int(os.environ["SUBMISSION_SCORE_THRESHOLD"])
    submission_repos = _parse_csv(os.environ["SUBMISSION_REPOS"])
    submission_token = os.environ["SUBMISSION_TOKEN"].strip()
    submission_labels = _parse_csv(os.environ["SUBMISSION_LABELS"])
    submission_category = os.environ["SUBMISSION_CATEGORY"]
    submission_plugin_name = os.environ["SUBMISSION_PLUGIN_NAME"]
    submission_plugin_url = os.environ["SUBMISSION_PLUGIN_URL"]
    submission_plugin_description = os.environ["SUBMISSION_PLUGIN_DESCRIPTION"]
    submission_author = os.environ["SUBMISSION_AUTHOR"]
    github_repository = os.environ.get("GITHUB_REPOSITORY", "")
    github_server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    github_sha = os.environ.get("GITHUB_SHA", "")
    github_run_id = os.environ.get("GITHUB_RUN_ID", "")
    github_api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    workflow_url = ""
    if github_repository and github_run_id:
        workflow_url = f"{github_server_url.rstrip('/')}/{github_repository}/actions/runs/{github_run_id}"

    result = scan_plugin(
        plugin_dir,
        ScanOptions(
            cisco_skill_scan=cisco_scan,
            cisco_policy=cisco_policy,
        ),
    )

    if output_format == "json":
        rendered = format_json(result)
    elif output_format == "markdown":
        rendered = format_markdown(result)
    elif output_format == "sarif":
        rendered = format_sarif(result)
    else:
        rendered = format_text(result)

    if output_path:
        target = Path(output_path)
        target.write_text(rendered, encoding="utf-8")
        print(f"Report written to {target}")
    else:
        print(rendered)

    highest_severity = max_severity(result.findings)
    severity_failed = should_fail_for_severity(result, fail_on)
    submission_eligible = submission_enabled and result.score >= submission_threshold and not severity_failed
    submission_issues = []
    registry_payload = None
    metadata = None
    report_path_value = ""
    registry_payload_path_value = ""

    if output_path:
        report_path_value = str(Path(output_path))

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
            registry_payload_path = Path(registry_payload_output)
            registry_payload_path.write_text(
                json.dumps(registry_payload, indent=2),
                encoding="utf-8",
            )
            registry_payload_path_value = str(registry_payload_path)

    if submission_eligible:
        if not submission_repos:
            print("Submission is enabled but no submission repositories were configured.", file=sys.stderr)
            return 1
        if not submission_token:
            print("Submission is enabled but no submission token was provided.", file=sys.stderr)
            return 1
        if metadata is None or registry_payload is None:
            print("Submission metadata could not be resolved.", file=sys.stderr)
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

    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if write_step_summary and step_summary_path:
        _write_step_summary(
            step_summary_path,
            _build_step_summary_lines(
                result=result,
                highest_severity=highest_severity,
                report_path=report_path_value,
                registry_payload_path=registry_payload_path_value,
                submission_issues=submission_issues,
                submission_eligible=submission_eligible,
            ),
        )

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        _write_outputs(
            github_output,
            {
                "score": str(result.score),
                "grade": result.grade,
                "grade_label": GRADE_LABELS.get(result.grade, "Unknown"),
                "max_severity": highest_severity.value if highest_severity else "none",
                "findings_total": str(sum(result.severity_counts.values())),
                "report_path": report_path_value,
                "registry_payload_path": registry_payload_path_value,
                "submission_eligible": "true" if submission_eligible else "false",
                "submission_performed": "true" if submission_issues else "false",
                "submission_issue_urls": ",".join(issue.url for issue in submission_issues),
                "submission_issue_numbers": ",".join(str(issue.number) for issue in submission_issues),
            },
        )

    if result.score < min_score:
        print(
            f"Score {result.score} is below minimum threshold {min_score}",
            file=sys.stderr,
        )
        return 1

    if severity_failed:
        print(
            f'Findings met or exceeded the "{fail_on}" severity threshold.',
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
