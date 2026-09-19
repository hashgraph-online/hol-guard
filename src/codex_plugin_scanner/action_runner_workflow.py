"""Actions scan, verification, and submission workflow using its live entry namespace."""

from __future__ import annotations

from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding
    from .submission import SubmissionIssue


def run(_runner: ModuleType) -> int:
    mode = _runner._read_env("MODE", "scan")
    plugin_dir = _runner._read_env("PLUGIN_DIR", ".")
    output_format = _runner._read_env("FORMAT", "text")
    output_path = _runner._read_env("OUTPUT")
    write_step_summary = _runner._read_bool_env("WRITE_STEP_SUMMARY", default=True)
    registry_payload_output = _runner._read_env("REGISTRY_PAYLOAD_OUTPUT")
    upload_sarif = _runner._read_bool_env("UPLOAD_SARIF")
    profile = _runner._read_env("PROFILE", "default")
    config = _runner._read_env("CONFIG")
    baseline = _runner._read_env("BASELINE")
    trust_repository_policy = _runner._read_bool_env("TRUST_REPOSITORY_POLICY")
    online = _runner._read_bool_env("ONLINE")
    min_score = int(_runner._read_env("MIN_SCORE", "0"))
    fail_on = _runner._read_env("FAIL_ON", "none")
    cisco_scan = _runner._read_env("CISCO_SCAN", "auto")
    cisco_mcp_scan = _runner._read_env("CISCO_MCP_SCAN", "auto")
    cisco_policy = _runner._read_env("CISCO_POLICY", "balanced")
    submission_enabled = _runner._read_bool_env("SUBMISSION_ENABLED")
    submission_threshold = int(_runner._read_env("SUBMISSION_SCORE_THRESHOLD", "80"))
    submission_repos = _runner._parse_csv(_runner._read_env("SUBMISSION_REPOS"))
    submission_token = _runner._read_env("SUBMISSION_TOKEN").strip()
    submission_labels = _runner._parse_csv(_runner._read_env("SUBMISSION_LABELS"))
    submission_category = _runner._read_env("SUBMISSION_CATEGORY", "Community Plugins")
    submission_plugin_name = _runner._read_env("SUBMISSION_PLUGIN_NAME")
    submission_plugin_url = _runner._read_env("SUBMISSION_PLUGIN_URL")
    submission_plugin_description = _runner._read_env("SUBMISSION_PLUGIN_DESCRIPTION")
    submission_author = _runner._read_env("SUBMISSION_AUTHOR")
    github_repository = _runner._read_env("GITHUB_REPOSITORY")
    github_server_url = _runner._read_env("GITHUB_SERVER_URL", "https://github.com")
    github_sha = _runner._read_env("GITHUB_SHA")
    github_run_id = _runner._read_env("GITHUB_RUN_ID")
    github_api_url = _runner._read_env("GITHUB_API_URL", "https://api.github.com")
    github_token = _runner._read_env("GITHUB_TOKEN")
    github_event_name = _runner._read_env("GITHUB_EVENT_NAME")
    github_event_path = _runner._read_env("GITHUB_EVENT_PATH")
    pr_comment_mode, pr_comment_style, pr_comment_max_findings = _runner._resolve_pr_comment_settings(
        plugin_dir=plugin_dir,
        config_path=config,
        trust_repository_policy=trust_repository_policy,
    )
    pull_request_number = _runner.load_pull_request_number(github_event_path) if github_event_path else None

    workflow_url = ""
    if github_repository and github_run_id:
        workflow_url = f"{github_server_url.rstrip('/')}/{github_repository}/actions/runs/{github_run_id}"
    normalized_github_api_url = github_api_url
    github_api_url_error: ValueError | None = None
    try:
        normalized_github_api_url = _runner.normalize_github_api_base_url(
            github_api_url,
            github_server_url=github_server_url,
        )
    except ValueError as error:
        github_api_url_error = error

    report_path_value = ""
    registry_payload_path_value = ""
    submission_issues: list[SubmissionIssue] = []
    submission_eligible = False
    return_code = 0
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
        "action_exit_code": "0",
        "pr_comment_status": "skipped",
        "pr_comment_id": "",
        "pr_comment_url": "",
    }
    verify_pass_for_summary: bool | None = None
    scan_scope = "plugin"
    local_plugin_count: int | None = None
    skipped_target_count: int | None = None
    pr_comment_body = ""
    summary_findings: tuple[Finding, ...] = ()

    def finish(return_code: int) -> int:
        output_values["report_path"] = report_path_value
        output_values["registry_payload_path"] = registry_payload_path_value
        if pr_comment_mode == "off":
            output_values["pr_comment_status"] = "disabled"
        elif _runner.should_manage_pr_comment(
            mode=pr_comment_mode,
            event_name=github_event_name,
            pull_request_number=pull_request_number,
        ):
            if github_api_url_error is not None:
                print(f"Warning: invalid GITHUB_API_URL: {github_api_url_error}", file=_runner.sys.stderr)
                output_values["pr_comment_status"] = "failed"
            elif github_repository and github_token and pr_comment_body:
                try:
                    pr_comment_result = _runner.upsert_pr_comment(
                        repository=github_repository,
                        pull_request_number=pull_request_number if pull_request_number is not None else 0,
                        token=github_token,
                        api_base_url=normalized_github_api_url,
                        body=pr_comment_body,
                    )
                    output_values["pr_comment_status"] = pr_comment_result.status
                    output_values["pr_comment_id"] = pr_comment_result.comment_id
                    output_values["pr_comment_url"] = pr_comment_result.comment_url
                except (_runner.HTTPError, _runner.URLError, RuntimeError) as error:
                    print(f"Warning: failed to update PR comment: {error}", file=_runner.sys.stderr)
                    output_values["pr_comment_status"] = "failed"
            else:
                output_values["pr_comment_status"] = "skipped"
        else:
            output_values["pr_comment_status"] = "skipped"
        step_summary_path = _runner._read_env("GITHUB_STEP_SUMMARY")
        if write_step_summary and step_summary_path:
            _runner._write_step_summary(
                step_summary_path,
                _runner._build_step_summary_lines(
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
                    findings=summary_findings,
                ),
            )
        output_values["action_exit_code"] = str(return_code)
        github_output = _runner._read_env("GITHUB_OUTPUT")
        if github_output:
            _runner._write_outputs(github_output, output_values)
        return return_code

    _runner.drop_external_analyzer_credentials(online)
    if mode in {"scan", "lint", "submit"}:
        args = _runner._build_scan_args(
            plugin_dir=plugin_dir,
            profile=profile,
            config=config,
            baseline=baseline,
            min_score=min_score,
            fail_on_severity=fail_on,
            cisco_scan=cisco_scan,
            cisco_mcp_scan=cisco_mcp_scan,
            cisco_policy=cisco_policy,
            trust_repository_policy=trust_repository_policy,
        )
        (
            raw_result,
            result,
            resolved_profile,
            policy_eval,
            _effective_score,
            _config_path,
            _baseline_path,
        ) = _runner._scan_with_policy(args, _runner.Path(plugin_dir).resolve())
        summary_findings = result.findings
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
                    print("upload_sarif requires format=sarif.", file=_runner.sys.stderr)
                    return finish(1)
                if not output_path:
                    output_path = "ai-plugin-scanner.sarif"
            rendered = _runner._render_scan_output(
                result,
                output_format=output_format,
                profile=resolved_profile,
                policy_pass=policy_eval.policy_pass,
                raw_score=raw_result.score,
            )
            pr_comment_body = _runner.build_scan_pr_comment_body(
                result=result,
                profile=resolved_profile,
                policy_pass=policy_eval.policy_pass,
                style=pr_comment_style,
                max_findings_to_render=pr_comment_max_findings,
            )
        elif mode == "lint":
            rendered = _runner._render_lint_output(
                result,
                output_format="json" if output_format not in {"json", "text"} else output_format,
                profile=resolved_profile,
                policy_pass=policy_eval.policy_pass,
            )
            pr_comment_body = _runner.build_scan_pr_comment_body(
                result=result,
                profile=resolved_profile,
                policy_pass=policy_eval.policy_pass,
                style=pr_comment_style,
                max_findings_to_render=pr_comment_max_findings,
            )
        else:
            if scan_scope != "plugin":
                print(
                    "Submission mode requires a single plugin directory. "
                    "Point plugin_dir at one plugin instead of a repo marketplace root.",
                    file=_runner.sys.stderr,
                )
                return finish(1)
            verification = _runner.verify_plugin(_runner.Path(plugin_dir).resolve(), online=online)
            artifact_path = output_path or "plugin-quality.json"
            artifact = _runner.build_quality_artifact(
                _runner.Path(plugin_dir).resolve(),
                result,
                verification,
                policy_eval,
                resolved_profile,
                raw_score=raw_result.score,
            )
            _runner.write_quality_artifact(_runner.Path(artifact_path), artifact)
            rendered = _runner.json.dumps(artifact, indent=2)
            print(f"Submission artifact written to {artifact_path}")
            verify_pass_for_summary = verification.verify_pass

        if output_path and mode != "submit":
            target = _runner.Path(output_path)
            _runner.write_text_atomic_no_follow(target, rendered)
            print(f"Report written to {target}")
            report_path_value = str(target)
        elif mode == "submit":
            report_path_value = artifact_path
        else:
            print(rendered)

        output_values["report_path"] = report_path_value

        highest_severity = _runner.max_severity(result.findings)
        severity_failed = _runner.should_fail_for_severity(result, fail_on)
        output_values.update(
            {
                "score": str(result.score),
                "grade": result.grade,
                "grade_label": _runner.GRADE_LABELS.get(result.grade, "Unknown"),
                "policy_pass": "true" if policy_eval.policy_pass else "false",
                "verify_pass": "true" if verification is not None and verification.verify_pass else "",
                "max_severity": highest_severity.value if highest_severity is not None else "none",
                "findings_total": str(sum(result.severity_counts.values())),
            }
        )

        if submission_enabled or registry_payload_output:
            metadata = _runner.resolve_submission_metadata(
                _runner.Path(plugin_dir).resolve(),
                result,
                plugin_name=submission_plugin_name,
                plugin_url=submission_plugin_url,
                description=submission_plugin_description,
                author=submission_author,
                category=submission_category,
                github_repository=github_repository or None,
                github_server_url=github_server_url,
            )
            registry_payload = _runner.build_submission_payload(
                metadata,
                result,
                source_repository=github_repository,
                source_sha=github_sha,
                workflow_url=workflow_url,
                scanner_version=_runner.__version__,
            )
            if registry_payload_output:
                registry_path = _runner.Path(registry_payload_output)
                _runner.write_text_atomic_no_follow(registry_path, _runner.json.dumps(registry_payload, indent=2))
                registry_payload_path_value = str(registry_path)
                output_values["registry_payload_path"] = registry_payload_path_value

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
                    print(
                        "Submission is enabled but no submission repositories were configured.", file=_runner.sys.stderr
                    )
                    return finish(1)
                if not submission_token:
                    print("Submission is enabled but no submission token was provided.", file=_runner.sys.stderr)
                    return finish(1)
                if github_api_url_error is not None:
                    print(f"Invalid GITHUB_API_URL: {github_api_url_error}", file=_runner.sys.stderr)
                    return finish(1)
                if not metadata.plugin_url:
                    print("Submission metadata is missing a plugin repository URL.", file=_runner.sys.stderr)
                    return finish(1)
                title = _runner.build_submission_issue_title(metadata)
                body = _runner.build_submission_issue_body(
                    metadata,
                    result,
                    payload=registry_payload,
                    workflow_url=workflow_url,
                )
                for submission_repo in submission_repos:
                    existing = _runner.find_existing_submission_issue(
                        submission_repo,
                        metadata.plugin_url,
                        submission_token,
                        api_base_url=normalized_github_api_url,
                    )
                    if existing is not None:
                        submission_issues.append(existing)
                        continue
                    submission_issues.append(
                        _runner.create_submission_issue(
                            submission_repo,
                            title,
                            body,
                            submission_token,
                            labels=submission_labels,
                            api_base_url=normalized_github_api_url,
                        )
                    )

        output_values["submission_eligible"] = "true" if submission_eligible else "false"
        output_values["submission_performed"] = "true" if submission_issues else "false"
        output_values["submission_issue_urls"] = ",".join(issue.url for issue in submission_issues)
        output_values["submission_issue_numbers"] = ",".join(str(issue.number) for issue in submission_issues)

        if result.score < min_score:
            print(f"Score {result.score} is below minimum threshold {min_score}", file=_runner.sys.stderr)
            return finish(1)
        if _runner.should_fail_for_severity(result, fail_on):
            print(f'Findings met or exceeded the "{fail_on}" severity threshold.', file=_runner.sys.stderr)
            return finish(1)
        if not policy_eval.policy_pass:
            print(f'Policy profile "{resolved_profile}" failed.', file=_runner.sys.stderr)
            return finish(1)
        if mode == "submit" and verification is not None and not verification.verify_pass:
            print("Submission blocked: runtime verification failed.", file=_runner.sys.stderr)
            return finish(1)

    elif mode == "verify":
        verification = _runner.verify_plugin(_runner.Path(plugin_dir).resolve(), online=online)
        scan_scope = getattr(verification, "scope", "plugin")
        if scan_scope == "repository":
            local_plugin_count = len(verification.plugin_results)
            skipped_target_count = len(verification.skipped_targets)
        verification_payload = _runner.build_verification_payload(verification)
        pr_comment_body = _runner.build_verify_pr_comment_body(
            verification_payload=verification_payload,
            style=pr_comment_style,
            max_findings_to_render=pr_comment_max_findings,
        )
        rendered = _runner._render_verify_output(verification, output_format=output_format)
        verify_pass_for_summary = verification.verify_pass
        if output_path:
            target = _runner.Path(output_path)
            _runner.write_text_atomic_no_follow(target, rendered)
            print(f"Report written to {target}")
            report_path_value = str(target)
        else:
            print(rendered)
        return_code = 1 if not verification.verify_pass else 0
        output_values["verify_pass"] = "true" if verification.verify_pass else "false"
        output_values["report_path"] = report_path_value
    else:
        print(f"Unsupported mode: {mode}", file=_runner.sys.stderr)
        return finish(1)

    if mode == "verify":
        return finish(return_code)
    return finish(0)
