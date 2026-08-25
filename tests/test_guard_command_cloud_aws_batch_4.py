"""Regression and adversarial coverage for AWS destructive operation batch 4."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_cloud_aws_operation_matrix import (
    AWS_DESTRUCTIVE_COMMAND_PATHS,
    AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1,
    AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4,
    aws_destructive_command_matchers,
)
from tests.command_extension_contracts import (
    assert_review_required_cases,
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

_ACTION = "AWS destructive command"
_RULE = "command.cloud.aws.resource-deletion"

AWS_BATCH_4_REVIEW_CASES: tuple[tuple[str, str, str], ...] = tuple(
    (f"aws {' '.join(path)} --cli-input-json '{{}}'", _ACTION, _RULE) for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4
)
AWS_BATCH_4_SAFE_CASES: tuple[str, ...] = tuple(
    command
    for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4
    for command in (
        f"aws {' '.join(path)} --help",
        f"aws {' '.join(path)} --generate-cli-skeleton input",
        f"aws {' '.join(path)} --generate-cli-skeleton=output",
        f"aws {' '.join(path)} --generate-cli-skeleton yaml-input",
    )
)

AWS_BATCH_4_READ_ONLY_NEIGHBORS: tuple[str, ...] = (
    "aws accessanalyzer get-analyzer --analyzer-name audit",
    "aws accessanalyzer list-analyzers",
    "aws account get-alternate-contact --alternate-contact-type SECURITY",
    "aws acm-pca get-policy --resource-arn arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/example",
    "aws amp describe-workspace --workspace-id ws-example",
    "aws amp list-workspaces",
    "aws appconfig get-extension --extension-identifier example",
    "aws appflow describe-flow --flow-name example",
    "aws apprunner describe-service --service-arn arn:aws:apprunner:us-east-1:123456789012:service/example/id",
    "aws appstream describe-fleets",
    "aws athena get-work-group --work-group primary",
    "aws auditmanager get-assessment --assessment-id example",
    "aws backup-gateway list-gateways",
    "aws batch describe-jobs --jobs example",
    "aws bedrock get-custom-model --model-identifier example",
    "aws bedrock-agent get-agent --agent-id example",
    "aws budgets describe-budget --account-id 123456789012 --budget-name example",
    (
        "aws ce get-cost-and-usage --time-period Start=2026-08-01,End=2026-08-02 "
        "--granularity DAILY --metrics UnblendedCost"
    ),
    "aws chime get-account --account-id example",
    "aws cloudhsmv2 describe-clusters",
)


def test_aws_batch_4_matrix_is_exactly_one_hundred_unique_operations() -> None:
    assert len(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4) == 100
    assert len(set(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4)) == 100
    assert all(len(path) == 2 for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4)
    assert all(
        token and token == token.strip() and not token.startswith("-")
        for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4
        for token in path
    )


def test_aws_combined_matrix_is_exactly_two_hundred_unique_operations() -> None:
    assert len(AWS_DESTRUCTIVE_COMMAND_PATHS) == 200
    assert len(set(AWS_DESTRUCTIVE_COMMAND_PATHS)) == 200
    assert AWS_DESTRUCTIVE_COMMAND_PATHS == (
        AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1 + AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4
    )
    assert set(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1).isdisjoint(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4)


def test_aws_batch_4_compiles_into_the_combined_path_set_matcher() -> None:
    matchers = aws_destructive_command_matchers(
        global_options_with_values=frozenset({"--region"}),
        global_flags=frozenset({"--debug"}),
    )
    assert len(matchers) == 1
    assert matchers[0].paths == frozenset(AWS_DESTRUCTIVE_COMMAND_PATHS)
    assert set(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4).issubset(matchers[0].paths)


def test_aws_batch_4_operations_feed_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(AWS_BATCH_4_REVIEW_CASES, tmp_path)


def test_aws_batch_4_help_and_request_skeletons_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(AWS_BATCH_4_SAFE_CASES, tmp_path)


def test_aws_batch_4_global_option_positions_and_native_launchers(tmp_path: Path) -> None:
    cases: list[tuple[str, str, str]] = []
    for service, operation in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4[:16]:
        cases.extend(
            (
                (
                    f"aws --profile prod --region us-east-1 {service} {operation} --cli-input-json '{{}}'",
                    _ACTION,
                    _RULE,
                ),
                (
                    f"aws {service} --region us-east-1 {operation} --cli-input-json '{{}}'",
                    _ACTION,
                    _RULE,
                ),
                (
                    f"aws.exe --profile=prod {service} {operation} --cli-input-json '{{}}'",
                    _ACTION,
                    _RULE,
                ),
                (
                    f"aws.cmd --no-cli-pager {service} {operation} --cli-input-json '{{}}'",
                    _ACTION,
                    _RULE,
                ),
            )
        )
    assert_reviewed_command_cases(tuple(cases), tmp_path)


def test_aws_batch_4_unknown_global_options_fail_secure(tmp_path: Path) -> None:
    cases = tuple(
        (
            f"aws --future-global-option account {' '.join(path)} --cli-input-json '{{}}'",
            _ACTION,
            _RULE,
        )
        for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4[:16]
    )
    assert_reviewed_command_cases(cases, tmp_path)


def test_aws_batch_4_invalid_request_skeleton_forms_remain_reviewable(tmp_path: Path) -> None:
    service, operation = AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4[0]
    assert_review_required_cases(
        (
            f"aws {service} {operation} --generate-cli-skeleton=bogus",
            f"aws {service} {operation} --generate-cli-skeleton=output --generate-cli-skeleton=bogus",
            f"aws {service} {operation} --generate-cli-skeleton",
        ),
        tmp_path,
    )


def test_aws_batch_4_dry_run_does_not_bypass_non_ec2_operations(tmp_path: Path) -> None:
    assert_review_required_cases(
        (
            "aws batch terminate-job --job-id example --reason test --dry-run",
            "aws bedrock delete-guardrail --guardrail-identifier example --dry-run",
        ),
        tmp_path,
    )


def test_aws_batch_4_safe_segment_cannot_hide_later_destructive_segment(tmp_path: Path) -> None:
    first = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4[0])
    second = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4[1])
    assert_review_required_cases(
        (
            f"aws {first} --help && aws {second} --cli-input-json '{{}}'",
            f"aws {first} --generate-cli-skeleton output; aws {second} --cli-input-json '{{}}'",
        ),
        tmp_path,
    )


def test_aws_batch_4_quoted_examples_remain_data(tmp_path: Path) -> None:
    first = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4[0])
    second = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4[-1])
    assert_safe_command_cases(
        (
            f"printf '%s\\n' 'aws {first}'",
            f"grep 'aws {second}' scripts/cloud-audit.sh",
            f"python -c \"print('aws {first}')\"",
        ),
        tmp_path,
    )


def test_aws_batch_4_read_only_neighbors_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(AWS_BATCH_4_READ_ONLY_NEIGHBORS, tmp_path)
