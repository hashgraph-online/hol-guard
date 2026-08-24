"""Regression and adversarial tests for AWS destructive operation batch 1."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_cloud_aws_operation_matrix import (
    AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

_ACTION = "AWS destructive command"
_RULE = "command.cloud.aws.resource-deletion"

AWS_BATCH_1_REVIEW_CASES: tuple[tuple[str, str, str], ...] = tuple(
    (f"aws {' '.join(path)} --cli-input-json '{{}}'", _ACTION, _RULE)
    for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1
)
AWS_BATCH_1_SAFE_CASES: tuple[str, ...] = tuple(
    command
    for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1
    for command in (
        f"aws {' '.join(path)} --help",
        f"aws {' '.join(path)} --generate-cli-skeleton input",
    )
)


def test_aws_batch_1_matrix_is_exactly_one_hundred_unique_operations() -> None:
    assert len(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1) == 100
    assert len(set(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1)) == 100
    assert all(len(path) == 2 for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1)


def test_aws_batch_1_operations_feed_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(AWS_BATCH_1_REVIEW_CASES, tmp_path)


def test_aws_batch_1_help_and_request_skeletons_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(AWS_BATCH_1_SAFE_CASES, tmp_path)


def test_aws_batch_1_global_option_positions_and_native_launchers(tmp_path: Path) -> None:
    cases: list[tuple[str, str, str]] = []
    for service, operation in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1[:12]:
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


def test_aws_batch_1_unknown_global_options_fail_secure(tmp_path: Path) -> None:
    cases = tuple(
        (
            f"aws --future-global-option account {' '.join(path)} --cli-input-json '{{}}'",
            _ACTION,
            _RULE,
        )
        for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1[:12]
    )
    assert_reviewed_command_cases(cases, tmp_path)


def test_aws_batch_1_invalid_request_skeleton_forms_remain_reviewable(tmp_path: Path) -> None:
    service, operation = AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1[0]
    for command in (
        f"aws {service} {operation} --generate-cli-skeleton=bogus",
        f"aws {service} {operation} --generate-cli-skeleton=output --generate-cli-skeleton=bogus",
    ):
        payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert payload["status"] == "review"
        assert _RULE in {rule["rule_id"] for rule in payload["rules"]}


def test_aws_batch_1_safe_segment_cannot_hide_later_destructive_segment(tmp_path: Path) -> None:
    first = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1[0])
    second = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1[1])
    payload = inspect_command(
        f"aws {first} --help && aws {second} --cli-input-json '{{}}'",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "review"
    assert payload["controlling_rule_id"] == _RULE


def test_aws_batch_1_quoted_examples_remain_data(tmp_path: Path) -> None:
    command = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1[0])
    assert_safe_command_cases(
        (
            f"printf '%s\\n' 'aws {command}'",
            f"grep 'aws {command}' scripts/cloud-audit.sh",
        ),
        tmp_path,
    )
