"""Regression and adversarial tests for AWS destructive operation batch 5."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.cloud_operation_fixtures import (
    AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5,
)
from tests.command_extension_contracts import (
    assert_review_required_cases,
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

_ACTION = "AWS destructive command"
_RULE = "command.cloud.aws.resource-deletion"

AWS_BATCH_5_REVIEW_CASES: tuple[tuple[str, str, str], ...] = tuple(
    (f"aws {' '.join(path)} --cli-input-json '{{}}'", _ACTION, _RULE) for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5
)
AWS_BATCH_5_SAFE_CASES: tuple[str, ...] = tuple(
    command
    for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5
    for skeleton_value in ("input", "output", "yaml-input")
    for command in (
        f"aws {' '.join(path)} --help",
        f"aws {' '.join(path)} --generate-cli-skeleton {skeleton_value}",
    )
)


# Only execution boundaries change. Keep all original safe requests, including
# repeats, and let the complete-node planner distribute each 50-command slice.
_SAFE_CASE_CHUNK_SIZE = 50
_SAFE_CASE_STARTS = tuple(range(0, len(AWS_BATCH_5_SAFE_CASES), _SAFE_CASE_CHUNK_SIZE))


def test_aws_batch_5_matrix_is_exactly_one_hundred_unique_operations() -> None:
    assert len(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5) == 100
    assert len(set(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5)) == 100
    assert all(len(path) == 2 for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5)
    assert all(
        token and token == token.strip() and not token.startswith("-")
        for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5
        for token in path
    )


def test_aws_batch_5_operations_feed_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(AWS_BATCH_5_REVIEW_CASES, tmp_path)


@pytest.mark.parametrize("case_start", _SAFE_CASE_STARTS, ids=lambda start: f"commands-{start:03d}")
def test_aws_batch_5_help_and_request_skeletons_remain_safe(tmp_path: Path, case_start: int) -> None:
    # Exercise every original command through the same real native security path.
    # Bounded nodes can be scheduled across different CI shards and xdist workers.
    assert_safe_command_cases(
        AWS_BATCH_5_SAFE_CASES[case_start : case_start + _SAFE_CASE_CHUNK_SIZE], tmp_path
    )


def test_aws_batch_5_global_option_positions_and_native_launchers(tmp_path: Path) -> None:
    cases: list[tuple[str, str, str]] = []
    for service, operation in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5[:16]:
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


def test_aws_batch_5_unknown_global_options_fail_secure(tmp_path: Path) -> None:
    cases = tuple(
        (
            f"aws --future-global-option account {' '.join(path)} --cli-input-json '{{}}'",
            _ACTION,
            _RULE,
        )
        for path in AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5[:16]
    )
    assert_reviewed_command_cases(cases, tmp_path)


def test_aws_batch_5_invalid_request_skeleton_forms_remain_reviewable(tmp_path: Path) -> None:
    service, operation = AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5[0]
    assert_review_required_cases(
        (
            f"aws {service} {operation} --generate-cli-skeleton=bogus",
            f"aws {service} {operation} --generate-cli-skeleton=output --generate-cli-skeleton=bogus",
        ),
        tmp_path,
    )


def test_aws_batch_5_safe_segment_cannot_hide_later_destructive_segment(tmp_path: Path) -> None:
    first = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5[0])
    second = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5[1])
    assert_review_required_cases(
        (f"aws {first} --help && aws {second} --cli-input-json '{{}}'",),
        tmp_path,
    )


def test_aws_batch_5_quoted_examples_remain_data(tmp_path: Path) -> None:
    first = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5[0])
    second = " ".join(AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5[-1])
    assert_safe_command_cases(
        (
            f"printf '%s\\n' 'aws {first}'",
            f"grep 'aws {second}' scripts/cloud-audit.sh",
        ),
        tmp_path,
    )
