"""Regression and adversarial tests for the gcloud destructive operation matrix."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_cloud_gcp_operation_matrix import (
    GCP_DESTRUCTIVE_COMMAND_PATHS,
    gcp_destructive_command_matchers,
)
from tests.command_extension_contracts import (
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

_ACTION = "Google Cloud destructive command"
_RULE = "command.cloud.gcp.resource-deletion"

GCP_REVIEW_CASES: tuple[tuple[str, str, str], ...] = tuple(
    (f"gcloud {' '.join(path)} fixture --quiet", _ACTION, _RULE) for path in GCP_DESTRUCTIVE_COMMAND_PATHS
)
GCP_SAFE_CASES: tuple[str, ...] = tuple(f"gcloud {' '.join(path)} --help" for path in GCP_DESTRUCTIVE_COMMAND_PATHS)


def test_gcp_matrix_is_exactly_one_hundred_unique_operations() -> None:
    assert len(GCP_DESTRUCTIVE_COMMAND_PATHS) == 100
    assert len(set(GCP_DESTRUCTIVE_COMMAND_PATHS)) == 100
    assert all(
        token and token == token.strip() and not token.startswith("-")
        for path in GCP_DESTRUCTIVE_COMMAND_PATHS
        for token in path
    )


def test_gcp_matrix_compiles_to_one_path_set_matcher() -> None:
    matchers = gcp_destructive_command_matchers(
        global_options_with_values=frozenset({"--project"}),
        global_flags=frozenset({"--quiet"}),
    )
    assert len(matchers) == 1
    assert len(matchers[0].paths) == 300


def test_gcp_matrix_feeds_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(GCP_REVIEW_CASES, tmp_path)


def test_gcp_matrix_help_forms_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(GCP_SAFE_CASES, tmp_path)


def test_gcp_release_tracks_global_options_and_native_launchers(tmp_path: Path) -> None:
    compute_paths = tuple(path for path in GCP_DESTRUCTIVE_COMMAND_PATHS if path[0] == "compute")[:12]
    cases: list[tuple[str, str, str]] = []
    for path in compute_paths:
        operation = " ".join(path)
        cases.extend(
            (
                (f"gcloud alpha {operation} fixture --quiet", _ACTION, _RULE),
                (f"gcloud beta {operation} fixture --quiet", _ACTION, _RULE),
                (f"gcloud --project prod {operation} fixture -q", _ACTION, _RULE),
                (f"gcloud {path[0]} --project=prod {' '.join(path[1:])} fixture", _ACTION, _RULE),
                (f"gcloud.exe --configuration prod {operation} fixture", _ACTION, _RULE),
                (f"gcloud.cmd --no-log-http {operation} fixture", _ACTION, _RULE),
            )
        )
    assert_reviewed_command_cases(tuple(cases), tmp_path)


def test_gcp_unknown_global_options_fail_secure(tmp_path: Path) -> None:
    cases = tuple(
        (f"gcloud --future-global-option account {' '.join(path)} fixture", _ACTION, _RULE)
        for path in GCP_DESTRUCTIVE_COMMAND_PATHS[:12]
    )
    assert_reviewed_command_cases(cases, tmp_path)


def test_gcp_disabled_help_form_remains_reviewable(tmp_path: Path) -> None:
    command = " ".join(GCP_DESTRUCTIVE_COMMAND_PATHS[0])
    assert_reviewed_command_cases(
        ((f"gcloud {command} fixture --help --help=false", _ACTION, _RULE),),
        tmp_path,
    )


def test_gcp_safe_segment_cannot_hide_later_destructive_segment(tmp_path: Path) -> None:
    first = " ".join(GCP_DESTRUCTIVE_COMMAND_PATHS[0])
    second = " ".join(GCP_DESTRUCTIVE_COMMAND_PATHS[1])
    assert_reviewed_command_cases(
        (
            (
                f"gcloud {first} --help && gcloud {second} fixture --quiet",
                _ACTION,
                _RULE,
            ),
        ),
        tmp_path,
    )


def test_gcp_quoted_examples_remain_data(tmp_path: Path) -> None:
    command = " ".join(GCP_DESTRUCTIVE_COMMAND_PATHS[0])
    assert_safe_command_cases(
        (
            f"printf '%s\\n' 'gcloud {command} fixture'",
            f"grep 'gcloud {command}' scripts/cloud-audit.sh",
        ),
        tmp_path,
    )
