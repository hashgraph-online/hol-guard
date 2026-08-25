"""Regression and adversarial tests for the Azure CLI destructive operation matrix."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_cloud_azure_operation_matrix import (
    AZURE_DESTRUCTIVE_COMMAND_PATHS,
    azure_destructive_command_matchers,
)
from tests.command_extension_contracts import (
    assert_review_required_cases,
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

_ACTION = "Azure destructive command"
_RULE = "command.cloud.azure.resource-deletion"

AZURE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = tuple(
    (f"az {' '.join(path)} fixture --yes", _ACTION, _RULE) for path in AZURE_DESTRUCTIVE_COMMAND_PATHS
)
AZURE_SAFE_CASES: tuple[str, ...] = tuple(
    command
    for path in AZURE_DESTRUCTIVE_COMMAND_PATHS
    for command in (
        f"az {' '.join(path)} --help",
        f"az {' '.join(path)} -h",
    )
)


def test_azure_matrix_is_exactly_one_hundred_unique_operations() -> None:
    """Keep the delivered batch count exact, unique, and structurally valid."""

    assert len(AZURE_DESTRUCTIVE_COMMAND_PATHS) == 100
    assert len(set(AZURE_DESTRUCTIVE_COMMAND_PATHS)) == 100
    assert all(
        token and token == token.strip() and not token.startswith("-")
        for path in AZURE_DESTRUCTIVE_COMMAND_PATHS
        for token in path
    )


def test_azure_matrix_compiles_to_one_path_set_matcher() -> None:
    """Compile all Azure paths into one fail-secure matcher."""

    matchers = azure_destructive_command_matchers(
        global_options_with_values=frozenset({"--subscription"}),
        global_flags=frozenset({"--only-show-errors"}),
    )
    assert len(matchers) == 1
    assert len(matchers[0].paths) == 100


def test_azure_matrix_feeds_inspection_and_runtime_hooks(tmp_path: Path) -> None:
    """Require review consistently in inspection and runtime projections."""

    assert_reviewed_command_cases(AZURE_REVIEW_CASES, tmp_path)


def test_azure_long_and_short_help_forms_remain_safe(tmp_path: Path) -> None:
    """Treat Azure long and short help forms as non-mutating variants."""

    assert_safe_command_cases(AZURE_SAFE_CASES, tmp_path)


def test_azure_global_options_and_native_launchers(tmp_path: Path) -> None:
    """Normalize provider-global options and native Windows launchers."""

    cases: list[tuple[str, str, str]] = []
    for path in AZURE_DESTRUCTIVE_COMMAND_PATHS[:12]:
        operation = " ".join(path)
        cases.extend(
            (
                (f"az --subscription prod {operation} fixture --yes", _ACTION, _RULE),
                (f"az {path[0]} --subscription prod {' '.join(path[1:])} fixture --yes", _ACTION, _RULE),
                (f"az.exe --output=json {operation} fixture --yes", _ACTION, _RULE),
                (f"az.cmd --only-show-errors {operation} fixture --yes", _ACTION, _RULE),
            )
        )
    assert_reviewed_command_cases(tuple(cases), tmp_path)


def test_azure_unknown_global_options_fail_secure(tmp_path: Path) -> None:
    """Retain review when future global options precede known destructive paths."""

    cases = tuple(
        (f"az --future-global-option account {' '.join(path)} fixture --yes", _ACTION, _RULE)
        for path in AZURE_DESTRUCTIVE_COMMAND_PATHS[:12]
    )
    assert_reviewed_command_cases(cases, tmp_path)


def test_azure_disabled_help_form_remains_reviewable(tmp_path: Path) -> None:
    """Reject an explicitly disabled help flag as a safe-form bypass."""

    command = " ".join(AZURE_DESTRUCTIVE_COMMAND_PATHS[0])
    assert_review_required_cases(
        (f"az {command} fixture --help --help=false",),
        tmp_path,
    )


def test_azure_safe_segment_cannot_hide_later_destructive_segment(tmp_path: Path) -> None:
    """Keep a later destructive shell segment visible after an earlier help segment."""

    first = " ".join(AZURE_DESTRUCTIVE_COMMAND_PATHS[0])
    second = " ".join(AZURE_DESTRUCTIVE_COMMAND_PATHS[1])
    assert_review_required_cases(
        (f"az {first} --help && az {second} fixture --yes",),
        tmp_path,
    )


def test_azure_quoted_examples_remain_data(tmp_path: Path) -> None:
    """Avoid classifying printed or searched Azure examples as executions."""

    command = " ".join(AZURE_DESTRUCTIVE_COMMAND_PATHS[0])
    assert_safe_command_cases(
        (
            f"printf '%s\\n' 'az {command} fixture'",
            f"grep 'az {command}' scripts/cloud-audit.sh",
        ),
        tmp_path,
    )


def test_azure_read_only_neighbors_remain_safe(tmp_path: Path) -> None:
    """Leave representative read-only Azure neighbors outside the delete rule."""

    assert_safe_command_cases(
        (
            "az group show --name fixture",
            "az resource list --subscription prod",
            "az network vnet show --name fixture --resource-group fixture",
            "az vm list --output json",
            "az monitor action-group show --name fixture --resource-group fixture",
        ),
        tmp_path,
    )
