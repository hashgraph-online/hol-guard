"""Static recognition for routine GitHub pull-request merges."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal

from .github_capability_contract import GitHubCommandAssessment, GitHubCommandCapability, github_assessment

ROUTINE_SQUASH_MERGE_DETAIL = (
    "The command performs a numeric, non-privileged squash merge and may clean up its merged head branch."
)
_MAX_PULL_REQUEST_NUMBER_DIGITS = 20
_MAX_REPOSITORY_LENGTH = 255
_STATIC_REPOSITORY = re.compile(r"(?:[A-Za-z0-9.-]+/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
BOOLEAN_OPTION_TRUE_VALUES = frozenset({"1", "t", "T", "TRUE", "true", "True"})
BOOLEAN_OPTION_FALSE_VALUES = frozenset({"0", "f", "F", "FALSE", "false", "False"})
BooleanOptionState = Literal["absent", "true", "false", "invalid"]


def boolean_option_token_state(argument: str, option: str) -> BooleanOptionState:
    """Classify one CLI token as an absent, true, false, or invalid boolean flag."""

    if argument == option:
        return "true"
    prefix = f"{option}="
    if not argument.startswith(prefix):
        return "absent"
    value = argument.removeprefix(prefix)
    if value in BOOLEAN_OPTION_TRUE_VALUES:
        return "true"
    if value in BOOLEAN_OPTION_FALSE_VALUES:
        return "false"
    return "invalid"


def boolean_option_state(args: Sequence[str], option: str) -> BooleanOptionState:
    """Return the last well-formed boolean flag value, or invalid on a malformed token."""

    state: BooleanOptionState = "absent"
    for token in args:
        if token == "--":
            break
        token_state = boolean_option_token_state(token, option)
        if token_state == "absent":
            continue
        if token_state == "invalid":
            return "invalid"
        state = token_state
    return state


def _is_positive_pull_request(value: str) -> bool:
    return value.isascii() and value.isdigit() and len(value) <= _MAX_PULL_REQUEST_NUMBER_DIGITS and int(value) > 0


def _is_static_repository(value: str) -> bool:
    return len(value) <= _MAX_REPOSITORY_LENGTH and _STATIC_REPOSITORY.fullmatch(value) is not None


def is_routine_squash_merge(args: Sequence[str]) -> bool:
    """Accept one numeric PR, squash mode, optional head cleanup, and an optional static repository."""

    pull_request: str | None = None
    repository: str | None = None
    squash = False
    delete_branch = False
    index = 0
    while index < len(args):
        argument = args[index]
        delete_state = boolean_option_token_state(argument, "--delete-branch")
        if argument == "--squash":
            if squash:
                return False
            squash = True
        elif delete_state != "absent":
            if delete_state == "invalid" or delete_branch:
                return False
            delete_branch = True
        elif argument in {"--repo", "-R"}:
            if repository is not None or index + 1 >= len(args):
                return False
            index += 1
            repository = args[index]
            if not _is_static_repository(repository):
                return False
        elif argument.startswith("--repo=") or argument.startswith("-R="):
            if repository is not None:
                return False
            repository = argument.split("=", maxsplit=1)[1]
            if not _is_static_repository(repository):
                return False
        elif pull_request is None and _is_positive_pull_request(argument):
            pull_request = argument
        else:
            return False
        index += 1
    return pull_request is not None and squash


def classify_pr_merge(tail: Sequence[str]) -> GitHubCommandAssessment:
    """Classify `gh pr merge` arguments, including boolean delete-branch and admin flags."""

    if is_routine_squash_merge(tail):
        return github_assessment(
            "routine_merge_remote",
            "github.command.pr-routine-squash-merge",
            ROUTINE_SQUASH_MERGE_DETAIL,
        )
    admin_state = boolean_option_state(tail, "--admin")
    delete_state = boolean_option_state(tail, "--delete-branch")
    if admin_state == "invalid":
        return github_assessment(
            "unknown",
            "github.command.invalid-admin-option",
            "The administrator merge option has an invalid Boolean value.",
        )
    if delete_state == "invalid":
        return github_assessment(
            "unknown",
            "github.command.invalid-delete-branch-option",
            "The delete-branch option has an invalid Boolean value.",
        )
    admin_merge = admin_state == "true"
    merge_capability: GitHubCommandCapability = "admin_merge_remote" if admin_merge else "merge_remote"
    capabilities: tuple[GitHubCommandCapability, ...] = (merge_capability,)
    if delete_state == "true":
        capabilities = (*capabilities, "delete_remote")
    return github_assessment(
        capabilities,
        "github.command.pr-admin-merge" if admin_merge else "github.command.pr-merge",
        (
            "The command uses administrator privileges to merge a pull request."
            if admin_merge
            else "The command merges a pull request and may also delete its branch."
        ),
    )
