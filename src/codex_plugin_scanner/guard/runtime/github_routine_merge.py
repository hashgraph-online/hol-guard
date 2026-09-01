"""Static recognition for routine GitHub pull-request merges."""

from __future__ import annotations

import re
from collections.abc import Sequence

ROUTINE_SQUASH_MERGE_DETAIL = (
    "The command performs a numeric, non-privileged squash merge and may clean up its merged head branch."
)
_MAX_PULL_REQUEST_NUMBER_DIGITS = 20
_MAX_REPOSITORY_LENGTH = 255
_STATIC_REPOSITORY = re.compile(r"(?:[A-Za-z0-9.-]+/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_TRUE_OPTION_VALUES = frozenset({"1", "t", "T", "TRUE", "true", "True"})
_FALSE_OPTION_VALUES = frozenset({"0", "f", "F", "FALSE", "false", "False"})


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
        if argument == "--squash":
            if squash:
                return False
            squash = True
        elif argument == "--delete-branch" or argument.startswith("--delete-branch="):
            if delete_branch:
                return False
            if argument.startswith("--delete-branch="):
                value = argument.split("=", maxsplit=1)[1]
                if value not in _TRUE_OPTION_VALUES and value not in _FALSE_OPTION_VALUES:
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
