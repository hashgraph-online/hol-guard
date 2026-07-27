"""Static recognition for routine GitHub pull-request merges."""

from __future__ import annotations

from collections.abc import Sequence

ROUTINE_SQUASH_MERGE_DETAIL = "The command performs a numeric, non-privileged squash merge."


def is_routine_squash_merge(args: Sequence[str]) -> bool:
    """Accept only a positive numeric pull request followed by ``--squash``."""

    if len(args) != 2 or args[1] != "--squash":
        return False
    pull_request = args[0]
    return pull_request.isascii() and pull_request.isdigit() and int(pull_request) > 0
