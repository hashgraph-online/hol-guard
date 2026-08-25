"""Classify shell redirections attached to GitHub CLI commands."""

from __future__ import annotations

import re

_SAFE_DISCARD_TARGETS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "nul"})
_ATTACHED_SAFE_DISCARD = re.compile(
    r"\A[012]?(?:>>|>\||>|<)(/dev/(?:null|stdout|stderr)|nul)\Z",
    re.IGNORECASE,
)


def github_shell_args_and_redirection(segment: list[str], command_index: int) -> tuple[list[str], bool]:
    """Return GitHub argv plus whether a material local redirection remains."""

    args: list[str] = []
    has_redirection = False
    index = command_index + 1
    while index < len(segment):
        token = segment[index]
        if token in {"2>&1", "1>&2"} or _ATTACHED_SAFE_DISCARD.fullmatch(token):
            index += 1
            continue
        if token in {">", ">>", ">|", "<", "<<", "<<<"}:
            target = segment[index + 1] if index + 1 < len(segment) else ""
            safe_discard = token in {">", ">>", ">|", "<"} and target.casefold() in _SAFE_DISCARD_TARGETS
            has_redirection = has_redirection or not safe_discard
            index += 2
            continue
        if any(marker in token for marker in (">", "<")):
            has_redirection = True
            index += 1
            continue
        args.append(token)
        index += 1
    return args, has_redirection


__all__ = ["github_shell_args_and_redirection"]
