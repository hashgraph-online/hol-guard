"""Separate a bounded literal shell payload from a mutable script-file launch."""

from __future__ import annotations

import shlex

# These are parser-supported transparent shells, not command permission grants.
_TRANSPARENT_SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh"})
_MAX_WRAPPER_BYTES = 8192


def literal_shell_read_payload(command_text: str) -> str:
    """Unwrap one exact literal invocation; retain ambiguous launches for review.

    The caller still classifies every payload operation. No command receives an
    allow decision here. Extra shell options, positional arguments, environment
    changes and expansions remain subject to the raw shell execution floor.
    """

    if len(command_text.encode("utf-8")) > _MAX_WRAPPER_BYTES or any(
        char in command_text for char in ("$", "`", "\n", "\r")
    ):
        return command_text
    try:
        tokens = shlex.split(command_text, posix=True, comments=False)
    except ValueError:
        return command_text
    if len(tokens) != 3 or tokens[0] not in _TRANSPARENT_SHELLS or tokens[1] not in {"-c", "-lc"}:
        return command_text
    return tokens[2]
