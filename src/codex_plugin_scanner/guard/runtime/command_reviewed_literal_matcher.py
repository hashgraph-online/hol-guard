"""The grammar an author's reviewed literal invocation has to be written in.

Matching a reviewed literal belongs to the runtime's ``reviewed-literal.v1``
matcher. What stays here is the authoring-time spelling check: a bounded
basename, one to sixteen literal argument tokens, and no shell syntax,
expansion, wrapper or environment override anywhere in them.
"""

from __future__ import annotations

import re

_EXECUTABLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}")
_LITERAL_ARGUMENT = re.compile(
    r"(?:--?|--?[A-Za-z0-9][A-Za-z0-9_.-]*(?:=[A-Za-z0-9][A-Za-z0-9._:/@+-]*)?"
    r"|[A-Za-z0-9][A-Za-z0-9._:/@+-]*)"
)


def validate_reviewed_literal_argv(executable: str, arguments: tuple[str, ...]) -> str:
    """Validate a narrow literal grammar and return its one supported spelling."""
    if not isinstance(executable, str) or _EXECUTABLE.fullmatch(executable) is None:
        raise ValueError("Reviewed literal executable must be a bounded basename")
    if not isinstance(arguments, tuple) or not 1 <= len(arguments) <= 16:
        raise ValueError("Reviewed literal invocation needs one to sixteen argument tokens")
    if any(
        not isinstance(argument, str) or len(argument) > 64 or _LITERAL_ARGUMENT.fullmatch(argument) is None
        for argument in arguments
    ):
        raise ValueError("Reviewed literal arguments cannot contain shell syntax or expansions")
    expected = " ".join((executable, *arguments))
    if len(expected) > 120:
        raise ValueError("Reviewed literal invocation exceeds the command example limit")
    return expected
