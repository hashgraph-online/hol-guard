"""Quote an argv for the Windows PowerShell a harness runs a shell command in.

Each argument becomes one single-quoted PowerShell literal and the call
operator starts the program. Inside a single-quoted literal PowerShell expands
nothing: ``$``, backticks, ``%``, ``&``, ``;``, ``|`` and parentheses are plain
text. Only the quote characters end it, and PowerShell reads the typographic
single quotes as quotes too, so each of them is doubled like ``'``.

Windows PowerShell 5.1 then rebuilds a native command line from the literals.
It drops an empty argument, cannot carry a double quote through, and leaves a
trailing backslash in front of the closing quote of an argument that contains
whitespace. Arguments that hit those cases, and control characters, are
refused so the caller keeps the original command instead of a changed one.
"""

from __future__ import annotations

from collections.abc import Sequence

_SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b"


def _quotable(argument: str) -> bool:
    if not argument or '"' in argument:
        return False
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in argument):
        return False
    return not (argument.endswith("\\") and any(char.isspace() for char in argument))


def powershell_join(argv: Sequence[str]) -> str | None:
    """The PowerShell command line that runs ``argv``, or ``None`` if it cannot be quoted."""

    if not argv or not all(_quotable(argument) for argument in argv):
        return None
    quoted = [
        "'" + "".join(char * 2 if char in _SINGLE_QUOTES else char for char in argument) + "'" for argument in argv
    ]
    return "& " + " ".join(quoted)
