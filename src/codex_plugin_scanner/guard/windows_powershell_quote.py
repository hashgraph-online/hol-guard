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

Codex runs each call in the shell the model picked for it, PowerShell or Git
Bash. ``sink_command_line`` first writes the argv in the subset both read the
same way: a bare drive path with forward slashes for the program, then
single-quoted arguments holding no quote character. Neither shell expands
anything inside such a literal. The bootstrap's package root moves out of its
Python string literal into the argument after it, so the code holds no quote.
Only an argv that subset cannot carry falls back to ``powershell_join``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

_SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b"
_BOOTSTRAP_HEAD = "import sys;sys.path.insert(0, "
_BOOTSTRAP_TAIL = ");from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))"
_ARGV_BOOTSTRAP = (
    "import sys;sys.path.insert(0,sys.argv.pop(1));from codex_plugin_scanner.cli import main;"
    "raise SystemExit(main(sys.argv[1:]))"
)
_BARE_PROGRAM = re.compile(r"[A-Za-z]:/[A-Za-z0-9._/-]+")


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


def _argv_bootstrap(argv: Sequence[str]) -> list[str] | None:
    if len(argv) < 4 or argv[1] != "-I" or argv[2] != "-c":
        return list(argv)
    code = argv[3]
    if not (code.startswith(_BOOTSTRAP_HEAD) and code.endswith(_BOOTSTRAP_TAIL)):
        return None
    literal = code[len(_BOOTSTRAP_HEAD) : -len(_BOOTSTRAP_TAIL)]
    if len(literal) < 2 or literal[0] != "'" or literal[-1] != "'":
        return None
    root = literal[1:-1]
    if "\\" in root or "'" in root:
        return None
    return [argv[0], "-I", "-c", _ARGV_BOOTSTRAP, root, *argv[4:]]


def _either_shell_join(argv: Sequence[str]) -> str | None:
    moved = _argv_bootstrap(argv)
    if not moved:
        return None
    program = moved[0].replace("\\", "/")
    if _BARE_PROGRAM.fullmatch(program) is None:
        return None
    arguments = moved[1:]
    if not all(_quotable(argument) and not any(char in _SINGLE_QUOTES for char in argument) for argument in arguments):
        return None
    return " ".join([program, *("'" + argument + "'" for argument in arguments)])


def sink_command_line(argv: Sequence[str]) -> str | None:
    """The Windows sink command line both of Codex's shells read, else the PowerShell one."""

    return _either_shell_join(argv) or powershell_join(argv)
