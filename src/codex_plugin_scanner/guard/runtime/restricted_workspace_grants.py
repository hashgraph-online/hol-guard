"""Read grants of the workspace sandbox plan: scratch scripts outside the workspace."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

_SCRIPT_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})


def _launched(path: Path, command: str) -> bool:
    """The command carries an absolute word that names exactly this file."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        words = list(lexer)
    except ValueError:
        return False
    return any(word.startswith("/") and os.path.realpath(word) == str(path) for word in words)


def read_grants_valid(value: object, command: str) -> bool:
    """At most one script outside the workspace, which the command launches.

    The grant is one absolute, canonical, regular file; the native plan derived
    it from the command, so a file the command does not name is not one the plan
    can have earned. A second grant could let one script read another.
    """
    if not isinstance(value, list) or len(value) > 1:
        return False
    for item in value:
        if not isinstance(item, str) or not item.startswith("/") or "\0" in item:
            return False
        path = Path(item)
        if (
            path.is_symlink()
            or not path.is_file()
            or path.resolve() != path
            or path.suffix.lower() not in _SCRIPT_SUFFIXES
            or not _launched(path, command)
        ):
            return False
    return True
