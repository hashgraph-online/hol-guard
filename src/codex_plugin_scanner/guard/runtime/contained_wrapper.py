"""Peel the cd prefix and bounded output filter that native authority classified."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .restricted_pytest_validation import _path_is_within

_COUNT = re.compile(r"[0-9]{1,6}")
_SUFFIX = re.compile(r"(?:\s+2>&1)?\s*\|\s*(?:tail|head)\s+(?:-[0-9]{1,6}|-n\s+[0-9]{1,6})\s*\Z")


def output_filter_suffix(command: str) -> str:
    """The bounded filter to keep on the routed sink, so output stays as requested."""
    match = _SUFFIX.search(command)
    return match.group(0) if match is not None else ""


def _unquote(token: str) -> str:
    words = shlex.split(token, posix=True)
    if len(words) != 1:
        raise ValueError("unsupported word")
    return words[0]


def _bounded_filter(arguments: list[str]) -> bool:
    if len(arguments) == 1:
        return arguments[0].startswith("-") and _COUNT.fullmatch(arguments[0][1:]) is not None
    return len(arguments) == 2 and arguments[0] == "-n" and _COUNT.fullmatch(arguments[1]) is not None


def peel_contained_wrapper(command: str, *, workspace: Path) -> tuple[str, Path] | None:
    """Return the core command and its directory, or None when nothing is wrapped.

    Raises ValueError (or OSError for a missing cd target) for shapes native authority never upgrades.
    """
    # Non-POSIX mode keeps quotes, so a quoted "|" is never mistaken for an operator.
    lexer = shlex.shlex(command, posix=False, punctuation_chars=True)
    lexer.whitespace_split = True
    tokens = list(lexer)
    directory = workspace
    wrapped = False
    if tokens[:1] == ["cd"]:
        if len(tokens) < 4 or tokens[2] != "&&":
            raise ValueError("unsupported cd prefix")
        target = Path(_unquote(tokens[1]))
        if not target.is_absolute():
            raise ValueError("relative cd target")
        directory = target.resolve(strict=True)
        if not directory.is_dir() or not _path_is_within(directory, workspace.resolve(strict=True)):
            raise ValueError("cd target outside the workspace")
        tokens, wrapped = tokens[3:], True
    if "|" in tokens:
        index = tokens.index("|")
        if tokens[index + 1 : index + 2] not in (["tail"], ["head"]) or not _bounded_filter(tokens[index + 2 :]):
            raise ValueError("unsupported output filter")
        tokens = tokens[:index]
        if tokens[-3:] == ["2", ">&", "1"]:
            tokens = tokens[:-3]
        wrapped = True
    if not wrapped:
        return None
    if not tokens or any(set(token) & set("();<>|&") for token in tokens):
        raise ValueError("unsupported wrapper shape")
    return shlex.join(_unquote(token) for token in tokens), directory
