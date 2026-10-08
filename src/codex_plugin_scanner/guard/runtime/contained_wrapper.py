"""Peel the cd prefix and bounded output filter that native authority classified."""

from __future__ import annotations

import contextlib
import io
import re
import shlex
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .restricted_pytest_validation import _path_is_within

_COUNT = re.compile(r"[0-9]{1,6}")
_MERGE = re.compile(r"2>&1(?=[ \t|]|\Z)")
_OPERATOR = frozenset("();<>|&\n")
# Characters the shell would expand; native authority only upgrades exact parses.
_UNQUOTED_EXPANSION = frozenset("$`*?[{")
_DOUBLE_QUOTED_ESCAPES = frozenset('$`"\\')
_ARGUMENT_REJECT = frozenset("<>|&;")


@dataclass(frozen=True)
class OutputFilter:
    """A trailing `| head|tail -N`, applied in-process to the contained output."""

    kind: str
    count: int
    merge_stderr: bool


def _lex(command: str) -> tuple[list[tuple[str, bool]], bool]:
    """Split like a POSIX shell into (value, is_operator) pairs; also report exactness.

    Quoted text is never an operator, so `'|'` or `'print(1)'` stay plain words.
    """
    tokens: list[tuple[str, bool]] = []
    word: list[str] | None = None
    exact = True
    index = 0

    def finish() -> None:
        nonlocal word
        if word is not None:
            tokens.append(("".join(word), False))
            word = None

    while index < len(command):
        character = command[index]
        if character in " \t":
            finish()
            index += 1
        elif word is None and _MERGE.match(command, index):
            tokens.append(("2>&1", True))
            index += 4
        elif character in _OPERATOR:
            finish()
            end = index
            while end < len(command) and command[end] in _OPERATOR:
                end += 1
            tokens.append((command[index:end], True))
            index = end
        elif character == "'":
            end = command.find("'", index + 1)
            if end < 0:
                raise ValueError("unterminated quote")
            word = [*(word or []), command[index + 1 : end]]
            index = end + 1
        elif character == '"':
            word = word or []
            index += 1
            while True:
                if index >= len(command):
                    raise ValueError("unterminated quote")
                character = command[index]
                if character == '"':
                    index += 1
                    break
                if character == "\\" and index + 1 < len(command) and command[index + 1] in _DOUBLE_QUOTED_ESCAPES:
                    index += 1
                    character = command[index]
                elif character == "\\" and command[index + 1 : index + 2] == "\n":
                    raise ValueError("line continuation")
                elif character in "$`":
                    exact = False
                word.append(character)
                index += 1
        elif character == "\\":
            if index + 1 >= len(command) or command[index + 1] == "\n":
                raise ValueError("unsupported escape")
            word = [*(word or []), command[index + 1]]
            index += 2
        else:
            if ord(character) < 32 or character in _UNQUOTED_EXPANSION or (word is None and character in "~#"):
                exact = False
            word = [*(word or []), character]
            index += 1
    finish()
    return tokens, exact


def _bounded_filter(arguments: list[tuple[str, bool]]) -> int | None:
    if any(operator for _value, operator in arguments):
        return None
    values = [value for value, _operator in arguments]
    if len(values) == 1 and values[0].startswith("-") and _COUNT.fullmatch(values[0][1:]):
        return int(values[0][1:])
    if len(values) == 2 and values[0] == "-n" and _COUNT.fullmatch(values[1]):
        return int(values[1])
    return None


def peel_contained_wrapper(command: str, *, workspace: Path) -> tuple[str, Path, OutputFilter | None] | None:
    """Return the core command, its directory, and output filter, or None when nothing is wrapped.

    Raises ValueError (or OSError for a missing cd target) for shapes native authority never upgrades.
    """
    tokens, exact = _lex(command)
    directory = workspace
    wrapped = False
    output = None
    if tokens[:1] == [("cd", False)]:
        if len(tokens) < 4 or tokens[1][1] or tokens[2] != ("&&", True):
            raise ValueError("unsupported cd prefix")
        target = Path(tokens[1][0])
        if not exact or not target.is_absolute():
            raise ValueError("relative cd target")
        directory = target.resolve(strict=True)
        if not directory.is_dir() or not _path_is_within(directory, workspace.resolve(strict=True)):
            raise ValueError("cd target outside the workspace")
        tokens, wrapped = tokens[3:], True
    if ("|", True) in tokens:
        index = tokens.index(("|", True))
        program = tokens[index + 1 : index + 2]
        count = _bounded_filter(tokens[index + 2 :])
        if program not in ([("tail", False)], [("head", False)]) or count is None:
            raise ValueError("unsupported output filter")
        tokens = tokens[:index]
        merge = tokens[-1:] == [("2>&1", True)]
        if merge:
            tokens = tokens[:-1]
        output = OutputFilter(program[0][0], count, merge)
        wrapped = True
    if not wrapped:
        return None
    if not exact or not tokens or any(operator or set(value) & _ARGUMENT_REJECT for value, operator in tokens):
        raise ValueError("unsupported wrapper shape")
    return shlex.join(value for value, _operator in tokens), directory, output


@contextlib.contextmanager
def bounded_output(output: OutputFilter | None) -> Iterator[None]:
    """Apply head/tail in-process; no external filter runs outside containment.

    The sandbox captures stdout and stderr separately, so with `2>&1` the merged
    stream is the run's stdout followed by its stderr, not their interleaving.
    """
    if output is None:
        yield
        return
    destination = sys.stdout
    captured = io.StringIO()
    errors = contextlib.redirect_stderr(captured) if output.merge_stderr else contextlib.nullcontext()
    try:
        with contextlib.redirect_stdout(captured), errors:
            yield
    finally:
        lines = captured.getvalue().splitlines(keepends=True)
        if output.kind == "head":
            kept = lines[: output.count]
        else:
            kept = lines[len(lines) - output.count :] if output.count else []
        destination.write("".join(kept))
        destination.flush()
