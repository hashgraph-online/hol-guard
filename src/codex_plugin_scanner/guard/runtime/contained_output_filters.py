"""Output filters after a contained core, as native authority classifies them.

A chain of up to three `| head -N`, `| tail -N` and `| grep` stages that read
only standard input. Head and tail run in-process. Grep runs as the system
binary on the captured output with a validated argument list: no file
operand, pattern file, recursion or other output, so it can only print lines
of the text it is given. `contained_output_filters.rs` accepts the same chain.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

MAX_FILTERS = 3
_COUNT = re.compile(r"[0-9]{1,6}")
# Single-letter switches that change only which input lines print and how.
_GREP_SWITCHES = frozenset("EFGacinosvwx")
_GREP_COUNTS = ("-A", "-B", "-C", "-m")
_GREP_PROGRAMS = {"grep": (), "egrep": ("-E",), "fgrep": ("-F",)}
_GREP_BINARIES = (Path("/usr/bin/grep"), Path("/bin/grep"))
_LOCALE = ("LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE")
_GREP_TIMEOUT_SECONDS = 60

Stage = tuple[str, ...]


def bounded_count(values: list[str]) -> int | None:
    """The line count of a `head`/`tail` stage: `-N` or `-n N`."""
    if len(values) == 1 and values[0].startswith("-") and _COUNT.fullmatch(values[0][1:]):
        return int(values[0][1:])
    if len(values) == 2 and values[0] == "-n" and _COUNT.fullmatch(values[1]):
        return int(values[1])
    return None


def grep_arguments(values: list[str]) -> bool:
    """Whether `grep <values>` reads only standard input.

    Switches from `_GREP_SWITCHES`, counted options, `-e PATTERN`, and one
    pattern operand unless `-e` gave the patterns. Any further operand is a
    file, so it is refused.
    """
    expressions = operands = 0
    options_done = False
    index = 0
    while index < len(values):
        value = values[index]
        index += 1
        if value == "-":
            return False
        if options_done or not value.startswith("-"):
            operands += 1
            continue
        if value == "--":
            options_done = True
            continue
        if value == "-e":
            if index >= len(values):
                return False
            index += 1
            expressions += 1
            continue
        option = next((option for option in _GREP_COUNTS if value.startswith(option)), None)
        if option is not None:
            count = value[len(option) :]
            if not count:
                if index >= len(values):
                    return False
                count = values[index]
                index += 1
            if not _COUNT.fullmatch(count):
                return False
            continue
        switches = value[1:]
        if not switches or not set(switches) <= _GREP_SWITCHES:
            return False
    return operands == 0 if expressions else operands == 1


def filter_chain(tokens: list[tuple[str, bool]]) -> tuple[Stage, ...]:
    """The stages after a core's first `|`, or ValueError for any other shape."""
    stages: list[list[str]] = [[]]
    for value, operator in tokens:
        if (value, operator) == ("|", True):
            stages.append([])
        elif operator:
            raise ValueError("unsupported output filter")
        else:
            stages[-1].append(value)
    if len(stages) > MAX_FILTERS:
        raise ValueError("unsupported output filter")
    chain: list[Stage] = []
    for program, *arguments in (stage or [""] for stage in stages):
        if program in {"head", "tail"} and (count := bounded_count(arguments)) is not None:
            chain.append((program, str(count)))
        elif program in _GREP_PROGRAMS and grep_arguments(arguments):
            chain.append((program, *arguments))
        else:
            raise ValueError("unsupported output filter")
    return tuple(chain)


def keep_lines(lines: list[str], kind: str, count: int) -> list[str]:
    if kind == "head":
        return lines[:count]
    return lines[len(lines) - count :] if count else []


def _trusted_grep() -> str:
    """The system grep: a root-owned regular file nobody else can rewrite."""
    for candidate in _GREP_BINARIES:
        try:
            info = candidate.stat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022:
            return str(candidate)
    raise RuntimeError("no trusted system grep")


def _grep(text: str, stage: Stage) -> tuple[str, str, int]:
    program, *arguments = stage
    if program not in _GREP_PROGRAMS or not grep_arguments(arguments):
        raise ValueError("unsupported output filter")
    environment = {"PATH": "/usr/bin:/bin"}
    environment.update({name: os.environ[name] for name in _LOCALE if name in os.environ})
    completed = subprocess.run(  # fixed binary, validated stdin-only arguments
        [_trusted_grep(), *_GREP_PROGRAMS[program], *arguments],
        input=text.encode("utf-8", "surrogateescape"),
        capture_output=True,
        env=environment,
        timeout=_GREP_TIMEOUT_SECONDS,
        check=False,
    )
    return (
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
        completed.returncode,
    )


def apply_filters(text: str, stages: tuple[Stage, ...]) -> tuple[str, str, int]:
    """Run the chain over `text`: (output, grep diagnostics, last stage's status)."""
    errors: list[str] = []
    status = 0
    for stage in stages:
        if stage[0] in {"head", "tail"}:
            text = "".join(keep_lines(text.splitlines(keepends=True), stage[0], int(stage[1])))
            status = 0
            continue
        text, error, status = _grep(text, stage)
        errors.append(error)
    return text, "".join(errors), status
