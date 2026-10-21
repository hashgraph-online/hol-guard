"""Peel the inert command prefixes and settings that native authority classified."""

from __future__ import annotations

import math
import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

# Mirrors the native inert-assignment allowlist: these names change output or
# presentation, never which program runs or what it loads.
_INERT_ENVIRONMENT_NAMES = frozenset(
    {
        "CI",
        "NODE_ENV",
        "FORCE_COLOR",
        "NO_COLOR",
        "CLICOLOR",
        "CLICOLOR_FORCE",
        "TERM",
        "TZ",
        "LANG",
        "LANGUAGE",
        "COLUMNS",
        "LINES",
        "DEBUG",
        "NODE_NO_WARNINGS",
        "RUST_LOG",
        "RUST_BACKTRACE",
        "PYTHONUNBUFFERED",
        "PYTHONDONTWRITEBYTECODE",
    }
)


def _inert_assignment(word: str) -> tuple[str, str] | None:
    name, separator, value = word.partition("=")
    if (
        separator
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
        and (name in _INERT_ENVIRONMENT_NAMES or name.startswith("LC_"))
    ):
        return name, value
    return None


def _data_assignment(word: str) -> bool:
    name, separator, value = word.partition("=")
    return bool(
        separator
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
        and name not in {"PYTHONPATH", "VIRTUAL_ENV", "NODE_PATH", "TMPDIR", "TMP", "TEMP"}
        and len(value) <= 512
        and re.fullmatch(r"(?!-)[A-Za-z0-9/._+@:,%-]*", value)
    )


def _split_command_prefix(command: list[str], *, drop_data: bool = False) -> tuple[list[str], dict[str, str]]:
    """Peel `command`/`time`/`env` prefixes and inert `NAME=value` assignments.

    The native model reads `CI=1 command bun run build` as `bun run build`
    with an inert assignment. With `drop_data`, a plain-data setting
    (`REPORT_DIR=/tmp/r`) is dropped too: callers do so only after the
    original drew a contained receipt, since native authority grants a
    read-only profile only when that profile's environment filter would drop
    the setting, and a workspace receipt still runs the original as issued.
    An option such as `command -v` or `env -i` keeps its prefix, and any
    other assignment stays in the command, so the core is rejected.
    """
    assignments: dict[str, str] = {}
    for _ in range(16):
        if len(command) > 1 and command[0] in {"command", "time", "env"} and not command[1].startswith("-"):
            command = command[1:]
        elif command and (assignment := _inert_assignment(command[0])) is not None:
            assignments[assignment[0]] = assignment[1]
            command = command[1:]
        elif drop_data and len(command) > 1 and _data_assignment(command[0]):
            command = command[1:]
        else:
            break
    return command, assignments


def _peel_for_receipt(command: list[str]) -> tuple[list[str], dict[str, str], bool]:
    """Peel with data settings dropped, and say whether one was dropped.

    A dropped setting means the core is not the command as issued, so the
    original must draw a contained receipt before the core runs.
    """
    core, assignments = _split_command_prefix(command, drop_data=True)
    return core, assignments, core != _split_command_prefix(command)[0]


@contextmanager
def _assignments_applied(assignments: Mapping[str, str]) -> Iterator[None]:
    """Export the assignments to the runner's source environment for one run.

    Each restricted profile still filters that environment, exactly as it
    filters a variable the agent's shell exported.
    """
    previous = {name: os.environ.get(name) for name in assignments}
    os.environ.update(assignments)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


# The shell resolves a bare `timeout` on `PATH`, and the two system paths name
# that same program. `./timeout` or `bin/timeout` is whatever that file holds,
# so native authority leaves it wrapped and this peel does not read it either.
_SYSTEM_TIMEOUT = frozenset({"timeout", "/usr/bin/timeout", "/bin/timeout"})
_CLOCK_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _clock_seconds(value: str) -> int | None:
    """Seconds in a duration `timeout` reads, mirroring the native reader.

    A number of seconds, or one carrying an `s`, `m`, `h` or `d` unit, with an
    optional fraction. Anything else is not a duration, so the word after it is
    not the program and the command is not peeled. A duration of zero turns
    `timeout` off, and this answers `0` for it: the prefix is still peeled, and
    the run it names is left unbounded rather than cut to a second.
    """
    number = value[:-1] if value[-1:] in _CLOCK_UNITS else value
    whole, _, fraction = number.partition(".")
    digits = set("0123456789")
    if not number or len(number) > 10 or not whole or not set(whole) <= digits:
        return None
    if fraction and not set(fraction) <= digits:
        return None
    unit = _CLOCK_UNITS.get(value[-1:], 1) if value[-1:] in _CLOCK_UNITS else 1
    duration = float(number) * unit
    # Seconds are whole here, so a fractional duration rounds up: cutting
    # `timeout 2.1` to two would end the run before the clock it was given.
    # Only an exact zero means no bound at all.
    return 0 if duration == 0 else math.ceil(duration)


def peel_timeout_clock(command: list[str]) -> tuple[list[str], int | None]:
    """Peel a system `timeout <duration>` prefix and report its seconds.

    The seconds are ``None`` when nothing bounds the run: either no prefix was
    peeled, or every peeled clock was the zero that turns `timeout` off.

    Native authority reads that clock through to the program it bounds, because
    it limits how long the work may take and not what it may do. The contained
    planners are handed the program the text already names, so `timeout 20
    pytest -q` reaches the same read-only profile as `pytest -q`, and the clock
    still bounds the run it is peeled from.
    """
    seconds: int | None = None
    for _ in range(4):
        if len(command) < 3 or command[0] not in _SYSTEM_TIMEOUT:
            break
        rest = command[1:]
        if rest[0] == "--":
            rest = rest[1:]
        if len(rest) < 2:
            break
        clock = _clock_seconds(rest[0])
        program = rest[1]
        if clock is None or not program or program.startswith("-") or _assignment_word(program):
            break
        if clock:
            seconds = clock if seconds is None else min(seconds, clock)
        command = rest[1:]
    return command, seconds


def _assignment_word(word: str) -> bool:
    name, separator, _ = word.partition("=")
    return bool(separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))
