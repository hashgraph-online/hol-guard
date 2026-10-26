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


def _peel_transparent_prefix(command: list[str], assignments: dict[str, str], *, drop_data: bool) -> list[str] | None:
    """Peel a prefix that only hands the program its own settings, as native reads it.

    Native authority owns that grammar — which names stand transparently in
    front of a program, and which words between the name and the program
    belong to it — so the sink asks it where the program stands and keeps no
    list of the names itself. A second copy of that list is what drift looks
    like: the parser reads `/usr/bin/env` and `/bin/env` as the `env` they
    are, while the copy here held only the bare spelling, so
    `/usr/bin/env CI=1 pytest -q` reached the planners with `/usr/bin/env` as
    its program and was refused, though native authority had already read it
    as the `pytest -q` it runs. The copy also peeled a bare `env pytest`,
    which the parser deliberately leaves alone — `env` with no assignment
    only bypasses shell functions, and extension floors key on that spelling
    — so the sink planned a program native authority had not judged.

    The settings the prefix carries stay the sink's own business. Each one
    must still be an inert assignment, which the runner exports to its source
    environment for the run, or, with `drop_data`, a plain-data setting the
    read-only profile would drop anyway. A word that is neither leaves the
    prefix in place, so the planners refuse the command rather than run its
    program with a setting nobody filtered.

    Returns the command behind the prefix, or ``None`` when there is no
    prefix here to peel.
    """
    if len(command) < 2 or not command[0] or command[0].startswith("-") or _assignment_word(command[0]):
        return None
    from ..native_restricted_pytest import restricted_native

    index = restricted_native("transparent_prefix", {"command": command}, (int, type(None)))
    if type(index) is not int or not 0 < index < len(command):
        return None
    carried: dict[str, str] = {}
    for word in command[1:index]:
        if (assignment := _inert_assignment(word)) is not None:
            carried[assignment[0]] = assignment[1]
        elif not (drop_data and _data_assignment(word)):
            return None
    assignments.update(carried)
    return command[index:]


def _split_command_prefix(command: list[str], *, drop_data: bool = False) -> tuple[list[str], dict[str, str]]:
    """Peel the transparent prefixes native authority reads, and inert assignments.

    The native model reads `CI=1 command bun run build` as `bun run build`
    with an inert assignment. With `drop_data`, a plain-data setting
    (`REPORT_DIR=/tmp/r`) is dropped too: callers do so only after the
    original drew a contained receipt, since native authority grants a
    read-only profile only when that profile's environment filter would drop
    the setting, and a workspace receipt still runs the original as issued.
    An option such as `command -v` or `env -i` keeps its prefix, and any
    other assignment stays in the command, so the core is rejected.

    An assignment is read here before the prefix is asked about, because a
    word carrying `=` is no prefix name and the answer would be the same.
    """
    assignments: dict[str, str] = {}
    for _ in range(16):
        if command and (assignment := _inert_assignment(command[0])) is not None:
            assignments[assignment[0]] = assignment[1]
            command = command[1:]
        elif drop_data and len(command) > 1 and _data_assignment(command[0]):
            command = command[1:]
        elif (peeled := _peel_transparent_prefix(command, assignments, drop_data=drop_data)) is not None:
            command = peeled
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


def _peel_launcher(command: list[str]) -> list[str]:
    """The program a system launcher runs, as the native parser reads it.

    Native authority owns that grammar — which names are launchers, and where
    each one's options end — so the sink asks it for the program's position and
    keeps no list of the names itself. A second copy of that list is what drift
    looks like: the parser learned to read the shell's `exec` as a launcher
    while the copy here still held `nice` and `stdbuf`, so `exec pytest -q`
    reached the planners with `exec` as its program and was refused, though
    native authority had already read it as the `pytest -q` it runs.

    A launcher stands as a bare name in front of a program, so a command too
    short to hold both, or one whose first word is spelled as a path, is not
    one and is not asked about. Every other command is, and the parser answers
    for the names it reads. A launcher it leaves in place stays in place, and
    the planners refuse it.
    """
    if len(command) < 2 or not command[0] or "/" in command[0] or "\\" in command[0]:
        return command
    from ..native_restricted_pytest import restricted_native

    index = restricted_native("launcher_program", {"command": command}, (int, type(None)))
    return command[index:] if type(index) is int and 0 < index < len(command) else command


def peel_run_prefixes(command: list[str]) -> tuple[list[str], int | None]:
    """Peel the prefixes native authority reads through, and the tightest clock.

    A system `timeout`, and every launcher the native parser reads, run the
    program they name unchanged, so the planners are handed that program, as
    native authority is. Each peel is followed by the inert `command`/`env`
    prefix and assignment split the planners already receive. `nice` and
    `stdbuf` set only scheduling priority and stdio buffering, and the shell's
    `exec` replaces the shell process rather than forking one; the contained
    runner applies its own process limits and returns the output when the run
    ends, so none of them changes what the caller reads.
    """
    seconds: int | None = None
    for _ in range(4):
        timed, clock = peel_timeout_clock(command)
        if clock is not None:
            seconds = clock if seconds is None else min(seconds, clock)
        peeled = _peel_launcher(timed)
        if peeled == command:
            break
        command, _ = _split_command_prefix(peeled)
    return command, seconds
