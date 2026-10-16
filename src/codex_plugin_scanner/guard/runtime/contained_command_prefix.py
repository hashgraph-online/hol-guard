"""Peel the inert command prefixes and settings that native authority classified."""

from __future__ import annotations

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
