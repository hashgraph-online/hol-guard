"""Safety checks for read-only jq output processors."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

_FILE_OPTIONS: Final = frozenset(
    {"-f", "-L", "--argfile", "--from-file", "--library-path", "--rawfile", "--run-tests", "--slurpfile"}
)
_SAFE_SHORT_OPTION_CHARACTERS: Final = frozenset("RacenrSsjMC")
_SAFE_LONG_OPTIONS: Final = frozenset(
    {
        "--ascii-output",
        "--compact-output",
        "--exit-status",
        "--join-output",
        "--monochrome-output",
        "--null-input",
        "--raw-input",
        "--raw-output",
        "--seq",
        "--slurp",
        "--sort-keys",
        "--tab",
        "--unbuffered",
    }
)


def safe_jq_arguments(arguments: Sequence[str]) -> bool:
    filter_seen = False
    for argument in arguments:
        if (
            argument in _FILE_OPTIONS
            or argument.startswith("-L")
            or any(argument.startswith(f"{option}=") for option in _FILE_OPTIONS)
        ):
            return False
        if not filter_seen and argument in _SAFE_LONG_OPTIONS:
            continue
        if (
            not filter_seen
            and argument.startswith("-")
            and len(argument) > 1
            and all(character in _SAFE_SHORT_OPTION_CHARACTERS for character in argument[1:])
        ):
            continue
        if argument.startswith("-"):
            return False
        if filter_seen:
            return False
        filter_seen = True
    return filter_seen
