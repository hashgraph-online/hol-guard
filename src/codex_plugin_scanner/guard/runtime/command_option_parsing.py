"""Conservative option parsing for destructive command matchers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Final

_MAX_OPTION_PARSE_STATES: Final = 16_384
_TRUTHY_FLAG_VALUES: Final = frozenset({"1", "on", "true", "yes"})


class _ParseOutcome(Enum):
    MATCH = auto()
    NO_MATCH = auto()
    UNCERTAIN = auto()


@dataclass(frozen=True, slots=True)
class _OptionTransition:
    advance: int
    flag_assignments: frozenset[tuple[str, bool]] = frozenset()


@dataclass(frozen=True, slots=True)
class _OptionShape:
    transitions: tuple[_OptionTransition, ...]
    fully_known: bool


def matches_subcommands_conservatively(
    arguments: tuple[str, ...],
    subcommands: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> bool:
    """Match a destructive prefix, including when bounded parsing is uncertain."""

    outcome = _subcommand_parse_outcome(
        arguments,
        subcommands,
        options_with_values=options_with_values,
        known_flags=known_flags,
    )
    return outcome is not _ParseOutcome.NO_MATCH


def flags_present_in_all_option_parses(
    arguments: tuple[str, ...],
    required_flags: frozenset[str],
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> bool:
    """Return whether every bounded parse certainly contains each required flag."""

    return all(
        _flag_parse_outcome(
            arguments,
            required_flag,
            options_with_values=options_with_values,
            known_flags=known_flags,
        )
        is _ParseOutcome.MATCH
        for required_flag in required_flags
    )


def known_option_advance(
    argument: str,
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> int | None:
    """Return the deterministic token advance for a fully known option shape."""

    if not _is_option(argument):
        return None
    shape = _option_shape(
        argument,
        options_with_values=options_with_values,
        known_flags=known_flags,
    )
    advances = {transition.advance for transition in shape.transitions}
    if not shape.fully_known or len(advances) != 1:
        return None
    return advances.pop()


def long_flag_assignment_is_enabled(argument: str) -> bool:
    """Return whether a long flag is bare or explicitly assigned a truthy value."""

    _option_name, separator, value = argument.partition("=")
    return not separator or value.lower() in _TRUTHY_FLAG_VALUES


def _subcommand_parse_outcome(
    arguments: tuple[str, ...],
    subcommands: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> _ParseOutcome:
    pending = [(0, 0)]
    visited: set[tuple[int, int]] = set()
    while pending:
        state = pending.pop()
        if state in visited:
            continue
        if len(visited) >= _MAX_OPTION_PARSE_STATES:
            return _ParseOutcome.UNCERTAIN
        visited.add(state)
        argument_index, subcommand_index = state
        if subcommand_index == len(subcommands):
            return _ParseOutcome.MATCH
        if argument_index >= len(arguments):
            continue
        argument = arguments[argument_index]
        if argument == "--":
            remaining = len(subcommands) - subcommand_index
            if arguments[argument_index + 1 : argument_index + 1 + remaining] == subcommands[subcommand_index:]:
                return _ParseOutcome.MATCH
            continue
        if _is_option(argument):
            shape = _option_shape(
                argument,
                options_with_values=options_with_values,
                known_flags=known_flags,
            )
            pending.extend((argument_index + transition.advance, subcommand_index) for transition in shape.transitions)
            continue
        if argument == subcommands[subcommand_index]:
            pending.append((argument_index + 1, subcommand_index + 1))
    return _ParseOutcome.NO_MATCH


def _flag_parse_outcome(
    arguments: tuple[str, ...],
    required_flag: str,
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> _ParseOutcome:
    pending: list[tuple[int, bool | None]] = [(0, None)]
    visited: set[tuple[int, bool | None]] = set()
    found_terminal = False
    while pending:
        state = pending.pop()
        if state in visited:
            continue
        if len(visited) >= _MAX_OPTION_PARSE_STATES:
            return _ParseOutcome.UNCERTAIN
        visited.add(state)
        argument_index, final_assignment = state
        if argument_index >= len(arguments) or arguments[argument_index] == "--":
            if final_assignment is not True:
                return _ParseOutcome.NO_MATCH
            found_terminal = True
            continue
        argument = arguments[argument_index]
        if not _is_option(argument):
            pending.append((argument_index + 1, final_assignment))
            continue
        shape = _option_shape(
            argument,
            options_with_values=options_with_values,
            known_flags=known_flags,
        )
        for transition in shape.transitions:
            next_assignment = final_assignment
            for flag, enabled in transition.flag_assignments:
                if flag == required_flag:
                    next_assignment = enabled
            pending.append((argument_index + transition.advance, next_assignment))
    return _ParseOutcome.MATCH if found_terminal else _ParseOutcome.NO_MATCH


def _option_shape(
    argument: str,
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> _OptionShape:
    if argument.startswith("--"):
        option_name, separator, _value = argument.partition("=")
        if option_name in options_with_values:
            advance = 1 if separator else 2
            return _OptionShape((_OptionTransition(advance),), fully_known=True)
        if option_name in known_flags:
            enabled = long_flag_assignment_is_enabled(argument)
            assignments = frozenset({(argument, True), (option_name, enabled)})
            return _OptionShape((_OptionTransition(1, assignments),), fully_known=True)
        if separator:
            return _OptionShape((_OptionTransition(1),), fully_known=True)
        return _OptionShape((_OptionTransition(1), _OptionTransition(2)), fully_known=False)
    return _short_option_shape(
        argument,
        options_with_values=options_with_values,
        known_flags=known_flags,
    )


def _short_option_shape(
    argument: str,
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> _OptionShape:
    transitions: set[_OptionTransition] = set()
    flags: set[str] = set()
    fully_known = True
    for index, character in enumerate(argument[1:], start=1):
        short_option = f"-{character}"
        if short_option in options_with_values:
            advance = 1 if index + 1 < len(argument) else 2
            assignments = frozenset((flag, True) for flag in flags)
            transitions.add(_OptionTransition(advance, assignments))
            return _OptionShape(tuple(transitions), fully_known=fully_known)
        if short_option in known_flags:
            flags.add(short_option)
            continue
        fully_known = False
        assignments = frozenset((flag, True) for flag in flags)
        transitions.add(_OptionTransition(1, assignments))
        if index + 1 == len(argument):
            transitions.add(_OptionTransition(2, assignments))
    assignments = frozenset((flag, True) for flag in flags)
    transitions.add(_OptionTransition(1, assignments))
    return _OptionShape(tuple(transitions), fully_known=fully_known)


def _is_option(argument: str) -> bool:
    return len(argument) > 1 and argument.startswith("-")
