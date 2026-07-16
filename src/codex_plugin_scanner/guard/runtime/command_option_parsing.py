"""Conservative option parsing for destructive command matchers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Final

_MAX_OPTION_PARSE_STATES: Final = 16_384
_EMPTY_STRING_SET: frozenset[str] = frozenset()
_TRUTHY_FLAG_VALUES: Final = frozenset({"1", "on", "true", "yes"})
_FALSEY_FLAG_VALUES: Final = frozenset({"0", "false", "no", "off"})


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


@dataclass(frozen=True, slots=True)
class _EffectiveOption:
    name: str
    token: str
    value: str | None
    is_value_option: bool
    positive_flag: str | None = None
    negative_flag: str | None = None
    positive_polarity: bool = True


@dataclass(frozen=True, slots=True)
class ArgumentSemantics:
    present_flags: frozenset[str]
    effective_options: tuple[tuple[str, str, str | None], ...]

    def option_value(self, option: str) -> str | None:
        return next((value for name, _token, value in self.effective_options if name == option), None)

    def option_token(self, option: str) -> str | None:
        return next((token for name, token, _value in self.effective_options if name == option), None)


def argument_semantics(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    inverse_flag_pairs: frozenset[tuple[str, str]] = frozenset(),
) -> ArgumentSemantics:
    flags: set[str] = set()
    inverse_aliases = {
        alias: (positive, negative, alias == positive)
        for positive, negative in inverse_flag_pairs
        for alias in (positive, negative)
    }
    effective_options: dict[str, _EffectiveOption] = {}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        option_name, separator, option_value = argument.partition("=")
        is_long_option = argument.startswith("--")
        is_value_option = option_name in options_with_values
        inverse_alias = inverse_aliases.get(option_name)
        if is_long_option or inverse_alias is not None:
            if is_value_option and not separator:
                option_value = arguments[index + 1] if index + 1 < len(arguments) else ""
            effective_name = inverse_alias[0] if inverse_alias is not None else option_name
            effective_options[effective_name] = _EffectiveOption(
                name=effective_name,
                token=argument,
                value=option_value if separator or is_value_option else None,
                is_value_option=is_value_option,
                positive_flag=inverse_alias[0] if inverse_alias is not None else None,
                negative_flag=inverse_alias[1] if inverse_alias is not None else None,
                positive_polarity=inverse_alias[2] if inverse_alias is not None else True,
            )
        else:
            flags.add(argument)
            if argument.startswith("-") and separator:
                flags.add(option_name)
        if inverse_alias is None and option_name.startswith("-") and not option_name.startswith("--"):
            for character in option_name[1:]:
                if not character.isalnum():
                    continue
                short_flag = f"-{character}"
                short_alias = inverse_aliases.get(short_flag)
                if short_alias is None:
                    flags.add(short_flag)
                else:
                    effective_options[short_alias[0]] = _EffectiveOption(
                        name=short_alias[0],
                        token=short_flag,
                        value=None,
                        is_value_option=False,
                        positive_flag=short_alias[0],
                        negative_flag=short_alias[1],
                        positive_polarity=short_alias[2],
                    )
                if short_flag in options_with_values:
                    break
        index += 2 if option_name in options_with_values and "=" not in argument else 1
    for option in effective_options.values():
        flags.add(option.token)
        if option.positive_flag is not None and option.negative_flag is not None:
            assigned_value = _boolean_flag_value(option.value)
            if assigned_value is not None:
                enabled = assigned_value if option.positive_polarity else not assigned_value
                flags.add(option.positive_flag if enabled else option.negative_flag)
        elif option.is_value_option or option.value is None or option.value in _TRUTHY_FLAG_VALUES:
            flags.add(option.name)
    return ArgumentSemantics(
        present_flags=frozenset(flags),
        effective_options=tuple((name, option.token, option.value) for name, option in effective_options.items()),
    )


def _boolean_flag_value(value: str | None) -> bool | None:
    if value is None or value in _TRUTHY_FLAG_VALUES:
        return True
    if value in _FALSEY_FLAG_VALUES:
        return False
    return None


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
            assignments = frozenset({(argument, True), (option_name, True)})
            return _OptionShape((_OptionTransition(advance, assignments),), fully_known=True)
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
