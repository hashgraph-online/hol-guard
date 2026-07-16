"""Conservative option parsing for destructive command matchers."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

_EMPTY_STRING_SET: frozenset[str] = frozenset()
_TRUTHY_FLAG_VALUES = frozenset({"1", "on", "true", "yes"})
_FALSEY_FLAG_VALUES = frozenset({"0", "false", "no", "off"})


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
    """Match a destructive prefix under any plausible unknown-option shape."""

    @cache
    def matches(argument_index: int, subcommand_index: int) -> bool:
        if subcommand_index == len(subcommands):
            return True
        if argument_index >= len(arguments):
            return False
        argument = arguments[argument_index]
        if argument == "--":
            remaining = len(subcommands) - subcommand_index
            return arguments[argument_index + 1 : argument_index + 1 + remaining] == subcommands[subcommand_index:]
        if _is_option(argument):
            option_name = argument.split("=", 1)[0]
            attached_short_option = _attached_short_value_option(argument, options_with_values)
            last_short_is_known_flag = _last_short_option_is_known_flag(argument, known_flags)
            if option_name in options_with_values:
                advance = 1 if "=" in argument else 2
                return matches(argument_index + advance, subcommand_index)
            if attached_short_option is not None or "=" in argument or last_short_is_known_flag:
                return matches(argument_index + 1, subcommand_index)
            if option_name in known_flags:
                return matches(argument_index + 1, subcommand_index)
            return matches(argument_index + 1, subcommand_index) or matches(
                argument_index + 2,
                subcommand_index,
            )
        if argument != subcommands[subcommand_index]:
            return False
        return matches(argument_index + 1, subcommand_index + 1)

    return matches(0, 0)


def flags_present_in_all_option_parses(
    arguments: tuple[str, ...],
    required_flags: frozenset[str],
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> bool:
    """Return whether every plausible option parse contains each required flag."""

    return all(
        _flag_present_in_all_option_parses(
            arguments,
            required_flag,
            options_with_values=options_with_values,
            known_flags=known_flags,
        )
        for required_flag in required_flags
    )


def _flag_present_in_all_option_parses(
    arguments: tuple[str, ...],
    required_flag: str,
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> bool:
    @cache
    def present(argument_index: int, seen: bool) -> bool:
        if argument_index >= len(arguments):
            return seen
        argument = arguments[argument_index]
        if argument == "--":
            return seen
        if not _is_option(argument):
            return present(argument_index + 1, seen)
        option_name = argument.split("=", 1)[0]
        attached_short_option = _attached_short_value_option(argument, options_with_values)
        if option_name in options_with_values:
            advance = 1 if "=" in argument else 2
            return present(argument_index + advance, seen or required_flag == option_name)
        if attached_short_option is not None:
            return present(argument_index + 1, seen)
        token_flags = _flags_in_option_token(argument, options_with_values)
        next_seen = seen or required_flag in token_flags
        if option_name in known_flags or "=" in argument or _last_short_option_is_known_flag(argument, known_flags):
            return present(argument_index + 1, next_seen)
        return present(argument_index + 1, next_seen) and present(argument_index + 2, seen)

    return present(0, False)


def _is_option(argument: str) -> bool:
    return len(argument) > 1 and argument.startswith("-")


def _attached_short_value_option(argument: str, options_with_values: frozenset[str]) -> str | None:
    if len(argument) <= 2 or not argument.startswith("-") or argument.startswith("--"):
        return None
    option = argument[:2]
    return option if option in options_with_values else None


def _last_short_option_is_known_flag(argument: str, known_flags: frozenset[str]) -> bool:
    return len(argument) > 2 and not argument.startswith("--") and f"-{argument[-1]}" in known_flags


def _flags_in_option_token(argument: str, options_with_values: frozenset[str]) -> frozenset[str]:
    flags = {argument}
    if "=" in argument:
        flags.add(argument.split("=", 1)[0])
    if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
        for character in argument[1:]:
            if not character.isalnum():
                continue
            short_flag = f"-{character}"
            flags.add(short_flag)
            if short_flag in options_with_values:
                break
    return frozenset(flags)
