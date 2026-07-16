"""Conservative option parsing for destructive command matchers."""

from __future__ import annotations

from functools import cache


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
