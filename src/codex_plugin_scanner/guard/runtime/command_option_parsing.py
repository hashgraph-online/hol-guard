"""Conservative option DTOs projected from the native command matchers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from ..native_shell_helpers import call

_EMPTY_STRING_SET: frozenset[str] = frozenset()


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
    result = call(
        "argument_semantics",
        "",
        arguments=arguments,
        options_with_values=sorted(options_with_values),
        inverse_flag_pairs=sorted(inverse_flag_pairs),
    )
    return ArgumentSemantics(
        frozenset(result["present_flags"]), tuple((row[0], row[1], row[2]) for row in result["effective_options"])
    )


def matches_subcommands_conservatively(
    arguments: tuple[str, ...],
    subcommands: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> bool:
    return cast(
        bool,
        call(
            "matches_subcommands",
            "",
            arguments=arguments,
            subcommands=subcommands,
            options_with_values=sorted(options_with_values),
            known_flags=sorted(known_flags),
        ),
    )


def flags_present_in_all_option_parses(
    arguments: tuple[str, ...],
    required_flags: frozenset[str],
    *,
    options_with_values: frozenset[str],
    known_flags: frozenset[str],
) -> bool:
    return cast(
        bool,
        call(
            "flags_all",
            "",
            arguments=arguments,
            required_flags=sorted(required_flags),
            options_with_values=sorted(options_with_values),
            known_flags=sorted(known_flags),
        ),
    )


def known_option_advance(
    argument: str, *, options_with_values: frozenset[str], known_flags: frozenset[str]
) -> int | None:
    return cast(
        int | None,
        call(
            "option_advance",
            "",
            argument=argument,
            options_with_values=sorted(options_with_values),
            known_flags=sorted(known_flags),
        ),
    )


def long_flag_assignment_is_enabled(argument: str) -> bool:
    return cast(bool, call("long_flag", "", argument=argument))
