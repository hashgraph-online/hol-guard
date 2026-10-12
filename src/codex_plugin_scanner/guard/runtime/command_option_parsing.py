"""Conservative option DTOs projected from the native command matchers."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, cast

from ..native_shell_helpers import call, runtime_key

_EMPTY_STRING_SET: frozenset[str] = frozenset()
_cached_runtime: tuple[object, ...] | None = None


@lru_cache(maxsize=512)
def _option_result(action: str, identity: tuple[object, ...], fields: tuple[tuple[str, Any], ...]) -> Any:
    """Reuse bound native DTOs only for identical inputs and runtime identity."""
    return call(action, "", **dict(fields))


def _option_call(action: str, _command: str, **fields: Any) -> Any:
    global _cached_runtime
    identity = runtime_key()
    if identity != _cached_runtime:
        _option_result.cache_clear()
        _cached_runtime = identity
    key = tuple(sorted((name, tuple(value) if isinstance(value, list) else value) for name, value in fields.items()))
    if len(repr(key)) > 8192:
        return call(action, "", **fields)
    return _option_result(action, identity, key)


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
    result = _option_call(
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
        _option_call(
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
        _option_call(
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
        _option_call(
            "option_advance",
            "",
            argument=argument,
            options_with_values=sorted(options_with_values),
            known_flags=sorted(known_flags),
        ),
    )


def long_flag_assignment_is_enabled(argument: str) -> bool:
    return cast(bool, _option_call("long_flag", "", argument=argument))
