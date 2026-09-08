"""Shared executable-matcher contract fields."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class _ExecutableContractBase:
    """Shared executable-matcher contract fields."""

    executables: frozenset[str]
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    allow_leading_options: bool = False
    leading_options_with_values: frozenset[str] = frozenset()
    interspersed_options_with_values: frozenset[str] = frozenset()
    interspersed_flags: frozenset[str] = frozenset()
    options_with_values: frozenset[str] = frozenset()
    inverse_flag_pairs: frozenset[tuple[str, str]] = frozenset()
    required_option_values: tuple[tuple[str, frozenset[str]], ...] = ()
    required_flags_in_all_arguments: bool = False
    fail_secure_unknown_options: bool = False
