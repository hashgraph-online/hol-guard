"""Reusable structured matcher builders for command extensions."""

from __future__ import annotations

from .command_rules import AnyMatcher, CommandSafeVariant, ExecutableMatcher

_EMPTY_STRING_SET: frozenset[str] = frozenset()


def executable_names(name: str) -> frozenset[str]:
    """Return portable launcher names for one command."""

    return frozenset({name, f"{name}.cmd", f"{name}.exe"})


def executable_matcher(
    executable: str,
    *subcommands: str,
    required_flags: frozenset[str] = _EMPTY_STRING_SET,
    global_options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    global_flags: frozenset[str] = _EMPTY_STRING_SET,
    allow_leading_options: bool = False,
    leading_options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    options_with_values: frozenset[str] = _EMPTY_STRING_SET,
) -> ExecutableMatcher:
    """Build a portable executable matcher with structured option handling."""

    return ExecutableMatcher(
        executables=executable_names(executable),
        subcommands=subcommands,
        required_flags=required_flags,
        interspersed_options_with_values=global_options_with_values,
        interspersed_flags=global_flags,
        allow_leading_options=allow_leading_options,
        leading_options_with_values=leading_options_with_values,
        options_with_values=options_with_values,
    )


def with_required_flag(matcher: AnyMatcher, flag: str) -> AnyMatcher:
    """Clone executable children while adding one required flag."""

    if not all(isinstance(child, ExecutableMatcher) for child in matcher.matchers):
        raise ValueError("Safe variants require executable matcher children")
    return AnyMatcher(
        matchers=tuple(
            ExecutableMatcher(
                executables=child.executables,
                subcommands=child.subcommands,
                required_flags=child.required_flags | {flag},
                forbidden_flags=child.forbidden_flags,
                allow_leading_options=child.allow_leading_options,
                leading_options_with_values=child.leading_options_with_values,
                interspersed_options_with_values=child.interspersed_options_with_values,
                interspersed_flags=child.interspersed_flags,
                options_with_values=child.options_with_values,
                required_flags_in_all_arguments=True,
            )
            for child in matcher.matchers
            if isinstance(child, ExecutableMatcher)
        )
    )


def safe_flag_variant(
    matcher: AnyMatcher,
    *,
    variant_id: str,
    title: str,
    flag: str,
) -> CommandSafeVariant:
    """Build a safe variant requiring one documented side-effect-free flag."""

    return CommandSafeVariant(
        variant_id=variant_id,
        title=title,
        matcher=with_required_flag(matcher, flag),
    )
