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
    forbidden_flags: frozenset[str] = _EMPTY_STRING_SET,
    global_options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    global_flags: frozenset[str] = _EMPTY_STRING_SET,
    allow_leading_options: bool = False,
    leading_options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    fail_secure_unknown_options: bool = False,
) -> ExecutableMatcher:
    """Build a portable executable matcher with structured option handling."""

    return ExecutableMatcher(
        executables=executable_names(executable),
        subcommands=subcommands,
        required_flags=required_flags,
        forbidden_flags=forbidden_flags,
        interspersed_options_with_values=global_options_with_values,
        interspersed_flags=global_flags,
        allow_leading_options=allow_leading_options,
        leading_options_with_values=leading_options_with_values,
        options_with_values=options_with_values,
        fail_secure_unknown_options=fail_secure_unknown_options,
    )


def with_required_flag(matcher: AnyMatcher, flag: str, *, inverse_flag: str | None = None) -> AnyMatcher:
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
                inverse_flag_pairs=(
                    child.inverse_flag_pairs | {(flag, inverse_flag)}
                    if inverse_flag is not None
                    else child.inverse_flag_pairs
                ),
                required_option_values=child.required_option_values,
                required_flags_in_all_arguments=True,
                fail_secure_unknown_options=child.fail_secure_unknown_options,
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
    inverse_flag: str | None = None,
) -> CommandSafeVariant:
    """Build a safe variant requiring one documented side-effect-free flag."""

    return CommandSafeVariant(
        variant_id=variant_id,
        title=title,
        matcher=with_required_flag(matcher, flag, inverse_flag=inverse_flag),
    )


def safe_option_variant(
    matcher: AnyMatcher,
    *,
    variant_id: str,
    title: str,
    option: str,
    allowed_values: frozenset[str],
) -> CommandSafeVariant:
    """Build a safe variant requiring one declared value-taking option."""

    if not allowed_values:
        raise ValueError("Safe option variants require at least one allowed value")
    if not all(isinstance(child, ExecutableMatcher) for child in matcher.matchers):
        raise ValueError("Safe variants require executable matcher children")
    return CommandSafeVariant(
        variant_id=variant_id,
        title=title,
        matcher=AnyMatcher(
            matchers=tuple(
                ExecutableMatcher(
                    executables=child.executables,
                    subcommands=child.subcommands,
                    required_flags=child.required_flags,
                    forbidden_flags=child.forbidden_flags,
                    allow_leading_options=child.allow_leading_options,
                    leading_options_with_values=child.leading_options_with_values,
                    interspersed_options_with_values=child.interspersed_options_with_values,
                    interspersed_flags=child.interspersed_flags,
                    options_with_values=child.options_with_values | {option},
                    inverse_flag_pairs=child.inverse_flag_pairs,
                    required_option_values=(*child.required_option_values, (option, allowed_values)),
                    required_flags_in_all_arguments=True,
                    fail_secure_unknown_options=child.fail_secure_unknown_options,
                )
                for child in matcher.matchers
                if isinstance(child, ExecutableMatcher)
            )
        ),
    )
