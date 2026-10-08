"""Reusable structured matcher builders for command extensions."""

from __future__ import annotations

from .command_path_set_matcher import ExecutablePathSetMatcher
from .command_rules import AnyMatcher, CommandSafeVariant, ExecutableMatcher

_EMPTY_STRING_SET: frozenset[str] = frozenset()
_EXECUTABLE_CHILDREN = (ExecutableMatcher, ExecutablePathSetMatcher)


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


def executable_path_set_matcher(
    executable: str,
    paths: tuple[tuple[str, ...], ...],
    *,
    global_options_with_values: frozenset[str] = _EMPTY_STRING_SET,
    global_flags: frozenset[str] = _EMPTY_STRING_SET,
    fail_secure_unknown_options: bool = False,
) -> ExecutablePathSetMatcher:
    """Build one fail-secure matcher for many destructive subcommand paths."""

    return ExecutablePathSetMatcher(
        executables=executable_names(executable),
        paths=frozenset(paths),
        interspersed_options_with_values=global_options_with_values,
        interspersed_flags=global_flags,
        fail_secure_unknown_options=fail_secure_unknown_options,
    )


def _clone_executable_child(
    child: ExecutableMatcher | ExecutablePathSetMatcher,
    *,
    required_flags: frozenset[str],
    inverse_flag_pairs: frozenset[tuple[str, str]],
    options_with_values: frozenset[str],
    required_option_values: tuple[tuple[str, frozenset[str]], ...],
) -> ExecutableMatcher | ExecutablePathSetMatcher:
    if isinstance(child, ExecutablePathSetMatcher):
        return ExecutablePathSetMatcher(
            executables=child.executables,
            paths=child.paths,
            required_flags=required_flags,
            forbidden_flags=child.forbidden_flags,
            allow_leading_options=child.allow_leading_options,
            leading_options_with_values=child.leading_options_with_values,
            interspersed_options_with_values=child.interspersed_options_with_values,
            interspersed_flags=child.interspersed_flags,
            options_with_values=options_with_values,
            inverse_flag_pairs=inverse_flag_pairs,
            required_option_values=required_option_values,
            required_flags_in_all_arguments=True,
            fail_secure_unknown_options=child.fail_secure_unknown_options,
        )
    return ExecutableMatcher(
        executables=child.executables,
        subcommands=child.subcommands,
        required_flags=required_flags,
        forbidden_flags=child.forbidden_flags,
        allow_leading_options=child.allow_leading_options,
        leading_options_with_values=child.leading_options_with_values,
        interspersed_options_with_values=child.interspersed_options_with_values,
        interspersed_flags=child.interspersed_flags,
        options_with_values=options_with_values,
        inverse_flag_pairs=inverse_flag_pairs,
        required_option_values=required_option_values,
        required_flags_in_all_arguments=True,
        fail_secure_unknown_options=child.fail_secure_unknown_options,
    )


def with_required_flag(matcher: AnyMatcher, flag: str, *, inverse_flag: str | None = None) -> AnyMatcher:
    """Clone executable children while adding one required flag."""

    if not all(isinstance(child, _EXECUTABLE_CHILDREN) for child in matcher.matchers):
        raise ValueError("Safe variants require executable matcher children")
    cloned: list[ExecutableMatcher | ExecutablePathSetMatcher] = []
    for child in matcher.matchers:
        if not isinstance(child, _EXECUTABLE_CHILDREN):
            continue
        cloned.append(
            _clone_executable_child(
                child,
                required_flags=child.required_flags | {flag},
                inverse_flag_pairs=(
                    child.inverse_flag_pairs | {(flag, inverse_flag)}
                    if inverse_flag is not None
                    else child.inverse_flag_pairs
                ),
                options_with_values=child.options_with_values,
                required_option_values=child.required_option_values,
            )
        )
    return AnyMatcher(matchers=tuple(cloned))


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
    if not all(isinstance(child, _EXECUTABLE_CHILDREN) for child in matcher.matchers):
        raise ValueError("Safe variants require executable matcher children")
    cloned: list[ExecutableMatcher | ExecutablePathSetMatcher] = []
    for child in matcher.matchers:
        if not isinstance(child, _EXECUTABLE_CHILDREN):
            continue
        cloned.append(
            _clone_executable_child(
                child,
                required_flags=child.required_flags,
                inverse_flag_pairs=child.inverse_flag_pairs,
                options_with_values=child.options_with_values | {option},
                required_option_values=(*child.required_option_values, (option, allowed_values)),
            )
        )
    return CommandSafeVariant(
        variant_id=variant_id,
        title=title,
        matcher=AnyMatcher(matchers=tuple(cloned)),
    )
