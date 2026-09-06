"""Small builders shared by structured command-extension coverage modules."""

from __future__ import annotations

from .command_matcher_contracts import CommandMatcher
from .command_rules import (
    AnyMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)

_EMPTY: frozenset[str] = frozenset()


def executable_matcher(
    executables: frozenset[str],
    *subcommands: str,
    required_flags: frozenset[str] = _EMPTY,
    forbidden_flags: frozenset[str] = _EMPTY,
    leading_options_with_values: frozenset[str] = _EMPTY,
    interspersed_options_with_values: frozenset[str] = _EMPTY,
    interspersed_flags: frozenset[str] = _EMPTY,
    options_with_values: frozenset[str] = _EMPTY,
) -> ExecutableMatcher:
    """Build an executable matcher with explicit option grammar."""

    return ExecutableMatcher(
        executables=executables,
        subcommands=subcommands,
        required_flags=required_flags,
        forbidden_flags=forbidden_flags,
        allow_leading_options=bool(leading_options_with_values),
        leading_options_with_values=leading_options_with_values,
        interspersed_options_with_values=interspersed_options_with_values,
        interspersed_flags=interspersed_flags,
        options_with_values=options_with_values,
    )


def _variant_leaf(
    matcher: ExecutableMatcher,
    required_flags: frozenset[str],
    *,
    required_flags_in_all_arguments: bool = False,
    fail_secure_unknown_options: bool = False,
) -> ExecutableMatcher:
    return ExecutableMatcher(
        executables=matcher.executables,
        subcommands=matcher.subcommands,
        required_flags=matcher.required_flags | required_flags,
        forbidden_flags=matcher.forbidden_flags,
        allow_leading_options=matcher.allow_leading_options,
        leading_options_with_values=matcher.leading_options_with_values,
        interspersed_options_with_values=matcher.interspersed_options_with_values,
        interspersed_flags=matcher.interspersed_flags,
        options_with_values=matcher.options_with_values,
        inverse_flag_pairs=matcher.inverse_flag_pairs,
        required_option_values=matcher.required_option_values,
        required_flags_in_all_arguments=(matcher.required_flags_in_all_arguments or required_flags_in_all_arguments),
        fail_secure_unknown_options=matcher.fail_secure_unknown_options or fail_secure_unknown_options,
    )


def _option_value_variant_leaf(
    matcher: ExecutableMatcher,
    *,
    option: str,
    allowed_values: frozenset[str],
) -> ExecutableMatcher:
    normalized_option = option.strip().lower()
    normalized_values = frozenset(value.strip().lower() for value in allowed_values if value.strip())
    existing_requirements = dict(matcher.required_option_values)
    existing = existing_requirements.get(normalized_option)
    if existing is not None and existing != normalized_values:
        raise ValueError("option-value variants cannot override an existing option-value requirement")
    required_option_values = matcher.required_option_values
    if existing is None:
        required_option_values = (*required_option_values, (normalized_option, normalized_values))
    return ExecutableMatcher(
        executables=matcher.executables,
        subcommands=matcher.subcommands,
        required_flags=matcher.required_flags,
        forbidden_flags=matcher.forbidden_flags,
        allow_leading_options=matcher.allow_leading_options,
        leading_options_with_values=matcher.leading_options_with_values,
        interspersed_options_with_values=matcher.interspersed_options_with_values,
        interspersed_flags=matcher.interspersed_flags,
        options_with_values=matcher.options_with_values | {normalized_option},
        inverse_flag_pairs=matcher.inverse_flag_pairs,
        required_option_values=required_option_values,
        required_flags_in_all_arguments=True,
        fail_secure_unknown_options=True,
    )


def flag_variant(
    matcher: ExecutableMatcher | AnyMatcher,
    *,
    variant_id: str,
    title: str,
    required_flags: frozenset[str],
    required_flags_in_all_arguments: bool = False,
    fail_secure_unknown_options: bool = False,
) -> CommandSafeVariant:
    """Create a rule-local safe variant without dropping matcher constraints."""

    if isinstance(matcher, ExecutableMatcher):
        variant_matcher: CommandMatcher = _variant_leaf(
            matcher,
            required_flags,
            required_flags_in_all_arguments=required_flags_in_all_arguments,
            fail_secure_unknown_options=fail_secure_unknown_options,
        )
    else:
        leaves = tuple(
            _variant_leaf(
                child,
                required_flags,
                required_flags_in_all_arguments=required_flags_in_all_arguments,
                fail_secure_unknown_options=fail_secure_unknown_options,
            )
            for child in matcher.matchers
            if isinstance(child, ExecutableMatcher)
        )
        if len(leaves) != len(matcher.matchers):
            raise ValueError("flag variants require executable matcher leaves")
        variant_matcher = AnyMatcher(matchers=leaves)
    return CommandSafeVariant(variant_id=variant_id, title=title, matcher=variant_matcher)


def option_value_variant(
    matcher: ExecutableMatcher | AnyMatcher,
    *,
    variant_id: str,
    title: str,
    option: str,
    allowed_values: frozenset[str],
) -> CommandSafeVariant:
    """Create a safe variant that requires the effective value of one option."""

    if not allowed_values:
        raise ValueError("option-value variants require at least one allowed value")
    if isinstance(matcher, ExecutableMatcher):
        variant_matcher: CommandMatcher = _option_value_variant_leaf(
            matcher,
            option=option,
            allowed_values=allowed_values,
        )
    else:
        leaves = tuple(
            _option_value_variant_leaf(
                child,
                option=option,
                allowed_values=allowed_values,
            )
            for child in matcher.matchers
            if isinstance(child, ExecutableMatcher)
        )
        if len(leaves) != len(matcher.matchers):
            raise ValueError("option-value variants require executable matcher leaves")
        variant_matcher = AnyMatcher(matchers=leaves)
    return CommandSafeVariant(variant_id=variant_id, title=title, matcher=variant_matcher)


def help_variant(matcher: ExecutableMatcher | AnyMatcher) -> CommandSafeVariant:
    return flag_variant(
        matcher,
        variant_id="help",
        title="Command help",
        required_flags=frozenset({"--help"}),
    )


def kubernetes_dry_run_variant(matcher: ExecutableMatcher | AnyMatcher, title: str) -> CommandSafeVariant:
    return option_value_variant(
        matcher,
        variant_id="dry-run",
        title=title,
        option="--dry-run",
        allowed_values=frozenset({"client", "server"}),
    )


def rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: CommandMatcher,
    action_class: str,
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    example_command: str | None = None,
    severity: CommandRuleSeverity = "high",
    safe_variants: tuple[CommandSafeVariant, ...] = (),
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        risk_classes=risk_classes,
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
        example_command=example_command,
    )
