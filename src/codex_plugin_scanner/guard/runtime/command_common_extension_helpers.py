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


def _variant_leaf(matcher: ExecutableMatcher, required_flags: frozenset[str]) -> ExecutableMatcher:
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
        required_flags_in_all_arguments=matcher.required_flags_in_all_arguments,
        fail_secure_unknown_options=matcher.fail_secure_unknown_options,
    )


def flag_variant(
    matcher: ExecutableMatcher | AnyMatcher,
    *,
    variant_id: str,
    title: str,
    required_flags: frozenset[str],
) -> CommandSafeVariant:
    """Create a rule-local safe variant without dropping matcher constraints."""

    if isinstance(matcher, ExecutableMatcher):
        variant_matcher: CommandMatcher = _variant_leaf(matcher, required_flags)
    else:
        leaves = tuple(
            _variant_leaf(child, required_flags)
            for child in matcher.matchers
            if isinstance(child, ExecutableMatcher)
        )
        if len(leaves) != len(matcher.matchers):
            raise ValueError("flag variants require executable matcher leaves")
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
    variants = tuple(
        flag_variant(
            matcher,
            variant_id=f"dry-run-{mode}",
            title=title,
            required_flags=frozenset({f"--dry-run={mode}"}),
        ).matcher
        for mode in ("client", "server")
    )
    return CommandSafeVariant(
        variant_id="dry-run",
        title=title,
        matcher=AnyMatcher(matchers=variants),
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
    example_command: str,
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
