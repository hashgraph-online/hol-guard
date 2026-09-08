"""Rule and metadata builders for common CLI Extensions."""

from __future__ import annotations

from .command_database_matchers import ArgumentCommandMatcher
from .command_extension_matchers import safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandRuleSeverity, CommandSafetyRule, CommandSafeVariant


def help_variants(matcher: AnyMatcher, *, short: bool = False) -> tuple[CommandSafeVariant, ...]:
    variants = [safe_flag_variant(matcher, variant_id="help", title="Command help", flag="--help")]
    if short:
        variants.append(safe_flag_variant(matcher, variant_id="short-help", title="Command help", flag="-h"))
    return tuple(variants)


def rule(
    *,
    extension_id: str,
    suffix: str,
    title: str,
    description: str,
    matcher: AnyMatcher | ArgumentCommandMatcher,
    action_class: str,
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    severity: CommandRuleSeverity = "high",
    safe_variants: tuple[CommandSafeVariant, ...] = (),
    example_command: str | None = None,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=f"{extension_id}.{suffix}",
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


def spec(
    extension_id: str,
    name: str,
    description: str,
    action_classes: tuple[str, ...],
    risk_classes: tuple[str, ...],
    safer_alternative: str,
    references: tuple[str, ...],
) -> CommandExtensionSpec:
    return CommandExtensionSpec(
        extension_id=extension_id,
        name=name,
        description=description,
        action_classes=action_classes,
        risk_classes=risk_classes,
        safer_alternatives=(safer_alternative,),
        reference_urls=references,
    )
