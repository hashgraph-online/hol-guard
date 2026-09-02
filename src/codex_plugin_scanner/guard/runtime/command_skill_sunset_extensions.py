"""Structured rules and metadata for the Skill Sunset command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# Canonical flag surface verified against skill-sunset 0.2.0 (src/cli.js).
# The npm/npx launcher is intentionally not an extension target: Guard's package
# firewall owns launcher policy, while this matcher owns the installed CLI.
_SKILL_SUNSET_AUDIT = AnyMatcher(
    matchers=(
        executable_matcher(
            "skill-sunset",
            "audit",
            options_with_values=frozenset({"--lang", "--out", "--format", "--fail-on"}),
        ),
    )
)


SKILL_SUNSET_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.skill-sunset.audit",
        title="Skill Sunset configuration audit",
        description=(
            "Identifies the canonical `skill-sunset audit` surface, which reads a selected agent configuration "
            "tree, writes an advisory report, and can launch the generated HTML report when --open is present."
        ),
        severity="low",
        risk_classes=("local_secret_read",),
        action_classes=("Skill Sunset configuration audit command",),
        safer_alternatives=(
            "Confirm the target and report output directory before starting the audit.",
            "Omit --open in non-interactive environments and review the generated report as untrusted data.",
        ),
        matcher=_SKILL_SUNSET_AUDIT,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _SKILL_SUNSET_AUDIT,
                variant_id="help",
                title="Skill Sunset audit command help",
                flag="--help",
            ),
            safe_flag_variant(
                _SKILL_SUNSET_AUDIT,
                variant_id="short-help",
                title="Skill Sunset audit command help",
                flag="-h",
            ),
        ),
    ),
)


SKILL_SUNSET_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.skill-sunset",
        name="Skill Sunset command protection",
        description=(
            "Reviews the canonical Skill Sunset audit surface and its local report and viewer side effects. "
            "Experiment execution and npm launcher policy remain outside this extension."
        ),
        action_classes=("Skill Sunset configuration audit command",),
        risk_classes=("local_secret_read",),
        safer_alternatives=(
            "Confirm the audit target and output directory before running Skill Sunset.",
            "Treat generated findings as advisory evidence and review them before changing agent configuration.",
        ),
        reference_urls=("https://github.com/ooocooc/open-skill-sunset/blob/main/src/cli.js",),
    ),
)
