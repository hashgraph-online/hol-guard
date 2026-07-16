"""Structured rules and metadata for hosting platform command extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher, CommandRuleSeverity, CommandSafetyRule, CommandSafeVariant
from .command_structured_matchers import leading_flags_and_operands

_VERCEL_GLOBAL_OPTIONS = frozenset(
    {
        "--cwd",
        "--global-config",
        "--local-config",
        "-A",
        "--project",
        "--scope",
        "-S",
        "--team",
        "-T",
        "--token",
        "-t",
    }
)
_VERCEL_GLOBAL_FLAGS = frozenset({"--debug", "--help", "--no-color"})
_NETLIFY_GLOBAL_OPTIONS = frozenset({"--auth", "--config", "--filter", "--site"})
_NETLIFY_GLOBAL_FLAGS = frozenset({"--debug", "--help", "-h"})
_HEROKU_GLOBAL_OPTIONS = frozenset({"--app", "-a", "--remote", "-r"})
_HEROKU_GLOBAL_FLAGS = frozenset({"--help", "-h", "--prompt"})


@final
@dataclass(frozen=True, slots=True)
class _ZeroOperandFlagMatcher:
    """Match default deployment syntax without matching flagged subcommands."""

    executables: frozenset[str]
    required_flags: frozenset[str]
    options_with_values: frozenset[str]

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            executable = segment.executable
            if executable is None or executable.replace("\\", "/").rsplit("/", 1)[-1].lower() not in self.executables:
                continue
            flags, operands = leading_flags_and_operands(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if operands or not self.required_flags <= flags:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=executable,
                    detail="Matched documented default production deployment syntax.",
                )
            )
        return tuple(evidence)


_VERCEL_DELETION = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "vercel",
            *operation,
            global_options_with_values=_VERCEL_GLOBAL_OPTIONS,
            global_flags=_VERCEL_GLOBAL_FLAGS,
        )
        for operation in (("remove",), ("rm",), ("project", "rm"))
    )
)
_VERCEL_PRODUCTION_CHANGE = AnyMatcher(
    matchers=(
        *(
            executable_matcher(
                "vercel",
                *operation,
                global_options_with_values=_VERCEL_GLOBAL_OPTIONS,
                global_flags=_VERCEL_GLOBAL_FLAGS,
            )
            for operation in (("promote",), ("rollback",))
        ),
        *(
            executable_matcher(
                "vercel",
                "deploy",
                required_flags=frozenset({flag}),
                global_options_with_values=_VERCEL_GLOBAL_OPTIONS,
                global_flags=_VERCEL_GLOBAL_FLAGS,
            )
            for flag in ("--prod", "-p")
        ),
        *(
            _ZeroOperandFlagMatcher(
                executables=executable_names("vercel"),
                required_flags=frozenset({flag}),
                options_with_values=_VERCEL_GLOBAL_OPTIONS,
            )
            for flag in ("--prod", "-p")
        ),
    )
)
_VERCEL_PRODUCTION_HELP = AnyMatcher(
    matchers=(
        *(
            executable_matcher(
                "vercel",
                *operation,
                required_flags=frozenset({"--help"}),
                global_options_with_values=_VERCEL_GLOBAL_OPTIONS,
                global_flags=_VERCEL_GLOBAL_FLAGS,
            )
            for operation in (("promote",), ("rollback",), ("deploy",))
        ),
        *(
            _ZeroOperandFlagMatcher(
                executables=executable_names("vercel"),
                required_flags=frozenset({flag, "--help"}),
                options_with_values=_VERCEL_GLOBAL_OPTIONS,
            )
            for flag in ("--prod", "-p")
        ),
    )
)
_VERCEL_PRODUCTION_STATUS = executable_matcher(
    "vercel",
    "promote",
    "status",
    global_options_with_values=_VERCEL_GLOBAL_OPTIONS,
    global_flags=_VERCEL_GLOBAL_FLAGS,
)
_NETLIFY_SITE_DELETE = AnyMatcher(
    matchers=(
        executable_matcher(
            "netlify",
            "sites:delete",
            global_options_with_values=_NETLIFY_GLOBAL_OPTIONS,
            global_flags=_NETLIFY_GLOBAL_FLAGS,
        ),
    )
)
_NETLIFY_PRODUCTION_DEPLOY = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "netlify",
            "deploy",
            required_flags=frozenset({flag}),
            global_options_with_values=_NETLIFY_GLOBAL_OPTIONS,
            global_flags=_NETLIFY_GLOBAL_FLAGS,
        )
        for flag in ("--prod", "-p")
    )
)
_HEROKU_DESTRUCTION = AnyMatcher(
    matchers=(
        executable_matcher(
            "heroku",
            "apps:destroy",
            global_options_with_values=_HEROKU_GLOBAL_OPTIONS,
            global_flags=_HEROKU_GLOBAL_FLAGS,
        ),
    )
)
_HEROKU_RELEASE_CHANGE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "heroku",
            operation,
            global_options_with_values=_HEROKU_GLOBAL_OPTIONS,
            global_flags=_HEROKU_GLOBAL_FLAGS,
        )
        for operation in ("pipelines:promote", "releases:rollback")
    )
)


def _platform_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: AnyMatcher,
    action_class: str,
    safer_alternative: str,
    severity: CommandRuleSeverity,
    safe_variants: tuple[CommandSafeVariant, ...],
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


PLATFORM_COMMAND_RULES = (
    _platform_rule(
        rule_id="command.platform.vercel.deletion",
        title="Vercel resource deletion",
        description="Identifies removal of Vercel deployments or projects.",
        matcher=_VERCEL_DELETION,
        action_class="Vercel destructive command",
        safer_alternative="Inspect the deployment or project before removing it.",
        severity="critical",
        safe_variants=(safe_flag_variant(_VERCEL_DELETION, variant_id="help", title="Command help", flag="--help"),),
    ),
    _platform_rule(
        rule_id="command.platform.vercel.production-change",
        title="Vercel production change",
        description="Identifies deployment, promotion, or rollback of a Vercel production deployment.",
        matcher=_VERCEL_PRODUCTION_CHANGE,
        action_class="Vercel production command",
        safer_alternative="Inspect deployment state or promotion status before changing production.",
        severity="high",
        safe_variants=(
            CommandSafeVariant(
                variant_id="status",
                title="Promotion status inspection",
                matcher=_VERCEL_PRODUCTION_STATUS,
            ),
            CommandSafeVariant(
                variant_id="help",
                title="Command help",
                matcher=_VERCEL_PRODUCTION_HELP,
            ),
        ),
    ),
    _platform_rule(
        rule_id="command.platform.netlify.site-deletion",
        title="Netlify site deletion",
        description="Identifies permanent deletion of a Netlify site.",
        matcher=_NETLIFY_SITE_DELETE,
        action_class="Netlify destructive command",
        safer_alternative="Inspect the linked site and its deploy history before deletion.",
        severity="critical",
        safe_variants=(
            safe_flag_variant(_NETLIFY_SITE_DELETE, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_NETLIFY_SITE_DELETE, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
    _platform_rule(
        rule_id="command.platform.netlify.production-deploy",
        title="Netlify production deployment",
        description="Identifies a Netlify deployment directed to the primary site URL.",
        matcher=_NETLIFY_PRODUCTION_DEPLOY,
        action_class="Netlify production command",
        safer_alternative="Create a draft deploy first and inspect it before publishing to production.",
        severity="high",
        safe_variants=(
            safe_flag_variant(_NETLIFY_PRODUCTION_DEPLOY, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_NETLIFY_PRODUCTION_DEPLOY, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
    _platform_rule(
        rule_id="command.platform.heroku.app-destruction",
        title="Heroku app destruction",
        description="Identifies permanent destruction of a Heroku app.",
        matcher=_HEROKU_DESTRUCTION,
        action_class="Heroku destructive command",
        safer_alternative="Inspect app identity, releases, and backups before destruction.",
        severity="critical",
        safe_variants=(
            safe_flag_variant(_HEROKU_DESTRUCTION, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_HEROKU_DESTRUCTION, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
    _platform_rule(
        rule_id="command.platform.heroku.release-change",
        title="Heroku release change",
        description="Identifies promotion or rollback of Heroku releases.",
        matcher=_HEROKU_RELEASE_CHANGE,
        action_class="Heroku release command",
        safer_alternative="Inspect pipeline or release state before promotion or rollback.",
        severity="high",
        safe_variants=(
            safe_flag_variant(_HEROKU_RELEASE_CHANGE, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_HEROKU_RELEASE_CHANGE, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
)


PLATFORM_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.platform.vercel",
        name="Vercel command protection",
        description="Reviews deployment and project deletion plus production deployment, promotion, and rollback.",
        action_classes=("Vercel destructive command", "Vercel production command"),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect deployment, project, and promotion state before remote changes.",),
        reference_urls=(
            "https://vercel.com/docs/cli/remove",
            "https://vercel.com/docs/cli/project",
            "https://vercel.com/docs/cli/promote",
            "https://vercel.com/docs/cli/rollback",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.platform.netlify",
        name="Netlify command protection",
        description="Reviews site deletion and production deployments.",
        action_classes=("Netlify destructive command", "Netlify production command"),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect the linked site and create a draft deploy before production changes.",),
        reference_urls=(
            "https://cli.netlify.com/commands/sites/",
            "https://docs.netlify.com/api-and-cli-guides/cli-guides/get-started-with-cli/",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.platform.heroku",
        name="Heroku command protection",
        description="Reviews app destruction, pipeline promotion, and release rollback.",
        action_classes=("Heroku destructive command", "Heroku release command"),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect app, pipeline, and release state before remote changes.",),
        reference_urls=(
            "https://devcenter.heroku.com/articles/heroku-cli-commands#heroku-apps-destroy",
            "https://devcenter.heroku.com/articles/pipelines#promoting",
            "https://devcenter.heroku.com/articles/releases#rollback",
        ),
    ),
)
