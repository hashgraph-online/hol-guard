"""Structured rules and metadata for CI/CD command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

_GH_GLOBAL_OPTIONS = frozenset({"--hostname", "--repo", "-R"})
_GH_GLOBAL_FLAGS = frozenset({"--help"})
_GLAB_GLOBAL_OPTIONS = frozenset({"--repo", "-R"})
_GLAB_GLOBAL_FLAGS = frozenset({"--help", "-h"})
_CIRCLECI_GLOBAL_OPTIONS = frozenset({"--host", "--token"})
_CIRCLECI_GLOBAL_FLAGS = frozenset({"--help", "-h", "--skip-update-check"})

_GH_RUN_ADMINISTRATION = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "gh",
            "run",
            operation,
            global_options_with_values=_GH_GLOBAL_OPTIONS,
            global_flags=_GH_GLOBAL_FLAGS,
        )
        for operation in ("cancel", "delete")
    )
)
_GH_WORKFLOW_DISABLE = AnyMatcher(
    matchers=(
        executable_matcher(
            "gh",
            "workflow",
            "disable",
            global_options_with_values=_GH_GLOBAL_OPTIONS,
            global_flags=_GH_GLOBAL_FLAGS,
        ),
    )
)
_GLAB_PIPELINE_CANCEL = AnyMatcher(
    matchers=(
        executable_matcher(
            "glab",
            "ci",
            "cancel",
            "pipeline",
            global_options_with_values=_GLAB_GLOBAL_OPTIONS,
            global_flags=_GLAB_GLOBAL_FLAGS,
        ),
    )
)
_CIRCLECI_PIPELINE_RUN = AnyMatcher(
    matchers=(
        executable_matcher(
            "circleci",
            "pipeline",
            "run",
            global_options_with_values=_CIRCLECI_GLOBAL_OPTIONS,
            global_flags=_CIRCLECI_GLOBAL_FLAGS,
        ),
    )
)


def _cicd_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: AnyMatcher,
    action_class: str,
    safer_alternative: str,
    safe_variants: tuple[CommandSafeVariant, ...],
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="high",
        risk_classes=("execution", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


CICD_COMMAND_RULES = (
    _cicd_rule(
        rule_id="command.cicd.github.run-administration",
        title="GitHub Actions run administration",
        description="Identifies cancellation or deletion of GitHub Actions workflow runs.",
        matcher=_GH_RUN_ADMINISTRATION,
        action_class="GitHub Actions administrative command",
        safer_alternative=(
            "Inspect the workflow run before canceling it, and retain run history unless deletion is required."
        ),
        safe_variants=(
            safe_flag_variant(_GH_RUN_ADMINISTRATION, variant_id="help", title="Command help", flag="--help"),
        ),
    ),
    _cicd_rule(
        rule_id="command.cicd.github.workflow-disable",
        title="GitHub Actions workflow disable",
        description="Identifies disabling a GitHub Actions workflow.",
        matcher=_GH_WORKFLOW_DISABLE,
        action_class="GitHub Actions administrative command",
        safer_alternative="View the workflow and confirm the target repository before disabling it.",
        safe_variants=(
            safe_flag_variant(_GH_WORKFLOW_DISABLE, variant_id="help", title="Command help", flag="--help"),
        ),
    ),
    _cicd_rule(
        rule_id="command.cicd.gitlab.pipeline-cancel",
        title="GitLab pipeline cancellation",
        description="Identifies cancellation of one or more GitLab CI/CD pipelines.",
        matcher=_GLAB_PIPELINE_CANCEL,
        action_class="GitLab pipeline administrative command",
        safer_alternative="Preview the selected pipeline IDs with --dry-run before cancellation.",
        safe_variants=(
            safe_flag_variant(
                _GLAB_PIPELINE_CANCEL, variant_id="dry-run", title="Cancellation preview", flag="--dry-run"
            ),
            safe_flag_variant(_GLAB_PIPELINE_CANCEL, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_GLAB_PIPELINE_CANCEL, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
    _cicd_rule(
        rule_id="command.cicd.circleci.pipeline-run",
        title="CircleCI pipeline execution",
        description="Identifies remote CircleCI pipeline execution.",
        matcher=_CIRCLECI_PIPELINE_RUN,
        action_class="CircleCI pipeline execution command",
        safer_alternative="Validate the configuration and inspect the pipeline definition before starting remote work.",
        safe_variants=(
            safe_flag_variant(_CIRCLECI_PIPELINE_RUN, variant_id="help", title="Command help", flag="--help"),
            safe_flag_variant(_CIRCLECI_PIPELINE_RUN, variant_id="short-help", title="Command help", flag="-h"),
        ),
    ),
)


CICD_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.cicd.github",
        name="GitHub Actions command protection",
        description="Reviews workflow-run cancellation, deletion, and workflow disabling through GitHub CLI.",
        action_classes=("GitHub Actions administrative command",),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=("Inspect workflow and run state before changing remote CI/CD state.",),
        reference_urls=(
            "https://cli.github.com/manual/gh_run_cancel",
            "https://cli.github.com/manual/gh_run_delete",
            "https://cli.github.com/manual/gh_workflow_disable",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.cicd.gitlab",
        name="GitLab CI/CD command protection",
        description="Reviews remote pipeline cancellation through GitLab CLI.",
        action_classes=("GitLab pipeline administrative command",),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=("Use the documented dry run before canceling selected pipelines.",),
        reference_urls=("https://docs.gitlab.com/cli/ci/cancel/pipeline/",),
    ),
    CommandExtensionSpec(
        extension_id="command.cicd.circleci",
        name="CircleCI command protection",
        description="Reviews remote pipeline execution through CircleCI CLI.",
        action_classes=("CircleCI pipeline execution command",),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=("Validate configuration and inspect the pipeline definition before execution.",),
        reference_urls=("https://circleci.com/docs/guides/toolkit/how-to-use-the-circleci-local-cli/",),
    ),
)
