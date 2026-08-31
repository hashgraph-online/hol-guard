"""Structured rules and metadata for Probe commands."""

from __future__ import annotations

from .command_extension_matchers import executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import CommandMatcher
from .command_path_set_matcher import ExecutablePathSetMatcher
from .command_rules import (
    AllMatcher,
    AnyMatcher,
    ArgumentMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
)

_PROBE_GLOBAL_FLAGS = frozenset({"--json", "--quiet", "-q"})
_PROBE_OPTIONS_WITH_VALUES = frozenset(
    {
        "--environment",
        "--extends",
        "--index",
        "--method",
        "--name",
        "--output",
        "--parent",
        "--url",
        "--value",
        "--var",
    }
)


def _probe_paths(*paths: tuple[str, ...]) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            ExecutablePathSetMatcher(
                executables=executable_names("probe"),
                paths=frozenset(paths),
                interspersed_options_with_values=_PROBE_OPTIONS_WITH_VALUES,
                interspersed_flags=_PROBE_GLOBAL_FLAGS,
            ),
        )
    )


_PROBE_REQUEST_RUN = _probe_paths(("request", "run"))
_PROBE_REQUEST_OUTPUT = AllMatcher(
    matchers=(
        _PROBE_REQUEST_RUN,
        ArgumentMatcher(
            executables=executable_names("probe"),
            required_arguments=frozenset({"--output"}),
        ),
    )
)
_PROBE_REQUEST_WRITE = _probe_paths(
    ("request", "create"),
    ("request", "set"),
    ("request", "rename"),
    ("request", "move"),
    ("request", "reorder"),
)
_PROBE_REQUEST_DELETE = _probe_paths(("request", "delete"))
_PROBE_FOLDER_WRITE = _probe_paths(
    ("folder", "create"),
    ("folder", "rename"),
    ("folder", "move"),
    ("folder", "reorder"),
)
_PROBE_FOLDER_DELETE = _probe_paths(("folder", "delete"))
_PROBE_ENVIRONMENT_WRITE = _probe_paths(
    ("environment", "create"),
    ("environment", "set"),
    ("environment", "unset"),
    ("environment", "rename"),
)
_PROBE_ENVIRONMENT_DELETE = _probe_paths(("environment", "delete"))


def _help_variants(matcher: AnyMatcher) -> tuple[CommandSafeVariant, ...]:
    return (
        safe_flag_variant(matcher, variant_id="help", title="Command help", flag="--help"),
        safe_flag_variant(matcher, variant_id="short-help", title="Command help", flag="-h"),
    )


def _probe_rule(
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
    help_matcher: AnyMatcher | None = None,
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
        safe_variants=_help_variants(help_matcher) if help_matcher is not None else (),
        example_command=example_command,
    )


PROBE_COMMAND_RULES = (
    _probe_rule(
        rule_id="command.probe.request-run",
        title="Probe request execution",
        description="Identifies HTTP request execution through the Probe CLI.",
        matcher=_PROBE_REQUEST_RUN,
        action_class="Probe request execution command",
        risk_classes=("execution", "network_egress"),
        safer_alternative="Inspect the request, selected environment, and runtime variable names before execution.",
        example_command="probe request run api.yml items/0 --environment production",
        help_matcher=_PROBE_REQUEST_RUN,
    ),
    _probe_rule(
        rule_id="command.probe.request-output",
        title="Probe response file write",
        description="Identifies Probe request execution that writes the response body to a local file.",
        matcher=_PROBE_REQUEST_OUTPUT,
        action_class="Probe workspace mutation command",
        risk_classes=("destructive_shell",),
        safer_alternative="Review the output path and existing destination before writing the response body.",
        example_command="probe request run api.yml items/0 --output response.json",
        severity="medium",
        help_matcher=_PROBE_REQUEST_RUN,
    ),
    _probe_rule(
        rule_id="command.probe.request-write",
        title="Probe request workspace mutation",
        description="Identifies Probe commands that create or modify requests in an OpenCollection workspace.",
        matcher=_PROBE_REQUEST_WRITE,
        action_class="Probe workspace mutation command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect the selected request and workspace status before persisting changes.",
        example_command="probe request set api.yml items/0 --method POST",
        help_matcher=_PROBE_REQUEST_WRITE,
    ),
    _probe_rule(
        rule_id="command.probe.request-delete",
        title="Probe request deletion",
        description="Identifies deletion of a request from an OpenCollection workspace.",
        matcher=_PROBE_REQUEST_DELETE,
        action_class="Probe destructive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Confirm the exact request selector and retain a recoverable workspace copy before deletion.",
        example_command="probe request delete api.yml items/0",
        help_matcher=_PROBE_REQUEST_DELETE,
    ),
    _probe_rule(
        rule_id="command.probe.folder-write",
        title="Probe folder workspace mutation",
        description="Identifies Probe commands that create or modify folders in an OpenCollection workspace.",
        matcher=_PROBE_FOLDER_WRITE,
        action_class="Probe workspace mutation command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect the selected folder and workspace status before persisting changes.",
        example_command="probe folder rename api.yml items/0 --name Accounts",
        help_matcher=_PROBE_FOLDER_WRITE,
    ),
    _probe_rule(
        rule_id="command.probe.folder-delete",
        title="Probe folder deletion",
        description="Identifies deletion of a folder from an OpenCollection workspace.",
        matcher=_PROBE_FOLDER_DELETE,
        action_class="Probe destructive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Confirm the exact folder selector and its contents before deletion.",
        example_command="probe folder delete api.yml items/0",
        help_matcher=_PROBE_FOLDER_DELETE,
    ),
    _probe_rule(
        rule_id="command.probe.environment-write",
        title="Probe environment workspace mutation",
        description="Identifies Probe commands that create or modify persisted OpenCollection environments.",
        matcher=_PROBE_ENVIRONMENT_WRITE,
        action_class="Probe workspace mutation command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect the selected environment and variable names before persisting changes.",
        example_command="probe environment create api.yml --name production",
        help_matcher=_PROBE_ENVIRONMENT_WRITE,
    ),
    _probe_rule(
        rule_id="command.probe.environment-delete",
        title="Probe environment deletion",
        description="Identifies deletion of an environment from an OpenCollection workspace.",
        matcher=_PROBE_ENVIRONMENT_DELETE,
        action_class="Probe destructive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Confirm the exact environment and dependent environments before deletion.",
        example_command="probe environment delete api.yml --environment production",
        help_matcher=_PROBE_ENVIRONMENT_DELETE,
    ),
)


PROBE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.probe",
        name="Probe command protection",
        description="Reviews HTTP execution and OpenCollection workspace mutations through the Probe CLI.",
        action_classes=(
            "Probe request execution command",
            "Probe workspace mutation command",
            "Probe destructive command",
        ),
        risk_classes=("execution", "network_egress", "destructive_shell"),
        safer_alternatives=(
            "Inspect selected requests, environments, selectors, and output paths before execution or mutation.",
        ),
        reference_urls=("https://github.com/crizant/probe/blob/main/docs/CLI.md",),
    ),
)
