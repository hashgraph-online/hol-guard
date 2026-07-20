"""Fail-closed decision factors for security-critical command effects."""

from __future__ import annotations

import shlex

from codex_plugin_scanner.guard.models import GuardAction

from .command_launcher_floors import launcher_child_commands
from .command_model import CanonicalCommand, CommandSegment, parse_shell_command
from .effect_contract import DecisionBasis, ProofRoute
from .effect_decision import DecisionFactor, DecisionFactorSource
from .github_capability_interaction import github_capability_action_class
from .github_command_capabilities import classify_github_cli
from .github_workflow_authorization import (
    GitHubWorkflowAuthorization,
    github_workflow_authorization_evidence,
)

_AWS_GLOBAL_VALUE_OPTIONS = frozenset(
    {
        "--ca-bundle",
        "--cli-binary-format",
        "--cli-connect-timeout",
        "--cli-read-timeout",
        "--color",
        "--endpoint-url",
        "--output",
        "--profile",
        "--query",
        "--region",
    }
)
_AWS_GLOBAL_BOOLEAN_OPTIONS = frozenset(
    {
        "--cli-auto-prompt",
        "--debug",
        "--no-cli-auto-prompt",
        "--no-cli-pager",
        "--no-paginate",
        "--no-sign-request",
        "--no-verify-ssl",
    }
)
_STRIPE_GLOBAL_VALUE_OPTIONS = frozenset(
    {
        "--api-base",
        "--api-key",
        "--color",
        "--config",
        "--device-name",
        "--log-level",
        "--project-name",
        "--stripe-account",
    }
)
_STRIPE_GLOBAL_BOOLEAN_OPTIONS = frozenset({"--help", "--live", "--show-headers", "--version"})
_ENV_LONG_BOOLEAN_OPTIONS = frozenset({"--debug", "--ignore-environment", "--list-signal-handling", "--null"})
_ENV_LONG_VALUE_OPTIONS = frozenset({"--argv0", "--chdir", "--unset"})
_ENV_SHORT_BOOLEAN_OPTIONS = frozenset({"0", "i", "v"})
_ENV_SHORT_VALUE_OPTIONS = frozenset({"C", "P", "a", "u"})
_WINDOWS_EXECUTABLES = frozenset(
    {
        "aws",
        "bunx",
        "cat",
        "docker",
        "gcloud",
        "getfacl",
        "gh",
        "hol-guard",
        "keyring",
        "npm",
        "npx",
        "plugin-guard",
        "rm",
        "stripe",
        "systemctl",
        "timeout",
        "xargs",
    }
)


def command_critical_floor_factors(
    command: CanonicalCommand,
    authorization: GitHubWorkflowAuthorization | None = None,
) -> tuple[DecisionFactor, ...]:
    """Return monotonic floors derived only from the canonical parsed command."""

    return _command_critical_floor_factors(command, authorization=authorization, depth=0)


def _command_critical_floor_factors(
    command: CanonicalCommand,
    *,
    authorization: GitHubWorkflowAuthorization | None,
    depth: int,
) -> tuple[DecisionFactor, ...]:

    factors: list[DecisionFactor] = []
    authorization_evidence = github_workflow_authorization_evidence(
        authorization,
        command_identity=command.security_identity,
    )
    authorized_action_class: str | None = None
    if authorization_evidence is not None:
        proof, authorized_action_class = authorization_evidence
        factors.append(
            DecisionFactor(
                source=DecisionFactorSource.AUTHORIZATION,
                reason_code="github-workflow-capability",
                basis=DecisionBasis("allow", ProofRoute.WORKFLOW_AUTHORIZED),
                operation_ref=f"operation:{command.security_identity.rsplit(':', 1)[-1]}",
                producer_ref="runtime:github-workflow-authorization-v1",
                proof=proof,
            )
        )
    path_export_index = _path_export_index(command)
    if path_export_index is not None:
        factors.append(_factor(command, path_export_index, "require-reapproval", "critical.path-provenance-drift"))
    for index, segment in enumerate(command.segments):
        executable = _executable_name(segment)
        arguments = segment.arguments
        github_factor = _github_factor(
            command,
            segment,
            index,
            executable,
            authorized_action_class=authorized_action_class,
        )
        if github_factor is not None:
            factors.append(github_factor)
        critical = _critical_floor(command, segment, executable, arguments)
        if critical is not None:
            action, reason_code = critical
            factors.append(_factor(command, index, action, reason_code))
        launcher_children = launcher_child_commands(executable, arguments)
        if depth < 3:
            for child in launcher_children:
                factors.extend(_command_critical_floor_factors(child, authorization=None, depth=depth + 1))
        elif launcher_children:
            factors.append(_factor(command, index, "block", "critical.launcher-depth-limit"))
    return tuple(factors)


def _github_factor(
    command: CanonicalCommand,
    segment: CommandSegment,
    index: int,
    executable: str,
    *,
    authorized_action_class: str | None,
) -> DecisionFactor | None:
    if executable != "gh":
        return None
    assessment = classify_github_cli(segment.arguments)
    if (
        authorized_action_class is not None
        and assessment.action_floor != "allow"
        and github_capability_action_class(assessment) == authorized_action_class
    ):
        return None
    if assessment.action_floor == "allow":
        return None
    return _factor(
        command,
        index,
        assessment.action_floor,
        f"github-capability.{assessment.capability.replace('_', '-')}",
    )


def _critical_floor(
    command: CanonicalCommand,
    segment: CommandSegment,
    executable: str,
    arguments: tuple[str, ...],
) -> tuple[GuardAction, str] | None:
    normalized = tuple(item.lower() for item in arguments)
    if executable == "aws" and _command_path(
        normalized,
        ("route53", "delete-hosted-zone"),
        value_options=_AWS_GLOBAL_VALUE_OPTIONS,
        boolean_options=_AWS_GLOBAL_BOOLEAN_OPTIONS,
        allow_unique_prefix=True,
    ):
        return "block", "critical.remote-destructive"
    if executable == "stripe" and _command_path(
        normalized,
        ("products", "delete"),
        value_options=_STRIPE_GLOBAL_VALUE_OPTIONS,
        boolean_options=_STRIPE_GLOBAL_BOOLEAN_OPTIONS,
    ):
        return "block", "critical.remote-destructive"
    if executable == "rm" and _destructive_remove(arguments):
        return "block", "critical.destructive-filesystem"
    if executable == "timeout" and _destructive_timeout_shell(arguments):
        return "block", "critical.destructive-filesystem"
    if executable == "gh" and _destructive_graphql(arguments):
        return "block", "critical.destructive-graphql"
    if executable in {"hol-guard", "plugin-guard"}:
        guard_control = _guard_control_floor(normalized)
        if guard_control is not None:
            return guard_control
    if segment.path_overridden:
        return "require-reapproval", "critical.path-provenance-drift"
    if executable in {"npx", "npm", "pnpm", "yarn", "bunx"} and _local_package_source(normalized):
        return "require-reapproval", "critical.package-source-drift"
    if executable == "cat" and segment.execution_context.startswith("substitution:"):
        return "require-reapproval", "critical.dynamic-sensitive-read"
    if executable == "cat" and _is_pipeline_segment(command, segment):
        return "require-reapproval", "critical.pipeline-sensitive-read"
    if executable == "keyring" and normalized[:1] == ("get",):
        return "require-reapproval", "critical.credential-metadata"
    if executable == "npm" and normalized[:1] == ("view",):
        return "review", "critical.package-registry-read"
    if executable == "docker" and _docker_read(normalized):
        return "review", "critical.container-state-read"
    if executable == "aws" and normalized[:2] == ("sts", "get-caller-identity"):
        return "review", "critical.cloud-identity-read"
    if executable == "gcloud" and normalized[:2] == ("projects", "describe"):
        return "review", "critical.cloud-identity-read"
    if executable in {"getfacl", "systemctl"}:
        return "review", "critical.system-metadata-read"
    return None


def _factor(command: CanonicalCommand, index: int, action: GuardAction, reason_code: str) -> DecisionFactor:
    operation_id = command.security_identity.rsplit(":", 1)[-1]
    return DecisionFactor(
        source=DecisionFactorSource.POLICY,
        reason_code=reason_code,
        basis=DecisionBasis(action, None),
        segment_ref=f"segment:{index}",
        operation_ref=f"operation:{operation_id}",
        producer_ref="runtime:command-critical-floors-v1",
    )


def _executable_name(segment: CommandSegment) -> str:
    executable = (segment.executable or "").replace("\\", "/")
    name = executable.rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") and name[:-4] in _WINDOWS_EXECUTABLES else name


def _recursive_force(arguments: tuple[str, ...]) -> bool:
    option_end = arguments.index("--") if "--" in arguments else len(arguments)
    flags = tuple(item for item in arguments[:option_end] if item.startswith("-") and item != "-")
    has_recursive = any(
        _long_option_prefix(item, "--recursive") or (not item.startswith("--") and ("r" in item[1:] or "R" in item[1:]))
        for item in flags
    )
    has_force = any(
        _long_option_prefix(item, "--force") or (not item.startswith("--") and "f" in item[1:]) for item in flags
    )
    return has_recursive and has_force


def _long_option_prefix(argument: str, expected: str) -> bool:
    return len(argument) > 2 and argument.startswith("--") and expected.startswith(argument)


def _destructive_remove(arguments: tuple[str, ...]) -> bool:
    if not _recursive_force(arguments):
        return False
    option_end = arguments.index("--") if "--" in arguments else len(arguments)
    targets = tuple(item for item in arguments[:option_end] if not item.startswith("-"))
    if option_end < len(arguments):
        targets += arguments[option_end + 1 :]
    routine_outputs = {
        ".cache",
        ".pytest_cache",
        ".ruff_cache",
        "build",
        "coverage",
        "dist",
    }
    return not targets or any(target.rstrip("/").removeprefix("./") not in routine_outputs for target in targets)


def _destructive_graphql(arguments: tuple[str, ...]) -> bool:
    assessment = classify_github_cli(arguments)
    return assessment.reason_code.startswith("github.graphql.") and "delete_remote" in assessment.capabilities


def _destructive_timeout_shell(arguments: tuple[str, ...]) -> bool:
    expanded = _expand_env_split_string(arguments)
    for index, argument in enumerate(expanded[:-1]):
        shell = argument.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if shell not in {"ash", "bash", "dash", "sh", "zsh"}:
            continue
        command_text = _shell_command_text(expanded[index + 1 :])
        if command_text is None:
            continue
        nested = parse_shell_command(command_text)
        return any(
            _executable_name(segment) == "rm" and _destructive_remove(segment.arguments) for segment in nested.segments
        )
    return False


def _expand_env_split_string(arguments: tuple[str, ...]) -> tuple[str, ...]:
    for index, argument in enumerate(arguments[:-1]):
        if argument.replace("\\", "/").rsplit("/", 1)[-1].lower() != "env":
            continue
        parsed = _env_split_string(arguments, index + 1)
        if parsed is None:
            return arguments
        split_string, consumed = parsed
        try:
            split = tuple(shlex.split(split_string, posix=True))
        except ValueError:
            return arguments
        if not split:
            return arguments
        return (*arguments[: index + 1], *split, *arguments[consumed:])
    return arguments


def _env_split_string(arguments: tuple[str, ...], start: int) -> tuple[str, int] | None:
    index = start
    while index < len(arguments):
        argument = arguments[index]
        if argument in _ENV_LONG_BOOLEAN_OPTIONS:
            index += 1
            continue
        option, separator, value = argument.partition("=")
        if option in _ENV_LONG_VALUE_OPTIONS:
            if separator:
                if not value:
                    return None
                index += 1
                continue
            if index + 1 >= len(arguments) or not arguments[index + 1]:
                return None
            index += 2
            continue
        if option == "--split-string":
            if separator:
                return (value, index + 1) if value else None
            if index + 1 >= len(arguments) or not arguments[index + 1]:
                return None
            return arguments[index + 1], index + 2
        if argument.startswith("--") or not argument.startswith("-") or argument == "-":
            return None
        cursor = 1
        while cursor < len(argument):
            short_option = argument[cursor]
            if short_option in _ENV_SHORT_BOOLEAN_OPTIONS:
                cursor += 1
                continue
            if short_option == "S":
                attached = argument[cursor + 1 :]
                if attached:
                    return attached, index + 1
                if index + 1 >= len(arguments) or not arguments[index + 1]:
                    return None
                return arguments[index + 1], index + 2
            if short_option not in _ENV_SHORT_VALUE_OPTIONS:
                return None
            if cursor + 1 < len(argument):
                index += 1
            elif index + 1 < len(arguments) and arguments[index + 1]:
                index += 2
            else:
                return None
            break
        else:
            index += 1
    return None


def _shell_command_text(arguments: tuple[str, ...]) -> str | None:
    options_with_values = {"-O", "-o", "--init-file", "--rcfile"}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in options_with_values:
            index += 2
            continue
        if argument == "--":
            return None
        if argument.startswith("-"):
            if not argument.startswith("--") and "c" in argument[1:]:
                return arguments[index + 1] if index + 1 < len(arguments) else None
            index += 1
            continue
        return None
    return None


def _local_package_source(arguments: tuple[str, ...]) -> bool:
    return any("file:" in item or item.startswith(("./", "../", "/")) for item in arguments)


def _command_path(
    arguments: tuple[str, ...],
    expected: tuple[str, ...],
    *,
    value_options: frozenset[str],
    boolean_options: frozenset[str],
    allow_unique_prefix: bool = False,
) -> bool:
    positional: list[str] = []
    index = 0
    while index < len(arguments) and len(positional) < len(expected):
        argument = arguments[index]
        option, separator, _value = argument.partition("=")
        normalized_option = _resolved_option(option, value_options | boolean_options) if allow_unique_prefix else option
        if normalized_option in value_options:
            index += 1 if separator else 2
            continue
        if normalized_option in boolean_options and not separator:
            index += 1
            continue
        if argument.startswith("-"):
            return False
        positional.append(argument)
        index += 1
    return tuple(positional) == expected


def _resolved_option(option: str, known: frozenset[str]) -> str:
    if option in known or not option.startswith("--"):
        return option
    matches = tuple(candidate for candidate in known if candidate.startswith(option))
    return matches[0] if len(matches) == 1 else option


def _contains_ordered(arguments: tuple[str, ...], first: str, second: str) -> bool:
    try:
        first_index = arguments.index(first)
    except ValueError:
        return False
    return second in arguments[first_index + 1 :]


def _guard_control_floor(arguments: tuple[str, ...]) -> tuple[GuardAction, str] | None:
    control_tokens = {"capability", "clear", "policy", "uninstall"}
    if control_tokens.intersection(arguments) and any(item in {"help", "--help", "-h"} for item in arguments):
        return "review", "critical.guard-control-help"
    if _contains_ordered(arguments, "capability", "consume"):
        return "block", "critical.capability-replay"
    if "uninstall" in arguments:
        return "block", "critical.guard-self-protection"
    if _contains_ordered(arguments, "policy", "disable"):
        return "block", "critical.guard-policy-tamper"
    if "clear" in arguments and "--all" in arguments:
        return "block", "critical.guard-data-tamper"
    return None


def _path_export_index(command: CanonicalCommand) -> int | None:
    for index, segment in enumerate(command.segments):
        if _executable_name(segment) == "export" and any(
            argument.casefold().startswith("path=") for argument in segment.arguments
        ):
            return index
    return None


def _is_pipeline_segment(command: CanonicalCommand, segment: CommandSegment) -> bool:
    return any(item.execution_context == segment.execution_context and item is not segment for item in command.segments)


def _docker_read(arguments: tuple[str, ...]) -> bool:
    return arguments[:1] == ("inspect",) or arguments[:2] == ("compose", "ps")


__all__ = ("command_critical_floor_factors",)
