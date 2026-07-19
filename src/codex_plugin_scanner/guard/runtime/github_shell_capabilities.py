"""Compose GitHub capabilities across nested shell command structures."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from . import github_shell_bindings as _bindings
from .github_capability_contract import (
    GitHubCommandAssessment,
    combine_github_assessments,
    github_assessment,
)
from .github_command_capabilities import classify_github_cli

_apply_assignment_updates = _bindings.apply_assignment_updates
_executable_control_flow_segment = _bindings.executable_control_flow_segment
_normalize_github_lookup_assignments = _bindings.normalize_github_lookup_assignments
_persistent_assignment_updates = _bindings.persistent_assignment_updates
_update_exported_bindings = _bindings.update_exported_bindings

_GH_EXECUTORS = frozenset({"builtin", "eval", "exec", "timeout", "watch", "xargs"})


def _text_assignment_updates(
    segment: list[str],
    *,
    command_index: int | None,
    analysis: GitHubShellAnalysis,
    depth: int,
    github_command_variables: frozenset[str],
    github_command_text_variables: frozenset[str],
) -> tuple[tuple[str, bool], ...]:
    return _bindings.assignment_updates(
        segment,
        command_index=command_index,
        text_values=True,
        text_value_classifier=lambda value: _text_value_is_github_command(
            value,
            analysis=analysis,
            depth=depth,
            github_command_variables=github_command_variables,
            github_command_text_variables=github_command_text_variables,
        ),
    )


def _persistent_text_assignment_updates(
    segment: list[str],
    *,
    command_name: str | None,
    command_index: int | None,
    analysis: GitHubShellAnalysis,
    depth: int,
    github_command_variables: frozenset[str],
    github_command_text_variables: frozenset[str],
) -> tuple[tuple[str, bool], ...]:
    return _persistent_assignment_updates(
        segment,
        command_name=command_name,
        command_index=command_index,
        text_values=True,
        text_value_classifier=lambda value: _text_value_is_github_command(
            value,
            analysis=analysis,
            depth=depth,
            github_command_variables=github_command_variables,
            github_command_text_variables=github_command_text_variables,
        ),
    )


def _text_value_is_github_command(
    value: str,
    *,
    analysis: GitHubShellAnalysis,
    depth: int,
    github_command_variables: frozenset[str],
    github_command_text_variables: frozenset[str],
) -> bool:
    first_token = value.strip().split(maxsplit=1)[0] if value.strip() else ""
    if _bindings.value_names_github_executable(first_token):
        return True
    return (
        classify_github_shell_capabilities(
            value,
            analysis=analysis,
            depth=depth + 1,
            github_command_variables=github_command_variables,
            github_command_text_variables=github_command_text_variables,
        )
        is not None
    )


@dataclass(frozen=True, slots=True)
class GitHubShellAnalysis:
    """Shell parsing operations supplied by the runtime command coordinator."""

    command_substitution_payloads: Callable[[str], tuple[str, ...]]
    split_parts: Callable[[str], list[str]]
    nested_commands: Callable[[list[str]], tuple[str, ...]]
    pipelines: Callable[[list[str]], list[list[list[str]]]]
    command_builtin_is_lookup: Callable[[list[str]], bool]
    primary_command: Callable[[list[str]], tuple[str | None, int | None]]
    pipeline_companion_is_read_only: Callable[[list[str]], bool]


def classify_github_shell_capabilities(
    command_text: str,
    *,
    analysis: GitHubShellAnalysis,
    depth: int = 0,
    github_command_variables: frozenset[str] | None = None,
    github_command_text_variables: frozenset[str] | None = None,
    github_exported_variables: frozenset[str] | None = None,
    github_exported_text_variables: frozenset[str] | None = None,
) -> GitHubCommandAssessment | None:
    """Return every GitHub capability observed in a shell composition."""

    if depth > 3:
        return github_assessment(
            "unknown",
            "github.shell.nesting-depth",
            "The nested shell composition exceeds the statically reviewed depth.",
        )
    analysis_text = _normalize_github_lookup_assignments(command_text)
    parts = analysis.split_parts(analysis_text)
    pipelines = analysis.pipelines(parts)
    conditional_pipeline_indexes, definitely_skipped_pipelines = _bindings.pipeline_control_flow(
        parts,
        pipelines,
        primary_command=analysis.primary_command,
    )
    parent_expanded_variables = _bindings.parent_expanded_variable_names(command_text)
    persistent_github_variables = set(github_command_variables or ())
    persistent_github_text_variables = set(github_command_text_variables or ())
    exported_github_variables = set(github_exported_variables or ())
    exported_github_text_variables = set(github_exported_text_variables or ())
    assessments: list[GitHubCommandAssessment] = []
    for function_body, function_prefix in _bindings.function_definition_payloads(command_text):
        function_assessment = classify_github_shell_capabilities(
            function_body,
            analysis=analysis,
            depth=depth + 1,
            github_command_variables=_github_variables_after_prefix(
                function_prefix,
                analysis=analysis,
                initial=frozenset(persistent_github_variables),
            ),
            github_command_text_variables=_github_text_variables_after_prefix(
                function_prefix,
                analysis=analysis,
                initial=frozenset(persistent_github_text_variables),
            ),
        )
        if function_assessment is not None:
            assessments.append(
                github_assessment(
                    "unknown",
                    "github.shell.deferred-definition",
                    "A shell function defers execution of a GitHub command.",
                )
            )
    for nested_command, command_prefix in _bindings.scoped_command_substitutions(
        command_text,
        payloads=analysis.command_substitution_payloads,
    ):
        assessment = classify_github_shell_capabilities(
            nested_command,
            analysis=analysis,
            depth=depth + 1,
            github_command_variables=_github_variables_after_prefix(
                command_prefix,
                analysis=analysis,
                initial=frozenset(persistent_github_variables),
            ),
            github_command_text_variables=_github_text_variables_after_prefix(
                command_prefix,
                analysis=analysis,
                initial=frozenset(persistent_github_text_variables),
            ),
            github_exported_variables=frozenset(exported_github_variables),
            github_exported_text_variables=frozenset(exported_github_text_variables),
        )
        if assessment is not None:
            assessments.append(assessment)

    for pipeline_index, pipeline in enumerate(pipelines):
        if pipeline_index in definitely_skipped_pipelines:
            continue
        contains_github_command = False
        for raw_segment in pipeline:
            segment = _executable_control_flow_segment(raw_segment)
            if not segment:
                continue
            command_name, command_index = analysis.primary_command(segment)
            assignment_updates = _bindings.assignment_updates(segment, command_index=command_index)
            text_assignment_updates = _text_assignment_updates(
                segment,
                command_index=command_index,
                analysis=analysis,
                depth=depth,
                github_command_variables=frozenset(persistent_github_variables),
                github_command_text_variables=frozenset(persistent_github_text_variables),
            )
            segment_github_variables = set(persistent_github_variables)
            segment_github_text_variables = set(persistent_github_text_variables)
            _apply_assignment_updates(segment_github_variables, assignment_updates)
            _apply_assignment_updates(segment_github_text_variables, text_assignment_updates)
            nested_github_variables = set(exported_github_variables)
            nested_github_text_variables = set(exported_github_text_variables)
            nested_github_variables.update(persistent_github_variables & parent_expanded_variables)
            nested_github_text_variables.update(persistent_github_text_variables & parent_expanded_variables)
            _apply_assignment_updates(nested_github_variables, assignment_updates)
            _apply_assignment_updates(nested_github_text_variables, text_assignment_updates)
            for nested_command in analysis.nested_commands(segment):
                assessment = classify_github_shell_capabilities(
                    nested_command,
                    analysis=analysis,
                    depth=depth + 1,
                    github_command_variables=frozenset(nested_github_variables),
                    github_command_text_variables=frozenset(nested_github_text_variables),
                    github_exported_variables=frozenset(nested_github_variables),
                    github_exported_text_variables=frozenset(nested_github_text_variables),
                )
                if assessment is not None:
                    assessments.append(assessment)
            if analysis.command_builtin_is_lookup(segment):
                continue
            if command_name is not None and _bindings.dynamic_command_may_invoke_github(
                segment[command_index] if command_index is not None else command_name,
                github_command_variables=frozenset(segment_github_variables),
                github_command_text_variables=frozenset(segment_github_text_variables),
            ):
                contains_github_command = True
                assessments.append(
                    github_assessment(
                        "unknown",
                        "github.shell.dynamic-command",
                        "A dynamically resolved command may invoke an unverified GitHub operation.",
                    )
                )
                continue
            indirect_assessment = _classify_indirect_github_segment(
                segment,
                command_name=command_name,
                command_index=command_index,
                analysis=analysis,
                depth=depth,
                github_command_variables=frozenset(segment_github_variables),
                github_command_text_variables=frozenset(segment_github_text_variables),
            )
            if indirect_assessment is not None:
                contains_github_command = True
                assessments.append(indirect_assessment)
                continue
            if command_name != "gh" or command_index is None:
                continue
            contains_github_command = True
            assessments.append(_classify_github_shell_segment(segment, command_index))
        if len(pipeline) == 1:
            persistent_segment = _executable_control_flow_segment(pipeline[0])
            persistent_command, persistent_index = analysis.primary_command(persistent_segment)
            conditional_pipeline = pipeline_index in conditional_pipeline_indexes
            executable_updates = _persistent_assignment_updates(
                persistent_segment,
                command_name=persistent_command,
                command_index=persistent_index,
                text_values=False,
            )
            text_updates = _persistent_text_assignment_updates(
                persistent_segment,
                command_name=persistent_command,
                command_index=persistent_index,
                analysis=analysis,
                depth=depth,
                github_command_variables=frozenset(persistent_github_variables),
                github_command_text_variables=frozenset(persistent_github_text_variables),
            )
            if conditional_pipeline:
                executable_updates = tuple(update for update in executable_updates if update[1])
                text_updates = tuple(update for update in text_updates if update[1])
            _apply_assignment_updates(
                persistent_github_variables,
                executable_updates,
            )
            _apply_assignment_updates(
                persistent_github_text_variables,
                text_updates,
            )
            _update_exported_bindings(
                persistent_segment,
                command_name=persistent_command,
                command_index=persistent_index,
                current_bindings=persistent_github_variables,
                exported_bindings=exported_github_variables,
                suppress_removals=conditional_pipeline,
            )
            _update_exported_bindings(
                persistent_segment,
                command_name=persistent_command,
                command_index=persistent_index,
                current_bindings=persistent_github_text_variables,
                exported_bindings=exported_github_text_variables,
                suppress_removals=conditional_pipeline,
            )
        if not contains_github_command or len(pipeline) < 2:
            if len(pipeline) >= 2 and _bindings.pipeline_executes_github_text(
                pipeline,
                primary_command=analysis.primary_command,
                github_command_text_variables=frozenset(persistent_github_text_variables),
            ):
                assessments.append(
                    github_assessment(
                        "unknown",
                        "github.pipeline.indirect-execution",
                        "A pipeline passes GitHub command text to an indirect command executor.",
                    )
                )
            continue
        for segment in pipeline:
            command_name, _command_index = analysis.primary_command(segment)
            if command_name == "gh":
                continue
            if not analysis.pipeline_companion_is_read_only(segment):
                assessments.append(
                    github_assessment(
                        "unknown",
                        "github.pipeline.unverified-companion",
                        "A GitHub command is composed with a pipeline stage that has not been proven read-only.",
                    )
                )
    return combine_github_assessments(assessments)


def _github_variables_after_prefix(
    command_prefix: str,
    *,
    analysis: GitHubShellAnalysis,
    initial: frozenset[str],
) -> frozenset[str]:
    bindings = set(initial)
    normalized_prefix = _normalize_github_lookup_assignments(command_prefix)
    parts = analysis.split_parts(normalized_prefix)
    conditional_indexes = _bindings.conditional_pipeline_indexes(parts)
    for pipeline_index, pipeline in enumerate(analysis.pipelines(parts)):
        if len(pipeline) == 1:
            command_name, command_index = analysis.primary_command(pipeline[0])
            updates = _persistent_assignment_updates(
                pipeline[0],
                command_name=command_name,
                command_index=command_index,
                text_values=False,
            )
            if pipeline_index in conditional_indexes:
                updates = tuple(update for update in updates if update[1])
            _apply_assignment_updates(
                bindings,
                updates,
            )
    return frozenset(bindings)


def _github_text_variables_after_prefix(
    command_prefix: str,
    *,
    analysis: GitHubShellAnalysis,
    initial: frozenset[str],
) -> frozenset[str]:
    bindings = set(initial)
    normalized_prefix = _normalize_github_lookup_assignments(command_prefix)
    parts = analysis.split_parts(normalized_prefix)
    conditional_indexes = _bindings.conditional_pipeline_indexes(parts)
    for pipeline_index, pipeline in enumerate(analysis.pipelines(parts)):
        if len(pipeline) == 1:
            command_name, command_index = analysis.primary_command(pipeline[0])
            updates = _persistent_text_assignment_updates(
                pipeline[0],
                command_name=command_name,
                command_index=command_index,
                analysis=analysis,
                depth=0,
                github_command_variables=frozenset(),
                github_command_text_variables=frozenset(bindings),
            )
            if pipeline_index in conditional_indexes:
                updates = tuple(update for update in updates if update[1])
            _apply_assignment_updates(
                bindings,
                updates,
            )
    return frozenset(bindings)


def _classify_indirect_github_segment(
    segment: list[str],
    *,
    command_name: str | None,
    command_index: int | None,
    analysis: GitHubShellAnalysis,
    depth: int,
    github_command_variables: frozenset[str],
    github_command_text_variables: frozenset[str],
) -> GitHubCommandAssessment | None:
    if command_name is None or command_index is None:
        return None
    is_definition = command_name == "alias"
    if is_definition:
        definition = classify_github_shell_capabilities(
            _bindings.definition_payload(segment, command_name=command_name, command_index=command_index),
            analysis=analysis,
            depth=depth + 1,
            github_command_variables=github_command_variables,
            github_command_text_variables=github_command_text_variables,
        )
        if definition is not None:
            return github_assessment(
                "unknown",
                "github.shell.deferred-definition",
                "A shell function or alias defers execution of a GitHub command.",
            )
        return None
    if command_name not in _GH_EXECUTORS:
        return None
    gh_indices = [
        index
        for index, token in enumerate(segment[command_index + 1 :], start=command_index + 1)
        if _bindings.value_names_github_executable(token)
    ]
    if gh_indices:
        return _classify_github_shell_segment(segment, gh_indices[0])
    payload = " ".join(segment[command_index + 1 :]).strip()
    return classify_github_shell_capabilities(
        payload,
        analysis=analysis,
        depth=depth + 1,
        github_command_variables=github_command_variables,
        github_command_text_variables=github_command_text_variables,
    )


def _classify_github_shell_segment(segment: list[str], command_index: int) -> GitHubCommandAssessment:
    args: list[str] = []
    has_redirection = False
    index = command_index + 1
    while index < len(segment):
        token = segment[index]
        if token in {"2>&1", "1>&2"}:
            index += 1
            continue
        if token in {">", ">>", ">|", "<", "<<", "<<<"}:
            has_redirection = True
            index += 2
            continue
        if any(marker in token for marker in (">", "<")):
            has_redirection = True
            index += 1
            continue
        args.append(token)
        index += 1
    github_operation = classify_github_cli(args)
    if not has_redirection:
        return github_operation
    combined = combine_github_assessments(
        (
            github_operation,
            github_assessment(
                "write_local",
                "github.command.shell-redirection",
                "The GitHub CLI invocation includes local input or output redirection.",
            ),
        )
    )
    if combined is None:
        raise AssertionError("redirection composition must contain both GitHub assessments")
    return combined
