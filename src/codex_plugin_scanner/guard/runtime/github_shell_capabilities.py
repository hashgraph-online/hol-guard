"""Compose GitHub capabilities across nested shell command structures."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .github_capability_contract import (
    GitHubCommandAssessment,
    combine_github_assessments,
    github_assessment,
)
from .github_command_capabilities import classify_github_cli


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
) -> GitHubCommandAssessment | None:
    """Return every GitHub capability observed in a shell composition."""

    if depth > 3:
        return github_assessment(
            "unknown",
            "github.shell.nesting-depth",
            "The nested shell composition exceeds the statically reviewed depth.",
        )
    assessments: list[GitHubCommandAssessment] = []
    for nested_command in analysis.command_substitution_payloads(command_text):
        assessment = classify_github_shell_capabilities(
            nested_command,
            analysis=analysis,
            depth=depth + 1,
        )
        if assessment is not None:
            assessments.append(assessment)

    parts = analysis.split_parts(command_text)
    for nested_command in analysis.nested_commands(parts):
        assessment = classify_github_shell_capabilities(
            nested_command,
            analysis=analysis,
            depth=depth + 1,
        )
        if assessment is not None:
            assessments.append(assessment)

    for pipeline in analysis.pipelines(parts):
        contains_github_command = False
        for segment in pipeline:
            if analysis.command_builtin_is_lookup(segment):
                continue
            command_name, command_index = analysis.primary_command(segment)
            if command_name != "gh" or command_index is None:
                continue
            contains_github_command = True
            assessments.append(_classify_github_shell_segment(segment, command_index))
        if not contains_github_command or len(pipeline) < 2:
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
