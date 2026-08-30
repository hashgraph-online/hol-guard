"""Statically skip GitHub pipelines that cannot run under &&, ||, or if."""

from __future__ import annotations

from collections.abc import Callable

from .github_shell_bindings import conditional_pipeline_connectors, token_is_shell_assignment

PrimaryCommand = Callable[[list[str]], tuple[str | None, int | None]]


def _literal_pipeline_truth(pipeline: list[list[str]], primary_command: PrimaryCommand) -> bool | None:
    """Return builtin status only when the whole pipeline is a bare true/false."""

    if len(pipeline) != 1:
        return None
    segment = pipeline[0]
    command_name, command_index = primary_command(segment)
    if command_name not in {"true", "false"} or command_index is None:
        return None
    command_token = segment[command_index]
    if any(marker in command_token for marker in (">", "<")):
        return None
    for index, token in enumerate(segment):
        if index == command_index or token_is_shell_assignment(token):
            continue
        return None
    return command_name == "true"


def _and_or_skipped_indexes(
    pipelines: list[list[list[str]]],
    connectors: dict[int, str],
    primary_command: PrimaryCommand,
) -> set[int]:
    skipped: set[int] = set()
    accumulated: bool | None = None
    for pipeline_index, pipeline in enumerate(pipelines):
        if not pipeline:
            accumulated = None
            continue
        truth = _literal_pipeline_truth(pipeline, primary_command)
        if pipeline_index == 0:
            accumulated = truth
            continue
        connector = connectors.get(pipeline_index)
        if connector == "&&":
            if accumulated is False:
                skipped.add(pipeline_index)
                continue
            accumulated = truth if accumulated is True else None
            continue
        if connector == "||":
            if accumulated is True:
                skipped.add(pipeline_index)
                continue
            accumulated = truth if accumulated is False else None
            continue
        accumulated = truth
    return skipped


def _if_branch_effects(pipelines: list[list[list[str]]]) -> tuple[set[int], set[int]]:
    extra_conditional: set[int] = set()
    skipped: set[int] = set()
    if_stack: list[tuple[bool | None, str | None]] = []
    for pipeline_index, pipeline in enumerate(pipelines):
        segment = pipeline[0] if pipeline else []
        first = segment[0].strip("\"'").lower() if segment else ""
        if first == "if":
            condition = segment[1].strip("\"'").lower() if len(segment) > 1 else ""
            truth = True if condition == "true" else False if condition == "false" else None
            if_stack.append((truth, None))
            continue
        if first == "fi":
            if if_stack:
                _ = if_stack.pop()
            continue
        if first in {"then", "else", "elif"} and if_stack:
            truth, _branch = if_stack[-1]
            if first == "elif":
                truth = None
            branch = "else" if first == "else" else "then"
            if_stack[-1] = (truth, branch)
        if not if_stack or if_stack[-1][1] is None:
            continue
        truth, branch = if_stack[-1]
        if truth is None:
            extra_conditional.add(pipeline_index)
        elif (branch == "then" and not truth) or (branch == "else" and truth):
            skipped.add(pipeline_index)
    return extra_conditional, skipped


def pipeline_control_flow(
    parts: list[str],
    pipelines: list[list[list[str]]],
    *,
    primary_command: PrimaryCommand,
) -> tuple[frozenset[int], frozenset[int]]:
    """Return conditional and statically skipped pipeline indexes."""

    connectors = conditional_pipeline_connectors(parts)
    skipped = _and_or_skipped_indexes(pipelines, connectors, primary_command)
    extra_conditional, if_skipped = _if_branch_effects(pipelines)
    return frozenset(set(connectors) | extra_conditional), frozenset(skipped | if_skipped)
