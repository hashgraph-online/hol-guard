"""Conservative whole-command recognition for routine Git inspection chains."""

from __future__ import annotations

import re
from typing import Final

from .shell_execution_context import ShellExecutionContext, ShellExecutionSegment

_REF: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}")
_REPOSITORY_DIR: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_BOUND: Final = 1000


def is_low_risk_compound_git_inspection(context: ShellExecutionContext) -> bool:
    """Recognize a deterministic leading-cd Git refresh and inspection chain."""

    if not context.complete or len(context.segments) < 2:
        return False
    if not _leading_literal_cd(context.segments[0]):
        return False
    saw_git = False
    for index, segment in enumerate(context.segments[1:], start=1):
        if any(control not in {"&&", "|"} for control in (*segment.control_before, *segment.control_after)):
            return False
        command = segment.tokens[0] if segment.tokens else ""
        if command == "git":
            if not is_low_risk_git_inspection_segment(segment):
                return False
            saw_git = True
            continue
        if command == "echo":
            if not _safe_echo_segment(segment):
                return False
            continue
        if command in {"head", "tail"}:
            if not _safe_bound_segment(segment, previous=context.segments[index - 1]):
                return False
            continue
        return False
    return saw_git


def _leading_literal_cd(segment: ShellExecutionSegment) -> bool:
    return bool(
        not segment.control_before
        and segment.directory_operation == "cd"
        and len(segment.tokens) == 2
        and segment.tokens[0] == "cd"
    )


def is_low_risk_git_inspection_segment(segment: ShellExecutionSegment) -> bool:
    """Recognize one bounded Git refresh or inspection segment."""

    tokens = _without_stderr_merge(segment.tokens)
    if tokens is None or len(tokens) < 2:
        return False
    operation_index = 1
    if tokens[1] == "-C":
        if len(tokens) < 4 or _REPOSITORY_DIR.fullmatch(tokens[2]) is None:
            return False
        operation_index = 3
    operation = tokens[operation_index]
    args = tokens[operation_index + 1 :]
    if operation == "fetch":
        return len(args) == 2 and args[0] == "origin" and _safe_ref(args[1])
    if operation == "log":
        return len(args) == 3 and set(args[1:]) == {"-1", "--oneline"} and _safe_ref(args[0])
    if operation == "status":
        return bool(args) and all(arg in {"--short", "--branch", "--porcelain", "--porcelain=v1"} for arg in args)
    if operation == "branch":
        return args in {("--show-current",), ("--list",)}
    if operation == "rev-parse":
        return args in {("--show-toplevel",), ("--show-prefix",), ("--is-inside-work-tree",), ("HEAD",)}
    if operation == "diff":
        return bool(args) and all(
            arg in {"--check", "--stat", "--name-only", "--name-status", "--cached", "HEAD"} or _safe_ref(arg)
            for arg in args
        )
    if operation == "show":
        return bool(args) and all(
            arg in {"--stat", "--oneline", "--name-only", "--name-status", "HEAD"} or _safe_ref(arg) for arg in args
        )
    return False


def _without_stderr_merge(tokens: tuple[str, ...]) -> tuple[str, ...] | None:
    redirects = tuple(token for token in tokens if token == "2>&1")
    if len(redirects) > 1:
        return None
    if any(any(marker in token for marker in (">", "<")) and token != "2>&1" for token in tokens):
        return None
    return tuple(token for token in tokens if token != "2>&1")


def _safe_ref(value: str) -> bool:
    return _REF.fullmatch(value) is not None and ".." not in value and not value.endswith((".", "/"))


def _safe_echo_segment(segment: ShellExecutionSegment) -> bool:
    return bool(
        len(segment.tokens) >= 2
        and segment.control_before == ("&&",)
        and segment.control_after == ("&&",)
        and all(token not in {"-e", "-E", "-n"} and not _dynamic(token) for token in segment.tokens[1:])
    )


def _safe_bound_segment(segment: ShellExecutionSegment, *, previous: ShellExecutionSegment) -> bool:
    if segment.control_before != ("|",) or len(segment.tokens) != 2:
        return False
    if not previous.tokens or previous.tokens[0] != "git" or previous.control_after != ("|",):
        return False
    count = segment.tokens[1]
    if not count.startswith("-") or not count[1:].isdigit():
        return False
    return 1 <= int(count[1:]) <= _BOUND


def _dynamic(value: str) -> bool:
    return any(marker in value for marker in ("$", "`", "<", ">", "|", ";", "&", "\x00"))


__all__ = ("is_low_risk_compound_git_inspection", "is_low_risk_git_inspection_segment")
