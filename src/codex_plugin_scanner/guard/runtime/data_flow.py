"""Local data-flow source and sink helpers for Guard runtime detectors."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

from .shell_structure import (
    ShellCommandSubstitution as ShellCommandSubstitution,
)
from .shell_structure import (
    ShellHeredoc as ShellHeredoc,
)
from .shell_structure import (
    ShellScanState as _ShellScanState,
)
from .shell_structure import (
    extract_command_substitution_spans as extract_command_substitution_spans,
)
from .shell_structure import (
    extract_command_substitutions as extract_command_substitutions,
)
from .shell_structure import (
    extract_expanded_heredoc_substitution_spans as extract_expanded_heredoc_substitution_spans,
)
from .shell_structure import (
    extract_heredocs as extract_heredocs,
)
from .shell_structure import (
    mask_complete_heredocs as mask_complete_heredocs,
)
from .shell_structure import (
    mask_heredoc_bodies as mask_heredoc_bodies,
)

_INPUT_REDIRECT_PATTERN = re.compile(r"(?<![<])(?:\d*)<\s*(?![<&])(?P<target>\"[^\"]+\"|'[^']+'|[^ \t\r\n;&|<>]+)")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>)}\]]+", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ShellPipe:
    """Top-level shell pipe edge between adjacent command segments."""

    left: str
    right: str


def extract_input_redirects(command: str) -> tuple[str, ...]:
    """Return file targets read through shell input redirects."""

    targets: list[str] = []
    for segment in _split_top_level_commands(command):
        for match in _INPUT_REDIRECT_PATTERN.finditer(segment):
            target = _strip_shell_quotes(match.group("target"))
            if target and not target.startswith(("(", "&")):
                targets.append(target)
    return _dedupe(targets)


def extract_pipes(command: str) -> tuple[ShellPipe, ...]:
    """Return adjacent top-level pipe edges, ignoring logical OR and quoted pipes."""

    pipes: list[ShellPipe] = []
    for segment in _split_top_level_commands(command):
        parts = _split_top_level_pipes(segment)
        if len(parts) < 2:
            continue
        for left, right in pairwise(parts):
            stripped_left = left.strip()
            stripped_right = right.strip()
            if stripped_left and stripped_right:
                pipes.append(ShellPipe(left=stripped_left, right=stripped_right))
    return tuple(pipes)


def extract_command_segments(command: str) -> tuple[str, ...]:
    """Return top-level shell command segments split on command separators."""

    return _split_top_level_commands(command)


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _strip_shell_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped


def _split_top_level_commands(command: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    index = 0
    state = _ShellScanState()
    while index < len(command):
        next_index = state.advance(command, index)
        if next_index != index + 1:
            index = next_index
            continue
        if state.is_top_level and command[index] in {";", "\n"}:
            _append_segment(parts, command[start:index])
            start = index + 1
        elif state.is_top_level and (command.startswith("&&", index) or command.startswith("||", index)):
            _append_segment(parts, command[start:index])
            start = index + 2
            index += 1
        elif state.is_top_level and command[index] == "&" and _is_background_separator(command, index):
            _append_segment(parts, command[start:index])
            start = index + 1
        index += 1
    _append_segment(parts, command[start:])
    return tuple(parts)


def _is_background_separator(command: str, index: int) -> bool:
    previous_char = command[index - 1] if index > 0 else ""
    next_char = command[index + 1] if index + 1 < len(command) else ""
    return previous_char not in {">", "<", "|"} and next_char not in {"&", ">"}


def _split_top_level_pipes(command: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    index = 0
    state = _ShellScanState()
    while index < len(command):
        next_index = state.advance(command, index)
        if next_index != index + 1:
            index = next_index
            continue
        if state.is_top_level and command[index] == "|":
            previous_is_pipe = index > 0 and command[index - 1] == "|"
            next_is_pipe = index + 1 < len(command) and command[index + 1] == "|"
            if not previous_is_pipe and not next_is_pipe:
                _append_segment(parts, command[start:index])
                start = index + 2 if index + 1 < len(command) and command[index + 1] == "&" else index + 1
        index += 1
    _append_segment(parts, command[start:])
    return tuple(parts)


def _append_segment(parts: list[str], value: str) -> None:
    stripped = value.strip()
    if stripped:
        parts.append(stripped)
