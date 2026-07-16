"""Source-faithful shell heredoc and command-substitution structures."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class ShellHeredoc:
    """One shell heredoc with exact source spans and unmodified body text."""

    delimiter: str
    body: str
    operator_start: int
    declaration_end: int
    body_start: int
    body_end: int
    end: int
    quoted: bool
    strip_tabs: bool


@dataclass(frozen=True, slots=True)
class ShellCommandSubstitution:
    """One executable shell substitution with exact source spans."""

    kind: Literal["dollar", "backtick"]
    body: str
    start: int
    body_start: int
    body_end: int
    end: int


_HEREDOC_OPERATOR_PATTERN = re.compile(
    r"(?<!<)(?P<operator><<-?)[ \t]*(?P<quote>['\"]?)(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)"
)


def extract_heredocs(command: str) -> tuple[ShellHeredoc, ...]:
    """Extract bounded POSIX heredocs without interpreting their contents."""

    if not command:
        return ()
    results: list[ShellHeredoc] = []
    scan_cursor = 0
    while scan_cursor < len(command):
        line_end = command.find("\n", scan_cursor)
        if line_end < 0:
            line_end = len(command)
        pending = _heredoc_declarations(command[scan_cursor:line_end])
        if not pending:
            if line_end == len(command):
                break
            scan_cursor = line_end + 1
            continue
        if line_end == len(command):
            break
        body_cursor = line_end + 1
        for match in pending:
            delimiter = match.group("delimiter")
            strip_tabs = match.group("operator") == "<<-"
            body_start = body_cursor
            closing_start, closing_end = _find_heredoc_closing_line(
                command,
                body_start=body_start,
                delimiter=delimiter,
                strip_tabs=strip_tabs,
            )
            results.append(
                ShellHeredoc(
                    delimiter=delimiter,
                    body=command[body_start:closing_start],
                    operator_start=scan_cursor + match.start(),
                    declaration_end=scan_cursor + match.end(),
                    body_start=body_start,
                    body_end=closing_start,
                    end=closing_end,
                    quoted=bool(match.group("quote")),
                    strip_tabs=strip_tabs,
                )
            )
            body_cursor = closing_end
        scan_cursor = body_cursor
    return tuple(results)


def _heredoc_declarations(line: str) -> tuple[re.Match[str], ...]:
    matches: list[re.Match[str]] = []
    state = ShellScanState()
    index = 0
    while index < len(line):
        next_index = state.advance(line, index)
        if next_index != index + 1:
            index = next_index
            continue
        if state.is_top_level and line.startswith("<<", index):
            match = _HEREDOC_OPERATOR_PATTERN.match(line, index)
            if match is not None:
                matches.append(match)
                index = match.end()
                continue
        index += 1
    return tuple(matches)


def _find_heredoc_closing_line(
    command: str,
    *,
    body_start: int,
    delimiter: str,
    strip_tabs: bool,
) -> tuple[int, int]:
    cursor = body_start
    while cursor <= len(command):
        line_end = command.find("\n", cursor)
        if line_end < 0:
            line_end = len(command)
        candidate = command[cursor:line_end]
        comparable = candidate.lstrip("\t") if strip_tabs else candidate
        if comparable == delimiter:
            return cursor, line_end + (1 if line_end < len(command) else 0)
        if line_end == len(command):
            break
        cursor = line_end + 1
    return len(command), len(command)


def mask_heredoc_bodies(command: str, heredocs: tuple[ShellHeredoc, ...]) -> str:
    """Hide heredoc bodies from top-level shell segmentation while retaining offsets."""

    if not heredocs:
        return command
    characters = list(command)
    for heredoc in heredocs:
        for index in range(heredoc.body_start, heredoc.end):
            if characters[index] != "\n":
                characters[index] = " "
    return "".join(characters)


def mask_complete_heredocs(command: str, heredocs: tuple[ShellHeredoc, ...]) -> str:
    """Hide heredoc declarations and bodies from compatibility text detectors."""

    characters = list(mask_heredoc_bodies(command, heredocs))
    for heredoc in heredocs:
        for index in range(heredoc.operator_start, heredoc.declaration_end):
            if characters[index] != "\n":
                characters[index] = " "
    return "".join(characters)


def extract_command_substitutions(command: str) -> tuple[str, ...]:
    """Return commands inside top-level `$()` and backtick substitutions."""

    return tuple(item.body for item in extract_command_substitution_spans(command))


def extract_command_substitution_spans(command: str) -> tuple[ShellCommandSubstitution, ...]:
    """Return top-level substitutions with exact source spans."""

    return _extract_command_substitution_spans(command, respect_quotes=True)


def extract_expanded_heredoc_substitution_spans(command: str) -> tuple[ShellCommandSubstitution, ...]:
    """Return substitutions expanded by an unquoted heredoc delimiter."""

    return _extract_command_substitution_spans(command, respect_quotes=False)


def _extract_command_substitution_spans(
    command: str,
    *,
    respect_quotes: bool,
) -> tuple[ShellCommandSubstitution, ...]:
    substitutions: list[ShellCommandSubstitution] = []
    index = 0
    quote: str | None = None
    while index < len(command):
        char = command[index]
        if char == "\\":
            index += 2
            continue
        if respect_quotes and char == "'" and quote is None:
            quote = "'"
            index += 1
            continue
        if respect_quotes and char == "'" and quote == "'":
            quote = None
            index += 1
            continue
        if respect_quotes and char == '"' and quote is None:
            quote = '"'
            index += 1
            continue
        if respect_quotes and char == '"' and quote == '"':
            quote = None
            index += 1
            continue
        if quote != "'" and command.startswith("$(", index):
            extracted, end_index = _extract_parenthesized(command, index + 2)
            if extracted.strip():
                body_start = index + 2
                leading = len(extracted) - len(extracted.lstrip())
                trailing = len(extracted.rstrip())
                substitutions.append(
                    ShellCommandSubstitution(
                        kind="dollar",
                        body=extracted.strip(),
                        start=index,
                        body_start=body_start + leading,
                        body_end=body_start + trailing,
                        end=min(len(command), end_index + 1),
                    )
                )
            index = end_index + 1
            continue
        if quote != "'" and char == "`":
            extracted, end_index = _extract_backtick(command, index + 1)
            if extracted.strip():
                body_start = index + 1
                leading = len(extracted) - len(extracted.lstrip())
                trailing = len(extracted.rstrip())
                substitutions.append(
                    ShellCommandSubstitution(
                        kind="backtick",
                        body=extracted.strip(),
                        start=index,
                        body_start=body_start + leading,
                        body_end=body_start + trailing,
                        end=min(len(command), end_index + 1),
                    )
                )
            index = end_index + 1
            continue
        index += 1
    return tuple(substitutions)


def _extract_parenthesized(command: str, start: int) -> tuple[str, int]:
    depth = 1
    index = start
    quote: str | None = None
    while index < len(command):
        char = command[index]
        if char == "\\":
            index += 2
            continue
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            index += 1
            continue
        if quote is None and char == "(":
            depth += 1
        elif quote is None and char == ")":
            depth -= 1
            if depth == 0:
                return command[start:index], index
        index += 1
    return command[start:], len(command)


def _extract_backtick(command: str, start: int) -> tuple[str, int]:
    index = start
    while index < len(command):
        char = command[index]
        if char == "\\":
            index += 2
            continue
        if char == "`":
            return command[start:index], index
        index += 1
    return command[start:], len(command)


class ShellScanState:
    """Track quoting and substitutions while scanning shell source."""

    def __init__(self) -> None:
        self.quote: str | None = None
        self.subshell_depth: int = 0
        self.in_backtick: bool = False

    @property
    def is_top_level(self) -> bool:
        return self.quote is None and self.subshell_depth == 0 and not self.in_backtick

    def advance(self, command: str, index: int) -> int:
        char = command[index]
        if char == "\\":
            return min(len(command), index + 2)
        if char == "`" and self.quote != "'":
            self.in_backtick = not self.in_backtick
            return index + 1
        if self.in_backtick:
            return index + 1
        if self.quote == "'":
            if char == "'":
                self.quote = None
            return index + 1
        if char == "'" and self.quote is None:
            self.quote = "'"
            return index + 1
        if char == '"':
            if self.quote == '"':
                self.quote = None
            elif self.quote is None:
                self.quote = '"'
            return index + 1
        if self.quote != "'" and command.startswith("$(", index):
            _extracted, end_index = _extract_parenthesized(command, index + 2)
            return min(len(command), end_index + 1)
        if self.quote is None and char == "(":
            self.subshell_depth += 1
        elif self.quote is None and char == ")" and self.subshell_depth > 0:
            self.subshell_depth -= 1
        return index + 1
