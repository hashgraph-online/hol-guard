"""Local data-flow source and sink helpers for Guard runtime detectors."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise
from typing import Literal

DataSourceType = Literal[
    "secret_file",
    "env",
    "clipboard",
    "keychain",
    "command_output",
    "prompt",
    "generated_file",
]
DataSinkType = Literal[
    "http_post",
    "http_get_query",
    "dns",
    "webhook",
    "paste",
    "git_remote",
    "package_publish",
    "clipboard",
    "local_log",
]

_VALID_SOURCE_TYPES = frozenset(
    {
        "secret_file",
        "env",
        "clipboard",
        "keychain",
        "command_output",
        "prompt",
        "generated_file",
    }
)
_VALID_SINK_TYPES = frozenset(
    {
        "http_post",
        "http_get_query",
        "dns",
        "webhook",
        "paste",
        "git_remote",
        "package_publish",
        "clipboard",
        "local_log",
    }
)
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_INPUT_REDIRECT_PATTERN = re.compile(r"(?<![<])(?:\d*)<\s*(?![<&])(?P<target>\"[^\"]+\"|'[^']+'|[^ \t\r\n;&|<>]+)")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>)}\]]+", re.IGNORECASE)
_CURL_METHOD_PATTERN = re.compile(
    r"(?i)(?:^|[\s;&|])(?:curl|curl\.exe)\b[^\r\n;&|]*?"
    + r"(?:--request(?:=|\s+)|-X\s*)['\"]?(?P<method>[a-z]+)['\"]?\b"
)
_FETCH_METHOD_PATTERN = re.compile(r"(?i)\bmethod\s*:\s*['\"](?P<method>[a-z]+)['\"]")
_REQUESTS_METHOD_PATTERN = re.compile(r"(?i)\brequests\.(?P<method>get|post|put|patch|delete|head|options)\s*\(")
_CURL_DATA_PATTERN = re.compile(
    r"(?i)(?:^|[\s;&|])(?:curl|curl\.exe)\b[^\r\n;&|]*(?:\s-d\b|\s--data(?:-raw|-binary|-urlencode)?\b)"
)


@dataclass(frozen=True, slots=True)
class DataSource:
    """Redacted local data source referenced by a runtime action."""

    source_type: DataSourceType
    value: str
    description: str
    evidence: str | None = None

    def __post_init__(self) -> None:
        if self.source_type not in _VALID_SOURCE_TYPES:
            raise ValueError("source_type must be a known Guard data source type")
        if not self.value.strip():
            raise ValueError("value must be a non-empty redacted source identifier")
        if not self.description.strip():
            raise ValueError("description must be a non-empty source description")

    def to_dict(self) -> dict[str, object]:
        return {
            "source_type": self.source_type,
            "value": self.value,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class DataSink:
    """Redacted destination where local data may leave the trusted context."""

    sink_type: DataSinkType
    value: str
    description: str
    method: str | None = None
    evidence: str | None = None

    def __post_init__(self) -> None:
        if self.sink_type not in _VALID_SINK_TYPES:
            raise ValueError("sink_type must be a known Guard data sink type")
        if not self.value.strip():
            raise ValueError("value must be a non-empty redacted sink identifier")
        if not self.description.strip():
            raise ValueError("description must be a non-empty sink description")
        if self.method is not None:
            normalized = self.method.upper()
            if normalized not in _HTTP_METHODS:
                raise ValueError("method must be a known HTTP method")
            object.__setattr__(self, "method", normalized)

    def to_dict(self) -> dict[str, object]:
        return {
            "sink_type": self.sink_type,
            "value": self.value,
            "description": self.description,
            "method": self.method,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class ShellPipe:
    """Top-level shell pipe edge between adjacent command segments."""

    left: str
    right: str


@dataclass(frozen=True, slots=True)
class ShellHeredoc:
    """One shell heredoc with source spans preserved."""

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


def extract_input_redirects(command: str) -> tuple[str, ...]:
    """Return file targets read through shell input redirects."""

    targets: list[str] = []
    for segment in _split_top_level_commands(command):
        for match in _INPUT_REDIRECT_PATTERN.finditer(segment):
            target = _strip_shell_quotes(match.group("target"))
            if target and not target.startswith(("(", "&")):
                targets.append(target)
    return _dedupe(targets)


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
            body = command[body_start:closing_start]
            if strip_tabs:
                body = "\n".join(line.lstrip("\t") for line in body.split("\n"))
            results.append(
                ShellHeredoc(
                    delimiter=delimiter,
                    body=body,
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
    state = _ShellScanState()
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

    substitutions: list[ShellCommandSubstitution] = []
    index = 0
    quote: str | None = None
    while index < len(command):
        char = command[index]
        if char == "\\":
            index += 2
            continue
        if char == "'" and quote is None:
            quote = "'"
            index += 1
            continue
        if char == "'" and quote == "'":
            quote = None
            index += 1
            continue
        if char == '"' and quote is None:
            quote = '"'
            index += 1
            continue
        if char == '"' and quote == '"':
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


def extract_http_methods(command: str) -> tuple[str, ...]:
    """Return explicit or strongly implied HTTP methods referenced by shell text."""

    methods: list[str] = []
    for pattern in (_CURL_METHOD_PATTERN, _FETCH_METHOD_PATTERN, _REQUESTS_METHOD_PATTERN):
        for match in pattern.finditer(command):
            _append_http_method(methods, match.group("method"))
    if _CURL_DATA_PATTERN.search(command):
        _append_http_method(methods, "POST")
    return _dedupe(methods)


def extract_urls(command: str) -> tuple[str, ...]:
    """Return HTTP(S) URLs while preserving first-seen order."""

    urls = [_strip_url_suffix(match.group(0)) for match in _URL_PATTERN.finditer(command)]
    return _dedupe(url for url in urls if url)


def extract_url_ranges(command: str) -> tuple[tuple[int, int], ...]:
    """Return HTTP(S) URL character ranges in shell text."""

    return tuple(
        (match.start(), match.start() + len(_strip_url_suffix(match.group(0))))
        for match in _URL_PATTERN.finditer(command)
    )


def _append_http_method(methods: list[str], method: str) -> None:
    normalized = method.upper()
    if normalized in _HTTP_METHODS:
        methods.append(normalized)


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


def _strip_url_suffix(value: str) -> str:
    return value.rstrip(".,;")


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


class _ShellScanState:
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
