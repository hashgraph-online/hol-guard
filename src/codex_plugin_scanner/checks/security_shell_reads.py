"""Bounded shell credential reads are references, not embedded secret values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .security_secret_patterns import DOCUMENTATION_EXTS

_VARIABLE = r"(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})"
_ENV_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_ENV_ARG = rf"(?:{_VARIABLE}|{_ENV_NAME}|\"(?:{_VARIABLE}|{_ENV_NAME})\")"
_SCOPE_NAME = r"[A-Za-z0-9_][A-Za-z0-9_.:@-]*"
_SCOPE_ARG = rf"(?:{_VARIABLE}|{_SCOPE_NAME}|\"(?:{_VARIABLE}|{_SCOPE_NAME})\")"
_SCOPE_OPTION = rf"[ \t]+--(?:project|configuration|account|impersonate-service-account)(?:=|[ \t]+){_SCOPE_ARG}"
_GCLOUD_READ = (
    rf"gcloud(?:{_SCOPE_OPTION})*[ \t]+auth[ \t]+(?:application-default[ \t]+)?print-access-token(?:{_SCOPE_OPTION})*"
)
_READ = rf"(?:printenv[ \t]+{_ENV_ARG}|{_GCLOUD_READ})"
_QUIET_FAILURE = r"(?:[ \t]+2>/dev/null)?(?:[ \t]+\|\|[ \t]+true)?"
_ASSIGNMENT_RE = re.compile(
    rf"(?:^|;)[ \t]*(?:(?:then|else|do)[ \t]+)?(?:export[ \t]+)?"
    rf"(?P<name>{_ENV_NAME})=\"(?P<value>\$\({_READ}{_QUIET_FAILURE}\))\""
    r"(?=[ \t]*(?:$|;)|[ \t]+#)",
    re.MULTILINE,
)
_FENCE_RE = re.compile(r"^[ \t]{0,3}(?P<marker>`{3,}|~{3,})(?P<info>[^\r\n]*)$", re.MULTILINE)
_SHELL_LANGUAGES = frozenset({"bash", "sh", "shell"})
_CONDITIONAL_PARAMETER = re.compile(rf"\$\{{{_ENV_NAME}:[+-]")
_UNBRACED_VARIABLE = re.compile(rf"\${_ENV_NAME}")


@dataclass
class _ShellContext:
    quote: str | None = None
    parentheses: int = 0
    word_start: bool = True
    parameter: bool = False


def _statement_read_spans(content: str, start: int, end: int) -> list[tuple[int, int]]:
    """Accept candidates only at unquoted, unescaped shell statement boundaries.

    Track nested command substitutions separately from their containing quotes.
    Unsupported here-documents, backticks and extended quoting stop exemptions
    for the rest of this range; the ordinary secret detectors still inspect it.
    This lexical check does not execute or interpret any shell command.
    """
    candidates = {match.start(): match for match in _ASSIGNMENT_RE.finditer(content, start, end)}
    if not candidates:
        return []
    contexts = [_ShellContext()]
    statement_start = start
    spans: list[tuple[int, int]] = []
    index = start
    while index < end:
        context = contexts[-1]
        char = content[index]
        top_level = len(contexts) == 1 and context.quote is None and context.parentheses == 0
        if top_level and (index == statement_start or char == ";") and index in candidates:
            match = candidates[index]
            spans.append((match.start("name"), match.end("value") + 1))
        if context.quote == "'":
            if char == "'":
                context.quote = None
            index += 1
            continue
        if context.parameter and (char in "'\\" or content.startswith("$(", index)):
            break
        if char == "\\":
            # A continued physical line or escaped semicolon is not a boundary.
            if index + 1 < end and content[index + 1] != "\n":
                context.word_start = False
            index += 2
            continue
        if char == "#" and context.quote is None and context.word_start and not context.parameter:
            newline = content.find("\n", index, end)
            index = newline if newline >= 0 else end
            continue
        if char == "`" or (context.quote is None and content.startswith(("$'", '$"', "<<"), index)):
            break
        if context.parameter and char == "$" and not content.startswith("${", index):
            variable = _UNBRACED_VARIABLE.match(content, index)
            if variable is None:
                break
            index = variable.end()
            continue
        if content.startswith("${", index):
            closing = content.find("}", index + 2, end)
            if closing < 0:
                break
            parameter_text = _UNBRACED_VARIABLE.sub("", content[index + 2 : closing])
            if any(symbol in parameter_text for symbol in "'\"`{}\\$"):
                # A closed, unquoted conditional parameter can contain quoted
                # text and nested simple references. No assignment inside it
                # qualifies. Other expansion grammar remains conservative.
                if context.quote is not None or len(contexts) >= 64 or not _CONDITIONAL_PARAMETER.match(content, index):
                    break
                context.word_start = False
                contexts.append(_ShellContext(parameter=True))
                index += 2
                continue
            context.word_start = False
            index = closing + 1
            continue
        if content.startswith("$(", index):
            if len(contexts) >= 64:
                break
            context.word_start = False
            contexts.append(_ShellContext())
            index += 2
            continue
        if char == '"':
            context.quote = None if context.quote == '"' else '"'
            context.word_start = False
        elif char == "'" and context.quote is None:
            context.quote = "'"
            context.word_start = False
        elif context.quote is None:
            if char == "}" and context.parameter:
                _ = contexts.pop()
            elif char == "(" and not context.parameter:
                context.parentheses += 1
            elif char == ")" and not context.parameter:
                if context.parentheses:
                    context.parentheses -= 1
                elif len(contexts) > 1:
                    _ = contexts.pop()
            if char == "\n" and top_level:
                statement_start = index + 1
            context.word_start = char in " \t\n;|&()<>"
        index += 1
    return spans


def _shell_code_ranges(relative_path: Path, content: str) -> tuple[tuple[int, int], ...]:
    """Require a shell file or a closed, explicitly shell-tagged Markdown fence."""
    suffix = relative_path.suffix.lower()
    if suffix in {".sh", ".bash"}:
        return ((0, len(content)),)
    if suffix not in DOCUMENTATION_EXTS:
        return ()
    ranges: list[tuple[int, int]] = []
    opened: tuple[str, int, int, bool] | None = None
    for fence in _FENCE_RE.finditer(content):
        marker = fence.group("marker")
        info = fence.group("info").strip()
        if opened is None:
            language = info.split(maxsplit=1)[0] if info else ""
            opened = (marker[0], len(marker), fence.end(), language in _SHELL_LANGUAGES)
        elif not info and marker[0] == opened[0] and len(marker) >= opened[1]:
            if opened[3]:
                ranges.append((opened[2], fence.start()))
            opened = None
    return tuple(ranges)


def _shell_credential_read_spans(relative_path: Path, content: str) -> tuple[tuple[int, int], ...]:
    """Prove complete assignments before exempting any generic detector match.

    This is a small allowlist, not a shell evaluator. It admits one environment
    lookup or one access-token command, optional stderr suppression and an empty
    failure result. Extra commands, literal prefixes/suffixes, defaults and
    arbitrary cloud flags do not qualify. Provider-secret detectors still scan
    the same text independently.
    """
    if "$(" not in content:
        return ()
    return tuple(
        span
        for start, end in _shell_code_ranges(relative_path, content)
        for span in _statement_read_spans(content, start, end)
    )
