"""Typed validation for non-executing GitHub Actions inspection workflows."""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Final, Literal

from .git_execution_safety import git_binary_path_is_trusted
from .github_capability_interaction import github_capability_requires_confirmation
from .github_command_capabilities import classify_github_cli

_ValueKind = Literal["number", "text"]
_NAME: Final = r"[A-Za-z_][A-Za-z0-9_]*"
_VARIABLE: Final = re.compile(rf"\$(?:\{{(?P<braced>{_NAME})\}}|(?P<plain>{_NAME}))")
_REPOSITORY_PART: Final = r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})"
_REPOSITORY: Final = rf"{_REPOSITORY_PART}/{_REPOSITORY_PART}"
_ACTIONS_ENDPOINT: Final = re.compile(
    rf"repos/{_REPOSITORY}/actions/(?:runs/[1-9][0-9]*/jobs|jobs/[1-9][0-9]*(?:/logs)?)"
)
_JOB_ID_QUERY: Final = re.compile(r"\.jobs\[\]\.id")
_FILTERED_JOB_ID_QUERY: Final = re.compile(r'\.jobs\[\]\|select\(\.name\|test\("(?:[^"\\]|\\.){1,200}"\)\)\|\.id')
_MAX_FILTER_LINES: Final = 100
_ACTIONS_LOG_METADATA_FIELDS: Final = frozenset(
    {
        "UV_PYTHON_INSTALL_DIR",
        "toolcache",
        "pythonLoc",
        "hostedtoolcache",
    }
)
_EXECUTION_ROUTING_ENVIRONMENT: Final = (
    "BASH_ENV",
    "CURL_CA_BUNDLE",
    "ENV",
    "GH_CONFIG_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "ZDOTDIR",
    "all_proxy",
    "https_proxy",
    "http_proxy",
)


def is_nonexecuting_github_actions_read_workflow(command_text: str, *, cwd: Path | None = None) -> bool:
    """Prove a small shell workflow reads Actions data without executable data flow.

    Fixed filters constrain emitted output and shell behavior. Network response
    size is not an approval boundary for an authenticated GitHub.com read.
    """

    if not command_text.strip() or "`" in command_text or "\\\n" in command_text:
        return False
    if os.environ.get("GH_HOST", "").strip().casefold() not in {"", "github.com"}:
        return False
    if any(os.environ.get(key, "").strip() not in {"", "cat"} for key in ("GH_PAGER", "PAGER")):
        return False
    if os.environ.get("RIPGREP_CONFIG_PATH", "").strip() or any(
        os.environ.get(key, "").strip() for key in _EXECUTION_ROUTING_ENVIRONMENT
    ):
        return False
    if any(key.startswith(("BASH_FUNC_", "DYLD_", "LD_")) for key in os.environ):
        return False
    values: dict[str, _ValueKind] = {}
    control_stack: list[str] = []
    saw_github_read = False
    for raw_line in command_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        literal_assignment = re.fullmatch(rf"(?P<name>{_NAME})=(?P<value>[1-9][0-9]*)", line)
        if literal_assignment is not None:
            values[literal_assignment.group("name")] = "number"
            continue
        assignment = re.fullmatch(rf"(?P<name>{_NAME})=\$\((?P<body>.*)\)", line)
        if assignment is not None:
            result_kind = _safe_github_read_pipeline(assignment.group("body"), values, cwd=cwd)
            if result_kind is None:
                return False
            values[assignment.group("name")] = result_kind
            saw_github_read = True
            continue
        loop = re.fullmatch(rf"for\s+(?P<name>{_NAME})\s+in\s+\$\((?P<body>.*)\);\s*do", line)
        if loop is not None:
            if _safe_github_read_pipeline(loop.group("body"), values, cwd=cwd) != "number":
                return False
            values[loop.group("name")] = "number"
            control_stack.append("for")
            saw_github_read = True
            continue
        if line == "done":
            if not control_stack or control_stack.pop() != "for":
                return False
            continue
        conditional = re.fullmatch(r"if\s+(?P<body>.*);\s*then", line)
        if conditional is not None:
            if not _safe_text_filter_pipeline(conditional.group("body"), values):
                return False
            control_stack.append("if")
            continue
        if line == "fi":
            if not control_stack or control_stack.pop() != "if":
                return False
            continue
        if line.startswith("echo ") or line == "echo":
            if not _safe_echo(line, values):
                return False
            continue
        result_kind = _safe_github_read_pipeline(line, values, cwd=cwd)
        if result_kind is None:
            return False
        saw_github_read = True
    return saw_github_read and not control_stack


def _safe_github_read_pipeline(
    command_text: str,
    values: dict[str, _ValueKind],
    *,
    cwd: Path | None = None,
) -> _ValueKind | None:
    segments = _pipeline_segments(command_text)
    if not segments or not segments[0] or segments[0][0] != "gh":
        return None
    if _safe_actions_log_metadata_pipeline(segments, cwd=cwd):
        return "text"
    substituted = _substitute_number_variables(segments[0], values)
    if substituted is None:
        return None
    github_tokens = _without_safe_stderr_redirect(substituted)
    if github_tokens is None or not _safe_actions_github_command(github_tokens):
        return None
    for segment in segments[1:]:
        if not _safe_emitted_output_filter(segment):
            return None
    if segments[1:] and not _filters_bound_emitted_matches(segments[1:]):
        return None
    return _github_output_kind(github_tokens)


def _safe_actions_log_metadata_pipeline(segments: list[list[str]], *, cwd: Path | None) -> bool:
    if len(segments) != 4:
        return False
    execution_cwd = cwd or Path.cwd()
    github_tokens = _without_safe_stderr_redirect(segments[0])
    if github_tokens is None or not _safe_run_log_metadata_args(github_tokens):
        return False
    grep, sort, head = segments[1:]
    return (
        _trusted_pipeline_executables(("gh", "grep", "sort", "head"), cwd=execution_cwd)
        and _safe_log_metadata_grep(grep)
        and sort == ["sort", "-u"]
        and len(head) == 2
        and head[0] == "head"
        and _bounded_count(head[1])
    )


def _trusted_pipeline_executables(names: tuple[str, ...], *, cwd: Path) -> bool:
    for name in names:
        executable = _path_command_for_cwd(name, cwd=cwd)
        try:
            resolved = Path(executable).resolve(strict=True) if executable is not None else None
        except (OSError, RuntimeError):
            return False
        if resolved is None or not git_binary_path_is_trusted(resolved, cwd=cwd):
            return False
    return True


def _path_command_for_cwd(name: str, *, cwd: Path) -> str | None:
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        directory = Path(entry or ".")
        if not directory.is_absolute():
            directory = cwd / directory
        candidate = directory / name
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            continue
    return None


def _safe_run_log_metadata_args(tokens: list[str]) -> bool:
    if not tokens or tokens[0] != "gh":
        return False
    args = tokens[1:]
    if len(args) < 2 or args[0] not in {"-R", "--repo"} or re.fullmatch(_REPOSITORY, args[1]) is None:
        return False
    args = args[2:]
    return bool(
        len(args) == 4
        and args[:2] == ["run", "view"]
        and re.fullmatch(r"[1-9][0-9]*", args[2]) is not None
        and args[3] == "--log"
    )


def _safe_log_metadata_grep(tokens: list[str]) -> bool:
    if len(tokens) != 3 or tokens[:2] != ["grep", "-iE"]:
        return False
    fields = tokens[2].split("|")
    return bool(fields) and len(fields) == len(set(fields)) and set(fields).issubset(_ACTIONS_LOG_METADATA_FIELDS)


def _pipeline_segments(command_text: str) -> list[list[str]]:
    try:
        lexer = shlex.shlex(command_text, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return []
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token != "|":
            segments[-1].append(token)
            continue
        if not segments[-1]:
            return []
        segments.append([])
    return segments if segments[-1] else []


def _substitute_number_variables(
    tokens: list[str],
    values: dict[str, _ValueKind],
) -> list[str] | None:
    substituted: list[str] = []
    for token in tokens:
        unknown = False

        def replace(match: re.Match[str]) -> str:
            nonlocal unknown
            name = match.group("braced") or match.group("plain")
            if name is None or values.get(name) != "number":
                unknown = True
                return ""
            return "1"

        value = _VARIABLE.sub(replace, token)
        if unknown or "$" in value:
            return None
        substituted.append(value)
    return substituted


def _without_safe_stderr_redirect(tokens: list[str]) -> list[str] | None:
    filtered: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"2>/dev/null", "2>&1"}:
            index += 1
            continue
        if token == "2>" and index + 1 < len(tokens) and tokens[index + 1] == "/dev/null":
            index += 2
            continue
        if any(marker in token for marker in (">", "<")):
            return None
        filtered.append(token)
        index += 1
    return filtered


def _safe_actions_github_command(tokens: list[str]) -> bool:
    if len(tokens) < 3 or tokens[0] != "gh":
        return False
    assessment = classify_github_cli(tokens[1:])
    if assessment.capability != "read_remote" or github_capability_requires_confirmation(assessment):
        return False
    if tokens[1:3] == ["run", "view"]:
        return _safe_run_view_args(tokens[3:])
    if tokens[1] != "api":
        return False
    endpoint = tokens[2] if len(tokens) > 2 and not tokens[2].startswith("-") else None
    return bool(
        endpoint is not None and _ACTIONS_ENDPOINT.fullmatch(endpoint) is not None and _safe_api_options(tokens[3:])
    )


def _safe_run_view_args(args: list[str]) -> bool:
    if not args or re.fullmatch(r"[1-9][0-9]*", args[0]) is None:
        return False
    index = 1
    while index < len(args):
        option = args[index]
        if option not in {"--repo", "--json", "--jq"} or index + 1 >= len(args):
            return False
        value = args[index + 1]
        if option == "--repo" and re.fullmatch(_REPOSITORY, value) is None:
            return False
        if option == "--json" and re.fullmatch(r"[A-Za-z][A-Za-z0-9_,]*", value) is None:
            return False
        index += 2
    return True


def _safe_api_options(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        if args[index] != "--jq" or index + 1 >= len(args):
            return False
        index += 2
    return True


def _github_output_kind(tokens: list[str]) -> _ValueKind:
    for index, token in enumerate(tokens):
        if token == "--jq" and index + 1 < len(tokens):
            expression = tokens[index + 1].strip()
            if _JOB_ID_QUERY.fullmatch(expression) or _FILTERED_JOB_ID_QUERY.fullmatch(expression):
                return "number"
    return "text"


def _safe_emitted_output_filter(tokens: list[str]) -> bool:
    if not tokens:
        return False
    if tokens[0] == "head":
        return len(tokens) == 2 and _bounded_count(tokens[1])
    if tokens[0] not in {"grep", "rg"}:
        return False
    positional: list[str] = []
    for token in tokens[1:]:
        if token.startswith("-"):
            flags = token.lstrip("-")
            if not flags or any(flag not in {"i", "o", "q"} for flag in flags):
                return False
            continue
        positional.append(token)
    return len(positional) == 1 and not any(marker in positional[0] for marker in ("$(", "`", "<(", ">("))


def _filters_bound_emitted_matches(segments: list[list[str]]) -> bool:
    final = segments[-1]
    if final[0] == "head":
        return True
    return final[0] in {"grep", "rg"} and any("q" in token.lstrip("-") for token in final[1:] if token.startswith("-"))


def _bounded_count(value: str) -> bool:
    normalized = value[1:] if value.startswith("-") else value
    return normalized.isdigit() and 1 <= int(normalized) <= _MAX_FILTER_LINES


def _safe_text_filter_pipeline(command_text: str, values: dict[str, _ValueKind]) -> bool:
    segments = _pipeline_segments(command_text)
    return bool(
        len(segments) == 2
        and segments[0]
        and segments[0][0] == "echo"
        and _safe_echo_tokens(segments[0][1:], values)
        and _safe_emitted_output_filter(segments[1])
    )


def _safe_echo(command_text: str, values: dict[str, _ValueKind]) -> bool:
    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError:
        return False
    return bool(tokens and tokens[0] == "echo" and _safe_echo_tokens(tokens[1:], values))


def _safe_echo_tokens(tokens: list[str], values: dict[str, _ValueKind]) -> bool:
    for token in tokens:
        if any(marker in token for marker in ("$(", "`", "<(", ">(", ">", "<", ";", "&")):
            return False
        names = [match.group("braced") or match.group("plain") for match in _VARIABLE.finditer(token)]
        if any(name not in values for name in names) or "$" in _VARIABLE.sub("", token):
            return False
    return True


__all__ = ("is_nonexecuting_github_actions_read_workflow",)
