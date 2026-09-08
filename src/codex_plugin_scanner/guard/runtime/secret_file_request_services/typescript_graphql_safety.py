"""Temporary TypeScript and GraphQL workflow safety."""

from __future__ import annotations

import re
from pathlib import Path

from .constants_core import _PYTEST_UNSAFE_ENV_KEYS, _UNMODELED_INLINE_INTERPRETER_COMMANDS
from .constants_patterns import _DESTRUCTIVE_NODE_INLINE_CALLS
from .github_pr_body_safety import (
    _path_text_looks_sensitive,
    _shell_heredoc_payloads,
    _text_contains_credential_exfiltration,
)
from .interpreter_observers import _shell_segment_sets_env_key, _single_interpreter_heredoc_interpreter
from .pytest_binary_safety import (
    _pytest_binary_segment_is_safe,
    _shell_segment_uses_cwd_changing_wrapper,
    _shell_segment_uses_env_split_string_wrapper,
)
from .shell_static_safety import _is_script_interpreter_command, _script_interpreter_texts
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command

_SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN = re.compile(
    r"\A\s*cat\s*>\s*(?P<path>'[^']+'|\"[^\"]+\"|[^\s]+)\s*<<(?P<quote>['\"])(?P<label>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)"
    r"\s*\n(?P<body>.*?)\n(?P=label)\s*(?:\n|&&|;)\s*(?P<rest>.+)\Z",
    re.DOTALL,
)

_CONTAINED_TEMP_TYPESCRIPT_WORKFLOW_PATTERN = re.compile(
    r"\A\s*cat\s*>\s*(?P<path>scripts/tmp-[A-Za-z0-9._-]+\.tsx?)\s*"
    r"<<(?P<quote>['\"])(?P<label>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)\s*\n"
    r"(?P<body>.*?)\n(?P=label)\s*(?:\n|&&|;)\s*"
    r"timeout\s+(?P<timeout>[1-9][0-9]{0,2})\s+npx\s+(?:--no-install\s+)?tsx\s+(?P=path)"
    r"(?:\s+2>&1)?(?:\s*\|\s*(?:grep\s+-v\s+(?:'[^']*'|\"[^\"]*\")|head\s+-[1-9][0-9]*|tail\s+-[1-9][0-9]*))*"
    r"\s*;\s*rm\s+-f\s+(?P=path)\s*\Z",
    re.DOTALL,
)


def _looks_like_contained_temporary_typescript_workflow(command_text: str) -> bool:
    match = _CONTAINED_TEMP_TYPESCRIPT_WORKFLOW_PATTERN.match(command_text)
    if match is None or int(match.group("timeout")) > 300:
        return False
    body = match.group("body")
    if len(body.encode("utf-8")) > 64 * 1024 or "\x00" in body:
        return False
    return not (_text_contains_credential_exfiltration(body) or _node_script_contains_sensitive_runtime_behavior(body))


def _strip_shell_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _contains_shell_expansion(value: str) -> bool:
    return (
        "$(" in value
        or "`" in value
        or "${" in value
        or "$'" in value
        or '$"' in value
        or re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", value) is not None
        or re.search(r"[*?\[\]{}]", value) is not None
    )


def _graphql_query_file_substitution_refs(target_path: str) -> set[str]:
    return {
        f"$(cat {target_path})",
        f'$(cat "{target_path}")',
        f"$(cat '{target_path}')",
    }


def _graphql_workflow_field_arg_is_safe(argument: str, target_path: str) -> bool:
    if "=" not in argument:
        return False
    name, value = argument.split("=", 1)
    if not name:
        return False
    if name == "query":
        return value in _graphql_query_file_argument_values(target_path)
    if not value or value.startswith("@"):
        return False
    return not (_contains_shell_expansion(value) or "/" in value or "\\" in value)


def _graphql_query_file_argument_values(target_path: str) -> set[str]:
    return _graphql_query_file_substitution_refs(target_path) | {f"@{target_path}"}


def script_references_destructive_file_call(script: str, *, allowed_write_calls: frozenset[str] = frozenset()) -> bool:
    """Return true when the script invokes any destructive file call outside the allow-list.

    Scans both direct invocations and member accesses (dot, quoted subscript,
    .call/.apply) against two redaction views so string-literal member names
    cannot smuggle a call through.
    """

    redacted_script = _redacted_node_inline_string_literals(script)
    member_scan_script = _redacted_node_inline_string_literals(script, preserve_bracket_member_strings=True)
    for call_name in _DESTRUCTIVE_NODE_INLINE_CALLS - allowed_write_calls:
        escaped_call_name = re.escape(call_name)
        if re.search(rf"(?<![A-Za-z0-9_$'\"]){escaped_call_name}\s*(?:\?\.\s*)?\(", redacted_script):
            return True
        for base_pattern in (
            rf"\.\s*{escaped_call_name}",
            rf"\[\s*['\"]{escaped_call_name}['\"]\s*\]",
        ):
            if re.search(rf"{base_pattern}\s*(?:\?\.\s*)?(?:\)\s*)?\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*call\s*\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*apply\s*\(", member_scan_script):
                return True
    return False


def _contains_destructive_node_inline_script(script: str) -> bool:
    return script_references_destructive_file_call(script)


def _node_script_contains_sensitive_runtime_behavior(script_text: str) -> bool:
    return script_references_destructive_file_call(script_text) or _node_script_contains_non_file_generation_risk(
        script_text
    )


def _node_script_contains_non_file_generation_risk(script_text: str) -> bool:
    lowered = script_text.lower()
    if _path_text_looks_sensitive(script_text):
        return True
    return bool(
        re.search(r"\b(?:fetch|xmlhttprequest)\s*\(", lowered)
        or re.search(r"\b(?:http|https|net|tls|dgram)\s*\.", lowered)
        or re.search(r"\brequire\s*\(\s*['\"](?:child_process|http|https|net|tls|dgram)['\"]\s*\)", lowered)
        or re.search(r"\b(?:exec|execfile|execfilesync|execsync|spawn|spawnsync|fork)\s*\(", lowered)
        or re.search(r"\b(?:eval|function)\s*\(", lowered)
    )


def _redacted_node_inline_string_literals(script: str, *, preserve_bracket_member_strings: bool = False) -> str:
    result: list[str] = []
    quote_char: str | None = None
    escape_next = False
    preserve_string_contents = False
    template_expression_depth = 0
    comment_type: str | None = None
    regex_literal = False
    regex_escape_next = False
    regex_char_class = False
    index = 0
    while index < len(script):
        character = script[index]
        if quote_char is None:
            if template_expression_depth > 0:
                if comment_type == "line":
                    result.append(character)
                    if character in {"\n", "\r"}:
                        comment_type = None
                    index += 1
                    continue
                if comment_type == "block":
                    result.append(character)
                    if character == "/" and result[-2:-1] == ["*"]:
                        comment_type = None
                    index += 1
                    continue
                if regex_literal:
                    result.append(character)
                    if regex_escape_next:
                        regex_escape_next = False
                    elif character == "\\":
                        regex_escape_next = True
                    elif character == "[" and not regex_char_class:
                        regex_char_class = True
                    elif character == "]" and regex_char_class:
                        regex_char_class = False
                    elif character == "/" and not regex_char_class:
                        regex_literal = False
                    index += 1
                    continue
                if character == "/" and index + 1 < len(script):
                    next_character = script[index + 1]
                    if next_character == "/":
                        result.append("//")
                        comment_type = "line"
                        index += 2
                        continue
                    if next_character == "*":
                        result.append("/*")
                        comment_type = "block"
                        index += 2
                        continue
                    if _js_slash_starts_regex(result):
                        result.append(character)
                        regex_literal = True
                        regex_escape_next = False
                        regex_char_class = False
                        index += 1
                        continue
                if character == "{":
                    template_expression_depth += 1
                    result.append(character)
                    index += 1
                    continue
                if character == "}":
                    template_expression_depth -= 1
                    result.append(character)
                    if template_expression_depth == 0:
                        quote_char = "`"
                        comment_type = None
                        regex_literal = False
                        regex_escape_next = False
                        regex_char_class = False
                    index += 1
                    continue
            if character in {"'", '"', "`"}:
                preserve_string_contents = (
                    preserve_bracket_member_strings and _last_non_whitespace_character(result) == "["
                )
                quote_char = character
                result.append(character)
                index += 1
                continue
            result.append(character)
            index += 1
            continue
        if escape_next:
            result.append(character if preserve_string_contents else "Q")
            escape_next = False
            index += 1
            continue
        if character == "\\":
            result.append(character)
            escape_next = True
            index += 1
            continue
        if quote_char == "`" and character == "$" and index + 1 < len(script) and script[index + 1] == "{":
            result.append("${")
            quote_char = None
            preserve_string_contents = False
            template_expression_depth = 1
            index += 2
            continue
        if character == quote_char:
            result.append(character)
            quote_char = None
            preserve_string_contents = False
            index += 1
            continue
        result.append(character if preserve_string_contents else "Q")
        index += 1
    return "".join(result)


def _last_non_whitespace_character(result: list[str]) -> str | None:
    for chunk in reversed(result):
        for character in reversed(chunk):
            if not character.isspace():
                return character
    return None


def _js_slash_starts_regex(result: list[str]) -> bool:
    previous_character = _last_non_whitespace_character(result)
    if previous_character is None:
        return True
    return previous_character in {
        "(",
        "{",
        "[",
        "=",
        ":",
        ",",
        ";",
        "!",
        "?",
        "|",
        "&",
        "+",
        "-",
        "*",
        "%",
        "^",
        "~",
    }


def _contains_unsafe_pytest_binary_invocation(parts: list[str], *, cwd: Path | None) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "pytest" or command_index is None:
            continue
        if _shell_segment_sets_env_key(segment, command_index, "PATH"):
            return True
        if any(_shell_segment_sets_env_key(segment, command_index, env_key) for env_key in _PYTEST_UNSAFE_ENV_KEYS):
            return True
        if _shell_segment_uses_env_split_string_wrapper(segment, command_index):
            return True
        if _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
            return True
        if not _pytest_binary_segment_is_safe(segment[command_index], segment[command_index + 1 :], cwd=cwd):
            return True
    return False


def _contains_unmodeled_inline_interpreter_eval(
    command_text: str,
    parts: list[str],
    command_names: list[str],
) -> bool:
    heredoc_interpreter = _single_interpreter_heredoc_interpreter(command_text)
    if heredoc_interpreter is not None:
        return _is_unmodeled_inline_interpreter_command(heredoc_interpreter)
    if not command_names or not all(_is_script_interpreter_command(command_name) for command_name in command_names):
        return False
    if not any(_is_unmodeled_inline_interpreter_command(command_name) for command_name in command_names):
        return False
    return bool(_script_interpreter_texts(parts) or _shell_heredoc_payloads(command_text))


def _is_unmodeled_inline_interpreter_command(command_name: str) -> bool:
    return command_name in _UNMODELED_INLINE_INTERPRETER_COMMANDS


__all__ = [
    "_CONTAINED_TEMP_TYPESCRIPT_WORKFLOW_PATTERN",
    "_SAFE_GRAPHQL_QUERY_FILE_WORKFLOW_PATTERN",
    "_contains_destructive_node_inline_script",
    "_contains_shell_expansion",
    "_contains_unmodeled_inline_interpreter_eval",
    "_contains_unsafe_pytest_binary_invocation",
    "_graphql_query_file_argument_values",
    "_graphql_query_file_substitution_refs",
    "_graphql_workflow_field_arg_is_safe",
    "_is_unmodeled_inline_interpreter_command",
    "_js_slash_starts_regex",
    "_last_non_whitespace_character",
    "_looks_like_contained_temporary_typescript_workflow",
    "_node_script_contains_non_file_generation_risk",
    "_node_script_contains_sensitive_runtime_behavior",
    "_redacted_node_inline_string_literals",
    "_strip_shell_quotes",
    "script_references_destructive_file_call",
]
