"""Node heredoc and generated-file safety."""

from __future__ import annotations

import os
import re

from .constants_patterns import (
    _NODE_LOCAL_FILE_ACCESS_PATTERN,
    _NODE_MUTATING_HTTP_PATTERN,
    _NODE_READ_ONLY_HTTP_PATTERN,
    _NODE_SENSITIVE_RUNTIME_PATTERN,
    _SAFE_NODE_GENERATED_FILE_EXTENSIONS,
    _SINGLE_NODE_HEREDOC_PATTERN,
)
from .github_pr_body_safety import _path_text_looks_sensitive
from .node_generated_workflows import (
    _js_string_literal_text,
    _node_expand_template_value,
    _node_generated_path_has_safe_root,
    _node_path_without_template_placeholders,
    _node_string_assignments,
    _node_template_placeholders_are_safe_filename_fragments,
    _single_node_heredoc_script,
)
from .typescript_graphql_safety import (
    _node_script_contains_non_file_generation_risk,
    script_references_destructive_file_call,
)


def _single_node_heredoc_delimiter_is_quoted(command_text: str) -> bool:
    match = _SINGLE_NODE_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return False
    args = match.group("args").strip()
    if args not in {"", "-"}:
        return False
    return bool(match.group("quote"))


def _looks_like_safe_node_generated_file_heredoc(command_text: str, script_text: str) -> bool:
    if _single_node_heredoc_script(command_text) is None or not _single_node_heredoc_delimiter_is_quoted(command_text):
        return False
    if _node_script_contains_non_file_generation_risk(script_text):
        return False
    if _node_script_contains_disallowed_destructive_file_call(script_text):
        return False
    write_targets = _node_write_file_targets(script_text)
    if not write_targets:
        return False
    assignments = _node_string_assignments(script_text)
    return all(_node_write_target_is_safe_generated_file(target, assignments) for target in write_targets)


def _looks_like_safe_node_read_only_http_heredoc(command_text: str, script_text: str) -> bool:
    if not _single_node_heredoc_delimiter_is_quoted(command_text):
        return False
    if _NODE_READ_ONLY_HTTP_PATTERN.search(script_text) is None:
        return False
    if _NODE_MUTATING_HTTP_PATTERN.search(script_text):
        return False
    if _NODE_LOCAL_FILE_ACCESS_PATTERN.search(script_text):
        return False
    if _NODE_SENSITIVE_RUNTIME_PATTERN.search(script_text):
        return False
    return not _node_script_contains_disallowed_destructive_file_call(script_text)


def _node_script_contains_disallowed_destructive_file_call(script_text: str) -> bool:
    return script_references_destructive_file_call(
        script_text,
        allowed_write_calls=frozenset({"writeFile", "writeFileSync"}),
    )


def _node_write_file_targets(script_text: str) -> tuple[str, ...]:
    targets: list[str] = []
    for match in re.finditer(r"(?:^|[^A-Za-z0-9_$])(?:fs\s*\.\s*)?writeFile(?:Sync)?\s*\(", script_text):
        target = _first_js_call_argument(script_text, match.end())
        if target is not None:
            targets.append(target)
    return tuple(targets)


def _first_js_call_argument(script_text: str, index: int) -> str | None:
    argument_start = index
    depth = 0
    quote: str | None = None
    escape_next = False
    while index < len(script_text):
        character = script_text[index]
        if escape_next:
            escape_next = False
            index += 1
            continue
        if character == "\\":
            escape_next = True
            index += 1
            continue
        if quote is not None:
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue
        if character in "([{":
            depth += 1
            index += 1
            continue
        if character in ")]}":
            if depth == 0:
                return script_text[argument_start:index].strip() or None
            depth -= 1
            index += 1
            continue
        if character == "," and depth == 0:
            return script_text[argument_start:index].strip() or None
        index += 1
    return None


def _node_write_target_is_safe_generated_file(target: str, assignments: dict[str, str]) -> bool:
    normalized = target.strip()
    if normalized in assignments:
        normalized = assignments[normalized]
    elif _js_string_literal_text(normalized) is not None:
        normalized = _js_string_literal_text(normalized) or ""
        normalized = _node_expand_template_value(normalized, assignments)
    else:
        return False
    if _node_generated_path_contains_shell_expansion(normalized) or _path_text_looks_sensitive(normalized):
        return False
    if "../" in normalized or normalized.startswith("../"):
        return False
    return _node_generated_path_has_safe_root(normalized) and _node_generated_path_has_safe_extension(normalized)


def _node_generated_path_contains_shell_expansion(path_text: str) -> bool:
    if "$(" in path_text or "`" in path_text or "$'" in path_text or '$"' in path_text:
        return True
    if not _node_template_placeholders_are_safe_filename_fragments(path_text):
        return True
    redacted_path = _node_path_without_template_placeholders(path_text)
    if any(character in redacted_path for character in "*?[]"):
        return True
    index = 0
    while index < len(redacted_path):
        if redacted_path[index] == "$" and index + 1 < len(redacted_path):
            next_character = redacted_path[index + 1]
            if next_character.isalnum() or next_character == "_":
                return True
        index += 1
    return False


def _node_generated_path_has_safe_extension(path_text: str) -> bool:
    without_templates = _node_path_without_template_placeholders(path_text)
    extension = os.path.splitext(without_templates)[1].lower()
    return extension in _SAFE_NODE_GENERATED_FILE_EXTENSIONS


__all__ = [
    "_first_js_call_argument",
    "_looks_like_safe_node_generated_file_heredoc",
    "_looks_like_safe_node_read_only_http_heredoc",
    "_node_generated_path_contains_shell_expansion",
    "_node_generated_path_has_safe_extension",
    "_node_script_contains_disallowed_destructive_file_call",
    "_node_write_file_targets",
    "_node_write_target_is_safe_generated_file",
    "_single_node_heredoc_delimiter_is_quoted",
]
