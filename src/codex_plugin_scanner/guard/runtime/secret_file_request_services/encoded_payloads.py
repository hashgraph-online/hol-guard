"""Encoded payload decoding and execution detection."""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from ..command_critical_floors import command_critical_floor_factors
from ..command_model import parse_shell_command
from ..data_flow import extract_heredocs
from ..read_only_git_audit import is_read_only_git_ancestry_audit
from ..shell_execution_context import (
    ShellExecutionContext,
    model_shell_execution_context,
    validate_shell_execution_segment,
)
from .constants_core import _DESTRUCTIVE_SHELL_COMMANDS, _SAFE_STATIC_SHELL_COMMANDS
from .destructive_shell_detection import (
    _contains_destructive_git_command,
    _contains_mutating_shell_redirection,
    _find_command_uses_delete,
    _redacted_shell_text_for_command_names,
    _shell_command_names,
    _shell_command_names_from_parts,
    _shell_text_for_redirection_scan,
    _single_interpreter_heredoc_script,
)
from .developer_inspection import _static_shell_segment_is_safe
from .github_shell_capabilities import (
    _env_split_string_payloads,
    _iter_shell_pipelines,
    _read_backtick_command_substitution,
    _read_command_substitution,
    _shell_command_scripts,
    _shell_command_substitution_payloads,
)
from .interpreter_observers import (
    _contains_pytest_env_shell_script_wrapper,
    _looks_like_benign_interpreter_wait,
    _looks_like_benign_interpreter_wait_chain,
    _looks_like_read_only_interpreter_command,
    _looks_like_read_only_interpreter_compound,
    _looks_like_safe_read_only_lookup_command,
    _read_only_lookup_segments,
)
from .node_generated_workflows import (
    _contains_destructive_node_inline_eval,
    _find_or_fd_uses_write_or_exec_action,
    _looks_like_safe_graphql_query_file_workflow,
    _single_node_heredoc_script,
)
from .node_heredoc_safety import (
    _looks_like_safe_node_generated_file_heredoc,
    _looks_like_safe_node_read_only_http_heredoc,
)
from .perl_read_only import _looks_like_read_only_perl_filter
from .pytest_binary_safety import (
    _contains_prior_pytest_state_mutation,
    _contains_pytest_process_substitution,
    _contains_unsafe_pytest_environment_wrapper,
    _is_literal_cat_heredoc_to_stdout,
    _looks_like_safe_pytest_binary_invocation,
    _looks_like_supported_python_invocation,
)
from .request_models import _MAX_DECODED_PAYLOAD_BYTES
from .routine_move import _looks_like_safe_routine_move
from .shell_static_safety import (
    _is_python_interpreter_command,
    _script_interpreter_texts,
    _script_is_read_only_observer,
)
from .shell_tokenization import _shell_segment_primary_command, _split_shell_parts
from .typescript_graphql_safety import (
    _contains_unmodeled_inline_interpreter_eval,
    _contains_unsafe_pytest_binary_invocation,
    _looks_like_contained_temporary_typescript_workflow,
    _node_script_contains_sensitive_runtime_behavior,
)


def _contains_command_substitution_decode_exec(command_text: str) -> bool:
    substitution_payloads = _shell_command_substitution_payloads(command_text)
    if not substitution_payloads:
        return False
    if not any(_contains_decode_primitive(payload) for payload in substitution_payloads):
        return False
    lowered = command_text.lower()
    if re.search(r"\b(?:ash|bash|dash|sh|zsh)\b[^\n;|&]*-[A-Za-z]*c[A-Za-z]*", lowered):
        return True
    return bool(re.search(r"\beval\b[^\n;|&]*\$\(", lowered))


def _contains_decode_primitive(command_text: str) -> bool:
    lowered = command_text.lower()
    return bool(
        re.search(r"\bbase64\b(?=[^\n|;]*\s(?:--decode|-[A-Za-z]*[dD][A-Za-z]*))", lowered)
        or re.search(r"\bxxd\s+(?:-r\s+-p|-rp)\b", lowered)
        or re.search(r"\bopenssl\s+enc\b[^\n|;]*\s-(?:d|decrypt)\b", lowered)
        or re.search(r"\b(?:gpg|gpg2)\b[^\n|;]*(?:--decrypt|-d)\b", lowered)
    )


def _shell_text_without_quoted_literals(command_text: str) -> str:
    characters: list[str] = []
    index = 0
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        character = command_text[index]
        if single_quoted:
            if character == "'":
                single_quoted = False
            characters.append(" ")
            index += 1
            continue
        if double_quoted:
            if character == "\\":
                characters.append(" ")
                if index + 1 < len(command_text):
                    characters.append(" ")
                    index += 2
                else:
                    index += 1
                continue
            if character == '"':
                double_quoted = False
                characters.append(" ")
                index += 1
                continue
            if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
                payload, next_index = _read_command_substitution(command_text, index + 2)
                characters.append(f"$({payload})")
                index = next_index
                continue
            if character == "`":
                payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
                characters.append(f"`{payload}`")
                index = next_index
                continue
            characters.append(" ")
            index += 1
            continue
        if character == "'":
            single_quoted = True
            characters.append(" ")
            index += 1
            continue
        if character == '"':
            double_quoted = True
            characters.append(" ")
            index += 1
            continue
        characters.append(character)
        index += 1
    return "".join(characters)


def _decode_base64_literal(literal: str) -> str | None:
    try:
        decoded_bytes = base64.b64decode(literal, validate=True)
    except binascii.Error:
        return None
    return _decoded_bytes_to_text(decoded_bytes)


def _decode_hex_literal(literal: str) -> str | None:
    if len(literal) % 2 != 0:
        return None
    try:
        decoded_bytes = binascii.unhexlify(literal)
    except binascii.Error:
        return None
    return _decoded_bytes_to_text(decoded_bytes)


def _decoded_bytes_to_text(decoded_bytes: bytes) -> str | None:
    if not decoded_bytes or len(decoded_bytes) > _MAX_DECODED_PAYLOAD_BYTES:
        return None
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = decoded_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _text_is_probably_source(text):
            return text
    return None


def _text_is_probably_source(text: str) -> bool:
    if not text.strip():
        return False
    printable = sum(1 for character in text if character.isprintable() or character in "\n\r\t")
    return printable / len(text) >= 0.85


def _looks_destructive_shell_command(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    execution_context: ShellExecutionContext | None = None,
    _execution_context_applied: bool = False,
    depth: int = 0,
) -> bool:
    if depth > 4:
        return True
    normalized = command_text.strip()
    if not normalized:
        return False
    if home_dir is not None and is_read_only_git_ancestry_audit(
        normalized,
        cwd=cwd,
        home_dir=home_dir,
    ):
        return False
    guard_command_token_present = any(
        Path(part).name.lower().removesuffix(".exe") in {"hol-guard", "plugin-guard"}
        for part in _split_shell_parts(normalized)
    )
    if guard_command_token_present:
        critical_factors = command_critical_floor_factors(parse_shell_command(normalized, cwd=cwd, home_dir=home_dir))
        if any(factor.basis.action_floor == "block" for factor in critical_factors):
            return True
    if not _execution_context_applied:
        execution_context = execution_context or model_shell_execution_context(
            normalized,
            cwd=cwd,
            workspace_root=cwd,
        )
        if execution_context.directory_change_present:
            if not execution_context.complete:
                return True
            has_heredoc = bool(extract_heredocs(normalized))
            heredoc_segment_cwds: list[Path] = []
            for context_segment in execution_context.segments:
                if context_segment.directory_operation is not None:
                    continue
                segment_cwd, validation_reason = validate_shell_execution_segment(
                    execution_context,
                    context_segment,
                )
                if segment_cwd is None or validation_reason is not None:
                    return True
                command_name, command_index = _shell_segment_primary_command(list(context_segment.tokens))
                if (
                    command_name in _SAFE_STATIC_SHELL_COMMANDS
                    and command_index is not None
                    and not _static_shell_segment_is_safe(list(context_segment.tokens[command_index + 1 :]))
                ):
                    return True
                segment_has_heredoc = any(token.startswith("<<") for token in context_segment.tokens)
                if segment_has_heredoc:
                    heredoc_segment_cwds.append(segment_cwd)
                elif _looks_destructive_shell_command(
                    context_segment.command_text,
                    cwd=segment_cwd,
                    home_dir=home_dir,
                    _execution_context_applied=True,
                    depth=depth + 1,
                ):
                    return True
            if has_heredoc:
                if len(heredoc_segment_cwds) != 1:
                    return True
                return _looks_destructive_shell_command(
                    normalized,
                    cwd=heredoc_segment_cwds[0],
                    home_dir=home_dir,
                    _execution_context_applied=True,
                    depth=depth + 1,
                )
            contextual_parts = _split_shell_parts(normalized)
            return _contains_prior_pytest_state_mutation(contextual_parts) or _contains_pytest_env_shell_script_wrapper(
                contextual_parts
            )
    if _is_literal_cat_heredoc_to_stdout(normalized):
        return False
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _looks_destructive_shell_command(substitution_payload, cwd=cwd, home_dir=home_dir, depth=depth + 1):
            return True
    node_heredoc_script = _single_node_heredoc_script(normalized)
    if node_heredoc_script is not None:
        if _looks_like_safe_node_read_only_http_heredoc(normalized, node_heredoc_script):
            return False
        if _looks_like_safe_node_generated_file_heredoc(normalized, node_heredoc_script):
            return False
        return _node_script_contains_sensitive_runtime_behavior(node_heredoc_script)
    if _looks_like_contained_temporary_typescript_workflow(normalized):
        return False
    if _looks_like_safe_graphql_query_file_workflow(normalized):
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    lowered = normalized.lower()
    redacted_command_text = _redacted_shell_text_for_command_names(lowered)
    redirection_parts = _split_shell_parts(_shell_text_for_redirection_scan(lowered))
    if _contains_mutating_shell_redirection(redirection_parts):
        return True
    if _contains_prior_pytest_state_mutation(parts):
        return True
    if _contains_pytest_env_shell_script_wrapper(parts):
        return True
    if _contains_pytest_process_substitution(normalized, parts):
        return True
    if _contains_unsafe_pytest_environment_wrapper(parts, cwd=cwd):
        return True
    if _looks_like_safe_read_only_lookup_command(normalized, parts, home_dir=home_dir):
        return False
    if _looks_like_read_only_shell_pipeline(normalized, parts, cwd=cwd, home_dir=home_dir):
        return False
    if _looks_like_read_only_interpreter_compound(normalized, parts, home_dir=home_dir):
        return False
    raw_command_names = list(_shell_command_names(redacted_command_text))
    parsed_command_names = list(_shell_command_names_from_parts(parts))
    if _looks_like_benign_interpreter_wait(normalized, parts, parsed_command_names):
        return False
    if _looks_like_benign_interpreter_wait_chain(normalized, parts):
        return False
    if _looks_like_read_only_interpreter_command(normalized, parts, parsed_command_names):
        return False
    if _looks_like_read_only_perl_filter(normalized, cwd=cwd, home_dir=home_dir):
        return False
    if _looks_like_safe_pytest_binary_invocation(parts, cwd=cwd):
        return False
    if _contains_unsafe_pytest_binary_invocation(parts, cwd=cwd):
        return True
    if _single_interpreter_heredoc_script(normalized) is not None or any(
        _is_python_interpreter_command(command_name) for command_name in parsed_command_names
    ):
        return not _looks_like_supported_python_invocation(parts, cwd=cwd)
    if _contains_unmodeled_inline_interpreter_eval(normalized, parts, parsed_command_names):
        return True
    if _contains_destructive_node_inline_eval(parts):
        return True
    if _contains_destructive_git_command(parts):
        return True
    if _find_or_fd_uses_write_or_exec_action(parts, home_dir=home_dir):
        return True
    if _looks_like_safe_routine_move(parts, cwd=cwd, home_dir=home_dir):
        return False
    command_names = list(raw_command_names)
    command_names.extend(_shell_command_names_from_parts(parts))
    if any(command_name in _DESTRUCTIVE_SHELL_COMMANDS for command_name in command_names):
        return True
    if _find_command_uses_delete(parts):
        return True
    for env_split_string in _env_split_string_payloads(parts):
        if _looks_destructive_shell_command(env_split_string, cwd=cwd, home_dir=home_dir, depth=depth + 1):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _looks_destructive_shell_command(shell_script, cwd=cwd, home_dir=home_dir, depth=depth + 1):
            return True
    return any(
        Path(segment[0]).name.lower() == "sed" and any(part == "-i" or part.startswith("-i") for part in segment[1:])
        for segment in _read_only_lookup_segments(parts)
        if segment
    )


def _looks_like_read_only_shell_pipeline(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    pipelines = _iter_shell_pipelines(parts)
    if len(pipelines) != 1:
        return False
    pipeline = pipelines[0]
    if len(pipeline) < 2:
        return False
    return all(_pipeline_segment_is_read_only(segment, cwd=cwd, home_dir=home_dir) for segment in pipeline)


def _pipeline_segment_is_read_only(
    segment: list[str],
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    if _is_python_interpreter_command(command_name):
        scripts = list(_script_interpreter_texts(segment))
        return bool(scripts) and all(_script_is_read_only_observer(script_text) for script_text in scripts)
    segment_text = " ".join(segment)
    return not _looks_destructive_shell_command(segment_text, cwd=cwd, home_dir=home_dir)


__all__ = [
    "_contains_command_substitution_decode_exec",
    "_contains_decode_primitive",
    "_decode_base64_literal",
    "_decode_hex_literal",
    "_decoded_bytes_to_text",
    "_looks_destructive_shell_command",
    "_looks_like_read_only_shell_pipeline",
    "_pipeline_segment_is_read_only",
    "_shell_text_without_quoted_literals",
    "_text_is_probably_source",
]
