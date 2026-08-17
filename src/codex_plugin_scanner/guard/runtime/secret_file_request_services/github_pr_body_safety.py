"""Static GitHub pull-request body and sensitive-read checks."""

from __future__ import annotations

from pathlib import Path

from ..github_command_capabilities import static_markdown_pr_body_file_operand
from ..github_pr_body_file import github_pr_body_file_is_safe, static_markdown_pr_edit_body_file_operand
from .constants_core import _FIND_EXEC_ACTION_FLAGS, _FIND_EXEC_PLACEHOLDER_TARGET, _FIND_EXEC_TERMINATOR_TOKENS
from .constants_patterns import _FIND_PATH_VALUE_PREDICATES, _HEREDOC_PATTERN, _SHELL_LOCAL_READ_COMMANDS
from .developer_inspection import _find_exec_sed_args_are_read_only
from .github_pr_expansion import _gh_pr_create_body_args_start_index, _shell_token_has_active_expansion
from .github_shell_capabilities import _shell_command_substitution_payloads, _ShellTokenWithQuoteContext
from .local_read_operands import _shell_segment_file_operand_tokens
from .pytest_target_detection import _shell_token_has_active_glob
from .request_models import (
    _SECRET_EXFILTRATION_DESTINATION_PATTERN,
    _SECRET_EXFILTRATION_NETWORK_PATTERN,
    _SECRET_EXFILTRATION_SECRET_PATTERN,
    classify_sensitive_path,
)
from .shell_quote_parsing import _shell_token_segments, _shell_tokens_preserving_quote_context
from .shell_tokenization import _shell_command_token_without_attached_redirection, _shell_segment_primary_command


def _gh_pr_create_uses_safe_static_body_file(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    if _shell_command_substitution_payloads(command_text):
        return False
    segment = _gh_pr_create_segment_with_bounded_output(command_text)
    if segment is None:
        return False
    args_start_index = _gh_pr_create_body_args_start_index(segment)
    if args_start_index is None:
        return False
    operand = static_markdown_pr_body_file_operand(tuple(token.plain for token in segment[args_start_index:]))
    if (
        operand is not None
        and operand.startswith("~/")
        and not any(token.plain == operand and token.raw.startswith("~/") for token in segment[args_start_index:])
    ):
        return False
    return operand is not None and github_pr_body_file_is_safe(
        operand,
        cwd=cwd,
        home_dir=home_dir,
    )


def _gh_pr_create_segment_with_bounded_output(
    command_text: str,
) -> list[_ShellTokenWithQuoteContext] | None:
    tokens = _shell_tokens_preserving_quote_context(command_text)
    separators = [index for index, token in enumerate(tokens) if token.plain in {"&&", "||", ";", "&", "|", "|&"}]
    if not separators:
        return tokens
    if len(separators) != 1 or tokens[separators[0]].plain != "|":
        return None
    pipe_index = separators[0]
    producer = tokens[:pipe_index]
    if producer and producer[-1].plain == "2>&1":
        producer = producer[:-1]
    if any(
        _shell_token_has_active_expansion(token.raw)
        or _shell_token_has_active_glob(token.raw)
        or "<" in token.raw
        or ">" in token.raw
        for token in producer
    ):
        return None
    consumer = tuple(token.plain for token in tokens[pipe_index + 1 :])
    if not _bounded_output_consumer(consumer):
        return None
    return producer


def _bounded_output_consumer(tokens: tuple[str, ...]) -> bool:
    if len(tokens) == 2 and tokens[0] in {"head", "tail"}:
        count = tokens[1]
        return count.startswith("-") and count[1:].isdigit() and 1 <= int(count[1:]) <= 1000
    elif len(tokens) == 3 and tokens[:2] in {("head", "-n"), ("tail", "-n")}:
        count = tokens[2]
    else:
        return False
    return count.isdigit() and 1 <= int(count) <= 1000


def _gh_pr_edit_uses_safe_static_body_file(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    if _shell_command_substitution_payloads(command_text):
        return False
    segments = _shell_token_segments(_shell_tokens_preserving_quote_context(command_text))
    if len(segments) != 1:
        return False
    segment = segments[0]
    if (
        len(segment) < 4
        or tuple(token.raw for token in segment[:3]) != ("gh", "pr", "edit")
        or tuple(token.plain for token in segment[:3]) != ("gh", "pr", "edit")
        or any(_shell_token_has_active_expansion(token.raw) for token in segment)
    ):
        return False
    args_start_index = 3
    operand = static_markdown_pr_edit_body_file_operand(tuple(token.plain for token in segment[args_start_index:]))
    if (
        operand is not None
        and operand.startswith("~/")
        and not any(token.plain == operand and token.raw.startswith("~/") for token in segment[args_start_index:])
    ):
        return False
    return operand is not None and github_pr_body_file_is_safe(
        operand,
        cwd=cwd,
        home_dir=home_dir,
    )


def _shell_segment_reads_sensitive_path(segment: list[str], *, cwd: Path | None, home_dir: Path | None) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    command_segment = segment[command_index:]
    if command_name == "find":
        return _find_segment_reads_sensitive_path(command_segment, cwd=cwd, home_dir=home_dir)
    if command_name not in _SHELL_LOCAL_READ_COMMANDS:
        return False
    if not _shell_read_segment_can_emit_stdout(command_segment):
        return False
    for token in _shell_segment_file_operand_tokens(command_segment):
        normalized_token = _shell_command_token_without_attached_redirection(token).strip("'\"")
        if not normalized_token:
            continue
        if classify_sensitive_path(normalized_token, cwd=cwd, home_dir=home_dir) is not None:
            return True
    return False


def _find_segment_reads_sensitive_path(
    command_segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    args = command_segment[1:]
    if not _find_exec_reads_file_content(args):
        return False
    return any(
        _find_target_candidate_is_sensitive(candidate, cwd=cwd, home_dir=home_dir)
        for candidate in _find_target_candidates(args)
    )


def _find_exec_reads_file_content(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg not in _FIND_EXEC_ACTION_FLAGS:
            index += 1
            continue
        if index + 1 >= len(args):
            return False
        command_name = Path(args[index + 1]).name.lower()
        exec_index = index + 2
        exec_args: list[str] = []
        while exec_index < len(args) and args[exec_index] not in _FIND_EXEC_TERMINATOR_TOKENS:
            exec_args.append(args[exec_index])
            exec_index += 1
        if command_name in _SHELL_LOCAL_READ_COMMANDS:
            if command_name == "sed" and not _find_exec_sed_args_are_read_only(exec_args):
                index = exec_index + 1 if exec_index < len(args) else exec_index
                continue
            return True
        index = exec_index + 1 if exec_index < len(args) else exec_index
    return False


def _find_target_candidates(args: list[str]) -> tuple[str, ...]:
    candidates: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in _FIND_EXEC_ACTION_FLAGS:
            index += 1
            while index < len(args) and args[index] not in _FIND_EXEC_TERMINATOR_TOKENS:
                index += 1
            if index < len(args):
                index += 1
            continue
        if arg in _FIND_PATH_VALUE_PREDICATES and index + 1 < len(args):
            candidates.append(args[index + 1])
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        candidates.append(arg)
        index += 1
    return tuple(candidates)


def _find_target_candidate_is_sensitive(candidate: str, *, cwd: Path | None, home_dir: Path | None) -> bool:
    normalized = _shell_command_token_without_attached_redirection(candidate).strip("'\"")
    if normalized in {"", "-", "{}", _FIND_EXEC_PLACEHOLDER_TARGET}:
        return False
    if classify_sensitive_path(normalized, cwd=cwd, home_dir=home_dir) is not None:
        return True
    return _path_text_looks_sensitive(normalized)


def _shell_read_segment_can_emit_stdout(segment: list[str]) -> bool:
    if not segment:
        return False
    command_name = Path(segment[0]).name.lower()
    args = segment[1:]
    if command_name in {"grep", "egrep", "fgrep", "rg"}:
        return not _search_args_use_quiet_mode(args)
    return True


def _search_args_use_quiet_mode(args: list[str]) -> bool:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            return False
        if arg in {"-e", "--regexp", "-f", "--file"}:
            skip_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in ("--regexp", "--file")):
            continue
        if (arg.startswith("-e") or arg.startswith("-f")) and len(arg) > 2:
            continue
        if arg in {"-q", "--quiet", "--silent"}:
            return True
        if arg.startswith("--quiet=") or arg.startswith("--silent="):
            return True
        if arg.startswith("-") and not arg.startswith("--") and "q" in arg[1:]:
            return True
    return False


def _text_contains_credential_exfiltration(text: str) -> bool:
    if not _SECRET_EXFILTRATION_SECRET_PATTERN.search(text):
        return False
    if not _SECRET_EXFILTRATION_NETWORK_PATTERN.search(text):
        return False
    return _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(text) is not None


def _shell_heredoc_payloads(command_text: str) -> tuple[str, ...]:
    payloads: list[str] = []
    lines = command_text.splitlines()
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        match = _HEREDOC_PATTERN.search(line)
        if match is None:
            line_index += 1
            continue
        delimiter = match.group(2)
        strip_tabs = line[match.start() :].startswith("<<-")
        body_lines: list[str] = []
        line_index += 1
        while line_index < len(lines):
            candidate_line = lines[line_index]
            normalized_line = candidate_line.lstrip("\t") if strip_tabs else candidate_line
            if normalized_line == delimiter:
                line_index += 1
                break
            body_lines.append(normalized_line if strip_tabs else candidate_line)
            line_index += 1
        payload = "\n".join(body_lines).strip()
        if payload:
            payloads.append(payload)
    return tuple(payloads)


def _path_text_looks_sensitive(path_text: str) -> bool:
    lowered = path_text.lower()
    return any(
        marker in lowered
        for marker in (
            ".aws/",
            ".docker/",
            ".kube/",
            ".ssh/",
            ".env",
            ".git-credentials",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "id_rsa",
        )
    )


__all__ = [
    "_bounded_output_consumer",
    "_find_exec_reads_file_content",
    "_find_segment_reads_sensitive_path",
    "_find_target_candidate_is_sensitive",
    "_find_target_candidates",
    "_gh_pr_create_segment_with_bounded_output",
    "_gh_pr_create_uses_safe_static_body_file",
    "_gh_pr_edit_uses_safe_static_body_file",
    "_path_text_looks_sensitive",
    "_search_args_use_quiet_mode",
    "_shell_heredoc_payloads",
    "_shell_read_segment_can_emit_stdout",
    "_shell_segment_reads_sensitive_path",
    "_text_contains_credential_exfiltration",
]
