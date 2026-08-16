"""Bounded recognition for one statically authored temporary PR body."""

from __future__ import annotations

import re

from ..github_command_capabilities import static_markdown_pr_body_file_operand
from ..secret_sensitivity import classify_secret_content
from ..shell_structure import extract_command_substitution_spans, extract_heredocs, mask_complete_heredocs
from .github_pr_expansion import _shell_token_has_active_expansion
from .github_shell_capabilities import github_argument_token_has_untrusted_expansion
from .shell_quote_tokens import (
    ShellTokenWithQuoteContext,
    shell_token_segments,
    shell_tokens_preserving_quote_context,
)

_MAX_WORKFLOW_BYTES = 192 * 1024
_MAX_BODY_BYTES = 128 * 1024
_VARIABLE = r"[A-Za-z_][A-Za-z0-9_]*"
_STATIC_UNQUOTED_ARGUMENT = re.compile(r"[A-Za-z0-9_@%+=:,./-]+")


def gh_pr_create_uses_safe_ephemeral_body(command_text: str) -> bool:
    """Accept one closed static heredoc flowing only into one PR proposal."""

    if not command_text or len(command_text.encode("utf-8")) > _MAX_WORKFLOW_BYTES:
        return False
    heredocs = extract_heredocs(command_text)
    if len(heredocs) != 1:
        return False
    heredoc = heredocs[0]
    if not heredoc.quoted or heredoc.body_end >= heredoc.end:
        return False
    body_bytes = heredoc.body.encode("utf-8")
    if not body_bytes or len(body_bytes) > _MAX_BODY_BYTES:
        return False
    if classify_secret_content(heredoc.body, suppress_samples=False):
        return False

    masked = mask_complete_heredocs(command_text, heredocs)
    segments = shell_token_segments(shell_tokens_preserving_quote_context(masked))
    if len(segments) < 3:
        return False
    variable = _assignment_variable(segments[0])
    if variable is None or not _heredoc_writer_is_safe(segments[1], variable=variable):
        return False
    substitutions = extract_command_substitution_spans(masked)
    if len(substitutions) != 1 or substitutions[0].body.strip() != "mktemp":
        return False

    pr_create_count = 0
    control_tokens: list[str] = []
    for segment in segments[2:]:
        if not segment:
            return False
        if segment[0].raw == "#":
            continue
        command = segment[0].plain
        if command in {"then", "else", "fi"}:
            if len(segment) != 1 or segment[0].raw != command:
                return False
            control_tokens.append(command)
            continue
        if command == "if":
            if not _body_grep_is_safe(segment, variable=variable):
                return False
            control_tokens.append(command)
            continue
        if command == "echo":
            if not _echo_is_safe(segment, variable=variable):
                return False
            continue
        if command == "cat":
            if not _body_cat_is_safe(segment, variable=variable):
                return False
            continue
        if command == "exit":
            if tuple(token.raw for token in segment) != ("exit", "1"):
                return False
            continue
        if command == "gh":
            if not _pr_create_is_safe(segment, variable=variable):
                return False
            pr_create_count += 1
            continue
        return False
    return pr_create_count == 1 and control_tokens in ([], ["if", "then", "else", "fi"])


def _assignment_variable(segment: list[ShellTokenWithQuoteContext]) -> str | None:
    if len(segment) != 1:
        return None
    match = re.fullmatch(rf'(?P<name>{_VARIABLE})="\$\(mktemp\)"', segment[0].raw)
    return match.group("name") if match is not None else None


def _heredoc_writer_is_safe(segment: list[ShellTokenWithQuoteContext], *, variable: str) -> bool:
    return bool(
        len(segment) == 3 and segment[0].raw == "cat" and segment[1].raw == ">" and segment[2].raw == f'"${variable}"'
    )


def _body_cat_is_safe(segment: list[ShellTokenWithQuoteContext], *, variable: str) -> bool:
    return len(segment) == 2 and segment[0].raw == "cat" and segment[1].raw == f'"${variable}"'


def _body_grep_is_safe(segment: list[ShellTokenWithQuoteContext], *, variable: str) -> bool:
    return bool(
        len(segment) == 5
        and tuple(token.raw for token in segment[:3]) == ("if", "grep", "-nE")
        and segment[3].raw.startswith("'")
        and _is_one_fully_quoted_word(segment[3].raw)
        and not segment[3].plain.startswith("-")
        and not _shell_token_has_active_expansion(segment[3].raw)
        and segment[4].raw == f'"${variable}"'
    )


def _echo_is_safe(segment: list[ShellTokenWithQuoteContext], *, variable: str) -> bool:
    if not segment or segment[0].raw != "echo":
        return False
    if len(segment) == 1:
        return True
    if len(segment) != 2:
        return False
    raw = segment[1].raw
    if re.fullmatch(rf'"{_VARIABLE}=\${re.escape(variable)}"', raw) is not None:
        return True
    return _static_shell_argument(raw, allow_unquoted=False)


def _static_shell_argument(raw: str, *, allow_unquoted: bool = True) -> bool:
    if not raw or _shell_token_has_active_expansion(raw) or "<(" in raw or ">(" in raw:
        return False
    if _is_one_fully_quoted_word(raw):
        return True
    return allow_unquoted and _STATIC_UNQUOTED_ARGUMENT.fullmatch(raw) is not None


def _is_one_fully_quoted_word(raw: str) -> bool:
    if len(raw) < 2 or raw[0] not in {"'", '"'} or raw[-1] != raw[0]:
        return False
    quote = raw[0]
    index = 1
    while index < len(raw) - 1:
        character = raw[index]
        if quote == '"' and character == "\\":
            index += 2
            continue
        if character == quote:
            return False
        index += 1
    return index == len(raw) - 1


def _pr_create_is_safe(segment: list[ShellTokenWithQuoteContext], *, variable: str) -> bool:
    if len(segment) < 5 or tuple(token.raw for token in segment[:3]) != ("gh", "pr", "create"):
        return False
    body_operand = f"${variable}"
    sanitized_args: list[str] = []
    saw_body_variable = False
    for token in segment[3:]:
        if token.plain == body_operand:
            if token.raw != f'"${variable}"' or saw_body_variable:
                return False
            sanitized_args.append("pr-body.md")
            saw_body_variable = True
            continue
        if github_argument_token_has_untrusted_expansion(token.raw):
            return False
        if not _static_shell_argument(token.raw):
            return False
        sanitized_args.append(token.plain)
    return bool(saw_body_variable and static_markdown_pr_body_file_operand(tuple(sanitized_args)) == "pr-body.md")


__all__ = ["gh_pr_create_uses_safe_ephemeral_body"]
