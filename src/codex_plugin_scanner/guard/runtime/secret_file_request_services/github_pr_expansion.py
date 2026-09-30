"""GitHub pull-request argument expansion checks."""

from __future__ import annotations

import ast
import re

from ..env_wrapper import parse_env_wrapper
from .constants_core import _SHELL_CONTROL_PREFIX_TOKENS, _SUDO_OPTION_VALUE_FLAGS, _SUDO_OPTION_VALUE_LONG_FLAGS
from .constants_patterns import _SHELL_ASSIGNMENT_PATTERN
from .github_shell_capabilities import (
    _command_builtin_options_are_lookup_only,
    _shell_command_substitution_payloads,
    _shell_segment_env_index,
    _ShellTokenWithQuoteContext,
)
from .request_artifacts import _normalized_shell_command_name
from .shell_quote_parsing import (
    _gh_pr_env_split_string_payloads_with_substitution,
    _shell_token_segments,
    _shell_tokens_preserving_quote_context,
    _skip_generic_shell_wrapper_options,
    _skip_gh_pr_options,
)
from .shell_tokenization import (
    _leading_shell_redirection_tokens_consumed,
    _shell_command_token_without_attached_redirection,
)


def _gh_pr_create_body_has_shell_command_substitution(command_text: str, *, depth: int = 0) -> bool:
    if depth > 2:
        return False
    if not _shell_command_substitution_payloads(command_text):
        return False
    tokens = _shell_tokens_preserving_quote_context(command_text)
    for segment in _shell_token_segments(tokens):
        for env_split_string in _gh_pr_env_split_string_payloads_with_substitution(segment):
            if _gh_pr_create_body_has_shell_command_substitution(env_split_string, depth=depth + 1):
                return True
        body_args_start_index = _gh_pr_create_body_args_start_index(segment)
        if body_args_start_index is None:
            continue
        if _gh_pr_create_body_args_have_substitution(segment[body_args_start_index:]):
            return True
    return False


def _gh_pr_edit_has_shell_command_substitution(command_text: str) -> bool:
    if not _shell_command_substitution_payloads(command_text):
        return False
    for segment in _shell_token_segments(_shell_tokens_preserving_quote_context(command_text)):
        plain = [token.plain for token in segment]
        if any(plain[index : index + 3] == ["gh", "pr", "edit"] for index in range(max(0, len(plain) - 2))):
            return True
    return False


def _gh_pr_create_has_active_shell_expansion(command_text: str, *, depth: int = 0) -> bool:
    if depth > 2 or ("$" not in command_text and "`" not in command_text):
        return False
    tokens = _shell_tokens_preserving_quote_context(command_text)
    for segment in _shell_token_segments(tokens):
        for env_split_string in _gh_pr_env_split_string_payloads_with_active_expansion(segment):
            if _gh_pr_create_has_active_shell_expansion(env_split_string, depth=depth + 1):
                return True
        args_start_index = _gh_pr_create_body_args_start_index(segment)
        if args_start_index is None:
            continue
        plain_segment = [token.plain for token in segment]
        index = args_start_index
        while index < len(segment):
            redirect_tokens_consumed = _leading_shell_redirection_tokens_consumed(plain_segment, index)
            if redirect_tokens_consumed > 0:
                index += redirect_tokens_consumed
                continue
            if _shell_token_has_active_expansion(segment[index].raw):
                return True
            index += 1
    return False


def _gh_pr_env_split_string_payloads_with_active_expansion(
    segment: list[_ShellTokenWithQuoteContext],
) -> tuple[str, ...]:
    env_index = _shell_segment_env_index([token.plain for token in segment])
    if env_index is None:
        return ()
    parsed = parse_env_wrapper([token.plain for token in segment[env_index + 1 :]])
    payloads: list[str] = []
    for expansion in parsed.split_expansions:
        source_index = env_index + 1 + expansion.source_index
        if source_index < len(segment) and _shell_token_has_active_expansion(segment[source_index].raw):
            payloads.append(expansion.payload.strip())
    return tuple(payload for payload in payloads if payload)


def _shell_token_has_active_expansion(raw_token: str) -> bool:
    index = 0
    single_quoted = False
    double_quoted = False
    parameter_prefixes = frozenset("{(_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz*?@#$!-")
    while index < len(raw_token):
        character = raw_token[index]
        if single_quoted:
            if character == "'":
                single_quoted = False
            index += 1
            continue
        if character == "\\":
            index += 2
            continue
        if character == "'" and not double_quoted:
            single_quoted = True
            index += 1
            continue
        if character == '"':
            double_quoted = not double_quoted
            index += 1
            continue
        if character == "`":
            return True
        if character == "$" and index + 1 < len(raw_token) and raw_token[index + 1] in parameter_prefixes:
            return True
        index += 1
    return False


def _gh_pr_create_body_args_start_index(segment: list[_ShellTokenWithQuoteContext]) -> int | None:
    return _gh_pr_body_args_start_index(segment, operations=frozenset({"create", "new"}))


def _gh_pr_body_args_start_index(
    segment: list[_ShellTokenWithQuoteContext],
    *,
    operations: frozenset[str],
) -> int | None:
    index = 0
    plain_segment = [token.plain for token in segment]
    while index < len(segment):
        redirect_tokens_consumed = _leading_shell_redirection_tokens_consumed(plain_segment, index)
        if redirect_tokens_consumed > 0:
            index += redirect_tokens_consumed
            continue
        token = segment[index]
        command_name = _normalized_shell_command_name(_shell_command_token_without_attached_redirection(token.plain))
        if command_name == "gh":
            if index + 1 >= len(segment) or segment[index + 1].plain != "pr":
                return None
            pr_command_index = _skip_gh_pr_options(segment, index + 2)
            if pr_command_index >= len(segment):
                return None
            if segment[pr_command_index].plain in operations:
                return pr_command_index + 1
            return None
        if _SHELL_ASSIGNMENT_PATTERN.match(_shell_command_token_without_attached_redirection(token.plain)):
            index += 1
            continue
        if command_name == "command":
            if _command_builtin_options_are_lookup_only(segment, index + 1):
                return None
            index = _skip_command_builtin_options(segment, index + 1)
            continue
        if command_name == "time":
            index = _skip_generic_shell_wrapper_options(command_name, segment, index + 1)
            continue
        if command_name == "env":
            index = _skip_env_wrapper_options(segment, index + 1)
            continue
        if command_name == "sudo":
            index = _skip_sudo_wrapper_options(segment, index + 1)
            continue
        if command_name in {"nice", "nohup", "stdbuf"}:
            index = _skip_generic_shell_wrapper_options(command_name, segment, index + 1)
            continue
        if command_name == "case":
            index = _skip_shell_case_header(segment, index + 1)
            continue
        if command_name == "select":
            index = _skip_shell_select_header(segment, index + 1)
            continue
        if token.plain in _SHELL_CONTROL_PREFIX_TOKENS or command_name in _SHELL_CONTROL_PREFIX_TOKENS:
            index += 1
            continue
        return None
    return None


def _skip_command_builtin_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return index + 1
        if plain.startswith("-"):
            index += 1
            continue
        break
    return index


def _skip_shell_case_header(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        if segment[index].plain.endswith(")"):
            return index + 1
        index += 1
    return index


def _skip_shell_select_header(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        if segment[index].plain == "do":
            return index
        index += 1
    return index


def _skip_env_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    parsed = parse_env_wrapper([token.plain for token in segment[index:]])
    if not parsed.complete or parsed.command_index is None or parsed.split_expansions:
        return len(segment)
    return index + parsed.command_index


def _skip_sudo_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain in _SUDO_OPTION_VALUE_FLAGS:
            index += 2
            continue
        if plain in _SUDO_OPTION_VALUE_LONG_FLAGS:
            index += 2
            continue
        if any(plain.startswith(f"{flag}=") for flag in _SUDO_OPTION_VALUE_LONG_FLAGS):
            index += 1
            continue
        if plain.startswith("-"):
            index += 1
            continue
        break
    return index


def _gh_pr_create_body_args_have_substitution(args: list[_ShellTokenWithQuoteContext]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.plain in {"--body", "-b", "--body-file", "-F"}:
            if index + 1 >= len(args):
                return False
            if _shell_command_substitution_payloads(args[index + 1].raw):
                return True
            index += 2
            continue
        if arg.plain.startswith("-F") and len(arg.plain) > 2 and _shell_command_substitution_payloads(arg.raw):
            return True
        if arg.plain.startswith("-b") and len(arg.plain) > 2 and _shell_command_substitution_payloads(arg.raw):
            return True
        if arg.plain.startswith("--body-file=") and _shell_command_substitution_payloads(arg.raw):
            return True
        if arg.plain.startswith("--body=") and _shell_command_substitution_payloads(arg.raw):
            return True
        index += 1
    return False


def _literal_python_argv(node: ast.expr | None) -> list[str] | None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    argv: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return None
        argv.append(element.value)
    return argv


def _python_call_resolves_pytest_main(
    node: ast.Call,
    *,
    pytest_module_aliases: set[str],
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> bool:
    if (
        not isinstance(node.func, ast.Name)
        or node.func.id != "getattr"
        or len(node.args) < 2
        or not isinstance(node.args[1], ast.Constant)
        or node.args[1].value not in {"console_main", "main"}
    ):
        return False
    target = node.args[0]
    if isinstance(target, ast.Name):
        return target.id in pytest_module_aliases
    return isinstance(target, ast.Call) and _python_call_imports_pytest(
        target,
        importlib_aliases=importlib_aliases,
        import_module_aliases=import_module_aliases,
    )


def _python_call_imports_pytest(
    node: ast.Call,
    *,
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> bool:
    if not node.args or not isinstance(node.args[0], ast.Constant) or node.args[0].value != "pytest":
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id == "__import__" or node.func.id in import_module_aliases
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "import_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in importlib_aliases
    )


def _python_call_runs_pytest_module(
    node: ast.Call,
    *,
    runpy_aliases: set[str],
    run_module_aliases: set[str],
) -> bool:
    if (
        not node.args
        or not isinstance(node.args[0], ast.Constant)
        or node.args[0].value not in {"pytest", "pytest.__main__"}
    ):
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id in run_module_aliases
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "run_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in runpy_aliases
    )


def _is_pytest_python_interpreter_command(command_name: str) -> bool:
    return re.fullmatch(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?", command_name) is not None


__all__ = [
    "_gh_pr_body_args_start_index",
    "_gh_pr_create_body_args_have_substitution",
    "_gh_pr_create_body_args_start_index",
    "_gh_pr_create_body_has_shell_command_substitution",
    "_gh_pr_create_has_active_shell_expansion",
    "_gh_pr_edit_has_shell_command_substitution",
    "_gh_pr_env_split_string_payloads_with_active_expansion",
    "_is_pytest_python_interpreter_command",
    "_literal_python_argv",
    "_python_call_imports_pytest",
    "_python_call_resolves_pytest_main",
    "_python_call_runs_pytest_module",
    "_shell_token_has_active_expansion",
    "_skip_command_builtin_options",
    "_skip_env_wrapper_options",
    "_skip_shell_case_header",
    "_skip_shell_select_header",
    "_skip_sudo_wrapper_options",
]
