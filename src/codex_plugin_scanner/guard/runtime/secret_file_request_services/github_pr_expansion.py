"""Public carriers delegated to the existing native shell kernels."""

from __future__ import annotations

import ast
import re

from ...native_shell_request_authority import shell_request_authority
from .shell_quote_tokens import ShellTokenWithQuoteContext as _ShellTokenWithQuoteContext


def _gh_pr_create_body_has_shell_command_substitution(command_text: str, *, depth: int = 0) -> bool:
    return shell_request_authority("_gh_pr_create_body_has_shell_command_substitution", locals())


def _gh_pr_edit_has_shell_command_substitution(command_text: str) -> bool:
    return shell_request_authority("_gh_pr_edit_has_shell_command_substitution", locals())


def _gh_pr_create_has_active_shell_expansion(command_text: str, *, depth: int = 0) -> bool:
    return shell_request_authority("_gh_pr_create_has_active_shell_expansion", locals())


def _gh_pr_env_split_string_payloads_with_active_expansion(
    segment: list[_ShellTokenWithQuoteContext],
) -> tuple[str, ...]:
    return tuple(shell_request_authority("_gh_pr_env_split_string_payloads_with_active_expansion", locals()))


def _shell_token_has_active_expansion(raw_token: str) -> bool:
    return shell_request_authority("_shell_token_has_active_expansion", locals())


def _gh_pr_create_body_args_start_index(segment: list[_ShellTokenWithQuoteContext]) -> int | None:
    return shell_request_authority("_gh_pr_create_body_args_start_index", locals())


def _gh_pr_body_args_start_index(
    segment: list[_ShellTokenWithQuoteContext], *, operations: frozenset[str]
) -> int | None:
    return shell_request_authority("_gh_pr_body_args_start_index", locals())


def _skip_command_builtin_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    return shell_request_authority("_skip_command_builtin_options", locals())


def _skip_shell_case_header(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    return shell_request_authority("_skip_shell_case_header", locals())


def _skip_shell_select_header(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    return shell_request_authority("_skip_shell_select_header", locals())


def _skip_env_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    return shell_request_authority("_skip_env_wrapper_options", locals())


def _skip_sudo_wrapper_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    return shell_request_authority("_skip_sudo_wrapper_options", locals())


def _gh_pr_create_body_args_have_substitution(args: list[_ShellTokenWithQuoteContext]) -> bool:
    return shell_request_authority("_gh_pr_create_body_args_have_substitution", locals())


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
