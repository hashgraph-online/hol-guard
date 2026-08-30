"""Pytest target and invocation detection."""

from __future__ import annotations

import ast

from ..false_positive_rules import fd_arg_requests_exec
from ..interpreter_options import shell_interpreter_command_payload as _shell_interpreter_command_payload
from .constants_core import (
    _FIND_EXEC_ACTION_FLAGS,
    _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES,
    _SHELL_COMMAND_STRING_INTERPRETERS,
)
from .constants_patterns import (
    _PYTEST_COMMAND_NAMES,
    _PYTEST_COMMAND_RUNNER_SUBCOMMANDS,
    _PYTEST_EXECUTOR_COMMANDS,
    _PYTEST_RUNNER_OPTIONS_WITH_VALUES,
    _PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS,
    _SHELL_ASSIGNMENT_PATTERN,
)
from .github_pr_expansion import (
    _is_pytest_python_interpreter_command,
    _literal_python_argv,
    _python_call_imports_pytest,
    _python_call_resolves_pytest_main,
    _python_call_runs_pytest_module,
)
from .github_shell_capabilities import _shell_command_substitution_payloads
from .python_pytest_entrypoints import _pytest_args_from_python, _python_segment_targets_module
from .request_artifacts import _normalized_shell_command_name
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command, _split_shell_parts


def _shell_token_has_active_glob(raw_token: str) -> bool:
    index = 0
    quote: str | None = None
    while index < len(raw_token):
        character = raw_token[index]
        if character == "\\":
            index += 2
            continue
        if quote is not None:
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in {"*", "?", "["}:
            return True
        index += 1
    return False


def _shell_command_targets_pytest(command_text: str, *, depth: int = 0) -> bool:
    """Return whether shell evaluation can reach pytest outside Guard containment."""

    if depth > 8:
        return any(
            _normalized_shell_command_name(token) in _PYTEST_COMMAND_NAMES for token in _split_shell_parts(command_text)
        )
    parts = _split_shell_parts(command_text)
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index, depth=depth):
            return True
        if command_name in _SHELL_COMMAND_STRING_INTERPRETERS:
            flag_payload = _shell_interpreter_command_payload(segment, command_index)
            if flag_payload is not None and _shell_command_targets_pytest(flag_payload.script_text, depth=depth + 1):
                return True
    return any(
        _shell_command_targets_pytest(payload, depth=depth + 1)
        for payload in _shell_command_substitution_payloads(command_text)
    )


def _segment_targets_pytest(
    segment: list[str],
    command_name: str,
    command_index: int,
    *,
    depth: int = 0,
) -> bool:
    if command_name in _PYTEST_COMMAND_NAMES:
        return True
    command_args = segment[command_index + 1 :]
    if _is_pytest_python_interpreter_command(command_name):
        return _python_segment_targets_module(command_args, "pytest") or _python_inline_script_runs_pytest(command_args)
    if command_name == "uvx":
        return _argument_sequence_targets_pytest(command_args)
    runner_subcommands = _PYTEST_COMMAND_RUNNER_SUBCOMMANDS.get(command_name)
    if runner_subcommands is not None:
        return any(
            token in runner_subcommands
            and _pytest_args_from_runner_argument_sequence(command_name, command_args[index + 1 :]) is not None
            for index, token in enumerate(command_args)
        )
    if command_name in _PYTEST_EXECUTOR_COMMANDS:
        return _argument_sequence_targets_pytest(command_args)
    if command_name == "eval":
        return _shell_command_targets_pytest(" ".join(command_args), depth=depth + 1)
    if command_name == "find":
        return any(
            token in _FIND_EXEC_ACTION_FLAGS and _argument_sequence_targets_pytest(command_args[index + 1 :])
            for index, token in enumerate(command_args)
        )
    if command_name == "fd":
        return any(
            fd_arg_requests_exec(token) and _argument_sequence_targets_pytest(command_args[index + 1 :])
            for index, token in enumerate(command_args)
        )
    return False


def _argument_sequence_targets_pytest(args: list[str]) -> bool:
    return _pytest_args_from_argument_sequence(args) is not None


def _pytest_args_from_argument_sequence(args: list[str]) -> list[str] | None:
    return _pytest_args_from_argument_sequence_ignoring(args, ignored_indices=frozenset())


def _pytest_args_from_runner_argument_sequence(command_name: str, args: list[str]) -> list[str] | None:
    value_options = _PYTEST_RUNNER_OPTIONS_WITH_VALUES.get(command_name, frozenset())
    ignored_indices: set[int] = set()
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            break
        if token in value_options:
            if index + 1 >= len(args):
                return None
            ignored_indices.add(index + 1)
            index += 2
            continue
        index += 1
    positional_prefix_count = _PYTEST_RUNNER_POSITIONAL_PREFIX_COUNTS.get(command_name, 0)
    for index, token in enumerate(args):
        if index in ignored_indices or token == "--" or token.startswith("-"):
            continue
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            continue
        if positional_prefix_count:
            positional_prefix_count -= 1
            continue
        pytest_args = _pytest_args_from_command_position(args, index)
        if pytest_args is not None:
            return pytest_args
        return None
    return None


def _pytest_args_from_argument_sequence_ignoring(
    args: list[str],
    *,
    ignored_indices: frozenset[int],
) -> list[str] | None:
    for index in range(len(args)):
        if index in ignored_indices:
            continue
        pytest_args = _pytest_args_from_command_position(args, index)
        if pytest_args is not None:
            return pytest_args
    return None


def _pytest_args_from_command_position(args: list[str], index: int) -> list[str] | None:
    command_token = args[index].rsplit(":", 1)[-1]
    command_name = _normalized_shell_command_name(command_token)
    if command_name in _PYTEST_COMMAND_NAMES:
        return args[index + 1 :]
    if not _is_pytest_python_interpreter_command(command_name):
        return None
    python_args = _pytest_args_from_python(args[index + 1 :])
    if python_args is not None:
        return python_args
    if _python_inline_script_runs_pytest(args[index + 1 :]):
        return []
    return None


def _python_inline_script_runs_pytest(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-c", "--command"} and index + 1 < len(args):
            return _inline_python_payload_runs_pytest(args[index + 1])
        if token.startswith("--command="):
            return _inline_python_payload_runs_pytest(token.split("=", 1)[1])
        if token.startswith("-c") and token != "-c":
            return _inline_python_payload_runs_pytest(token[2:])
        if token in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if not token.startswith("-"):
            return False
        index += 1
    return False


def _inline_python_payload_runs_pytest(payload: str, *, depth: int = 0) -> bool:
    if depth > 8:
        return "pytest" in payload.casefold()
    try:
        tree = ast.parse(payload, mode="exec")
    except (SyntaxError, ValueError):
        return False

    pytest_module_aliases = {"pytest"}
    pytest_main_aliases: set[str] = set()
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()
    runpy_aliases = {"runpy"}
    run_module_aliases: set[str] = set()
    os_aliases = {"os"}
    os_process_aliases: set[str] = set()
    subprocess_aliases = {"subprocess"}
    subprocess_process_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "pytest":
                    pytest_module_aliases.add(alias.asname or "pytest")
                elif alias.name == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
                elif alias.name == "runpy":
                    runpy_aliases.add(alias.asname or "runpy")
                elif alias.name == "os":
                    os_aliases.add(alias.asname or "os")
                elif alias.name == "subprocess":
                    subprocess_aliases.add(alias.asname or "subprocess")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "pytest":
                pytest_main_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name in {"console_main", "main"}
                )
            elif node.module == "importlib":
                import_module_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "import_module"
                )
            elif node.module == "runpy":
                run_module_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name == "run_module"
                )
            elif node.module == "os":
                os_process_aliases.update(
                    alias.asname or alias.name for alias in node.names if alias.name in {"popen", "system"}
                )
            elif node.module == "subprocess":
                subprocess_process_aliases.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name in {"Popen", "call", "check_call", "check_output", "run"}
                )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name) and function.id in pytest_main_aliases:
            return True
        if isinstance(function, ast.Call) and _python_call_resolves_pytest_main(
            function,
            pytest_module_aliases=pytest_module_aliases,
            importlib_aliases=importlib_aliases,
            import_module_aliases=import_module_aliases,
        ):
            return True
        if isinstance(function, ast.Attribute) and function.attr in {"console_main", "main"}:
            if isinstance(function.value, ast.Name) and function.value.id in pytest_module_aliases:
                return True
            if isinstance(function.value, ast.Call) and _python_call_imports_pytest(
                function.value,
                importlib_aliases=importlib_aliases,
                import_module_aliases=import_module_aliases,
            ):
                return True
        if _python_call_runs_pytest_module(
            node,
            runpy_aliases=runpy_aliases,
            run_module_aliases=run_module_aliases,
        ):
            return True
        if _python_process_call_targets_pytest(
            node,
            depth=depth,
            os_aliases=os_aliases,
            os_process_aliases=os_process_aliases,
            subprocess_aliases=subprocess_aliases,
            subprocess_process_aliases=subprocess_process_aliases,
        ):
            return True
        if (
            isinstance(function, ast.Name)
            and function.id in {"eval", "exec"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and _inline_python_payload_runs_pytest(node.args[0].value, depth=depth + 1)
        ):
            return True
    return False


def _python_process_call_targets_pytest(
    node: ast.Call,
    *,
    depth: int,
    os_aliases: set[str],
    os_process_aliases: set[str],
    subprocess_aliases: set[str],
    subprocess_process_aliases: set[str],
) -> bool:
    function = node.func
    recognized = isinstance(function, ast.Name) and function.id in {
        *os_process_aliases,
        *subprocess_process_aliases,
    }
    if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
        recognized = recognized or (function.value.id in os_aliases and function.attr in {"popen", "system"})
        recognized = recognized or (
            function.value.id in subprocess_aliases
            and function.attr in {"Popen", "call", "check_call", "check_output", "run"}
        )
    if not recognized:
        return False

    command_node: ast.expr | None = node.args[0] if node.args else None
    if command_node is None:
        command_node = next((keyword.value for keyword in node.keywords if keyword.arg in {"args", "command"}), None)
    if isinstance(command_node, ast.Constant) and isinstance(command_node.value, str):
        return _shell_command_targets_pytest(command_node.value, depth=depth + 1)
    literal_argv = _literal_python_argv(command_node)
    return literal_argv is not None and _argument_sequence_targets_pytest(literal_argv)


__all__ = [
    "_argument_sequence_targets_pytest",
    "_inline_python_payload_runs_pytest",
    "_pytest_args_from_argument_sequence",
    "_pytest_args_from_argument_sequence_ignoring",
    "_pytest_args_from_command_position",
    "_pytest_args_from_runner_argument_sequence",
    "_python_inline_script_runs_pytest",
    "_python_process_call_targets_pytest",
    "_segment_targets_pytest",
    "_shell_command_targets_pytest",
    "_shell_token_has_active_glob",
]
