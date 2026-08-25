"""Pytest configuration and module execution safety."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..pytest_config import PytestConfigAssessment, assess_pytest_configs, assess_selected_pytest_config
from .constants_core import (
    _PYTEST_OPTION_CONFIG_PATHS,
    _PYTEST_SAFE_FLAGS,
    _PYTEST_SAFE_FLAGS_WITH_VALUES,
    _PYTEST_UNSAFE_ENV_KEYS,
    _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES,
    _PYTHON_MODULE_MUTATING_FLAGS,
    _PYTHON_MODULE_MUTATING_SUBCOMMANDS,
    _PYTHON_MODULE_OPTIONS_WITH_VALUES,
    _SAFE_PYTHON_MODULE_COMMANDS,
)
from .interpreter_observers import (
    _python_module_may_be_shadowed,
    _python_module_may_be_shadowed_in_search_roots,
    _shell_segment_explicit_env_value,
)
from .read_only_filters import _split_attached_redirection_token


def _python_module_root_from_args(args: list[str]) -> str | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return None
        if arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return None
        if arg == "-m":
            module = args[index + 1] if index + 1 < len(args) else ""
            return module.split(".", 1)[0] or None
        if arg.startswith("-m") and len(arg) > 2:
            return arg[2:].split(".", 1)[0] or None
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            return None
        index += 1
    return None


def _python_module_unsafe_env_keys(module_root: str | None) -> frozenset[str]:
    if module_root == "pytest":
        return _PYTEST_UNSAFE_ENV_KEYS
    return _PYTEST_UNSAFE_ENV_KEYS - frozenset({"PYTHONPATH"})


def _shell_args_without_trailing_redirections(args: list[str]) -> list[str]:
    trimmed = list(args)
    while trimmed and _is_shell_redirection_token(trimmed[-1]):
        trimmed.pop()
    return trimmed


def _is_shell_redirection_token(token: str) -> bool:
    if token in {"|", "|&"}:
        return True
    if _split_attached_redirection_token(token) is not None:
        return True
    return bool(re.fullmatch(r"[012]?>&?\S*", token) or re.fullmatch(r"[012]?>>?", token))


def _python_segment_runs_safe_module(args: list[str], *, cwd: Path | None = None) -> bool:
    args = _shell_args_without_trailing_redirections(args)
    if not args:
        return False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return False
        if arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return False
        if arg == "-m":
            module = args[index + 1] if index + 1 < len(args) else ""
            return _python_module_args_are_safe(module, args[index + 2 :], cwd=cwd)
        if arg.startswith("-m") and len(arg) > 2:
            module = arg[2:]
            return _python_module_args_are_safe(module, args[index + 1 :], cwd=cwd)
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            return False
        index += 1
    return False


def _python_module_args_are_safe(module: str, module_args: list[str], *, cwd: Path | None = None) -> bool:
    module_root = module.split(".", 1)[0]
    if module_root not in _SAFE_PYTHON_MODULE_COMMANDS:
        return False
    if _python_module_may_be_shadowed(module_root, cwd):
        return False
    if module_root == "pytest" and _pytest_config_may_add_unsafe_options(cwd, module_args):
        return False
    if module_root == "pytest" and not _pytest_module_args_are_safe(module_args):
        return False
    mutating_subcommands = _PYTHON_MODULE_MUTATING_SUBCOMMANDS.get(module_root, frozenset())
    subcommand = _python_module_subcommand(module_root, module_args)
    if subcommand in mutating_subcommands:
        return module_root == "ruff" and _ruff_format_target_is_bounded(module_args, cwd=cwd)
    mutating_flags = _PYTHON_MODULE_MUTATING_FLAGS.get(module_root, frozenset())
    return not any(
        arg in mutating_flags or any(arg.startswith(f"{flag}=") for flag in mutating_flags) for arg in module_args
    )


def _ruff_format_target_is_bounded(module_args: list[str], *, cwd: Path | None) -> bool:
    if cwd is None or len(module_args) != 2 or module_args[0] != "format":
        return False
    target = Path(module_args[1])
    if target.is_absolute() or ".." in target.parts or any(marker in module_args[1] for marker in ("$", "`")):
        return False
    try:
        workspace = cwd.resolve(strict=True)
        resolved = (workspace / target).resolve(strict=True)
        _ = resolved.relative_to(workspace)
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved.is_file()


def _python_module_may_be_shadowed_from_execution_context(
    module_root: str | None,
    *,
    cwd: Path | None,
    segment: list[str],
    command_index: int,
) -> bool:
    if module_root is None:
        return True
    search_roots: list[Path] = []
    if cwd is not None:
        search_roots.append(cwd)
    search_roots.extend(_pythonpath_search_roots_from_segment(segment, command_index, cwd=cwd))
    return _python_module_may_be_shadowed_in_search_roots(module_root, search_roots)


def _pythonpath_search_roots_from_segment(
    segment: list[str],
    command_index: int,
    *,
    cwd: Path | None,
) -> list[Path]:
    if cwd is None:
        return []
    search_roots: list[Path] = []
    is_set, path_value, complete = _shell_segment_explicit_env_value(
        segment,
        command_index,
        "PYTHONPATH",
    )
    if not complete or not is_set or path_value is None:
        return search_roots
    for entry in path_value.split(":"):
        normalized_entry = entry.strip()
        if not normalized_entry:
            continue
        candidate = Path(normalized_entry)
        search_roots.append(candidate if candidate.is_absolute() else cwd / candidate)
    return search_roots


def _pytest_config_may_add_unsafe_options(cwd: Path | None, module_args: list[str]) -> bool:
    if cwd is None:
        return True
    return _pytest_config_assessment(cwd, module_args).unsafe


def _pytest_config_assessment(cwd: Path, module_args: list[str]) -> PytestConfigAssessment:
    explicit_config_paths = _pytest_explicit_config_paths(module_args, cwd=cwd)
    if explicit_config_paths is None:
        return assess_pytest_configs(cwd, ("../invalid-pytest-config-search",))
    if explicit_config_paths:
        return assess_pytest_configs(cwd, explicit_config_paths, require_present=True)
    config_dirs = _pytest_config_search_dirs(module_args, cwd=cwd)
    if config_dirs is None:
        return assess_pytest_configs(cwd, ("../invalid-pytest-config-search",))
    candidates = tuple(
        (Path(config_dir) / config_path).as_posix()
        for config_dir in config_dirs
        for config_path in _PYTEST_OPTION_CONFIG_PATHS
    )
    return assess_selected_pytest_config(cwd, candidates)


def _pytest_explicit_config_paths(module_args: list[str], *, cwd: Path) -> tuple[str, ...] | None:
    paths: list[str] = []
    index = 0
    while index < len(module_args):
        token = module_args[index]
        path_text: str | None = None
        if token in {"-c", "--config-file"}:
            if index + 1 >= len(module_args):
                return None
            path_text = module_args[index + 1]
            index += 2
        elif token.startswith("--config-file="):
            path_text = token.split("=", 1)[1]
            index += 1
        elif token.startswith("-c="):
            path_text = token[3:]
            index += 1
        elif token.startswith("-c") and len(token) > 2:
            path_text = token[2:]
            index += 1
        else:
            index += 1
            continue
        selected_path = _pytest_selected_relative_path(path_text, cwd=cwd)
        if selected_path is None or not selected_path:
            return None
        paths.append(selected_path)
    return (paths[-1],) if paths else ()


def _pytest_config_search_dirs(module_args: list[str], *, cwd: Path) -> tuple[str, ...] | None:
    positional_args = _pytest_positional_args(module_args)
    if not positional_args:
        return ("",)
    selected_paths: list[str] = []
    for module_arg in positional_args:
        selected_path = _pytest_selected_relative_path(module_arg, cwd=cwd)
        if selected_path is None:
            return None
        if selected_path == "":
            continue
        config_root = Path(selected_path)
        if not (cwd / config_root).is_dir():
            config_root = config_root.parent
        selected_paths.append("" if str(config_root) == "." else config_root.as_posix())
    if not selected_paths:
        return ("",)
    try:
        selected_root = Path(os.path.commonpath(selected_paths))
    except ValueError:
        return None
    return _pytest_config_ancestor_dirs(selected_root)


def _pytest_selected_relative_path(module_arg: str, *, cwd: Path) -> str | None:
    path_text = module_arg.split("::", 1)[0]
    if not path_text:
        return ""
    path = Path(path_text)
    if ".." in path.parts:
        return None
    if not path.is_absolute():
        return path.as_posix()
    cwd_text = str(cwd)
    path_text = str(path)
    if path_text == cwd_text:
        return ""
    prefix = f"{cwd_text}{os.sep}"
    if not path_text.startswith(prefix):
        return None
    relative_text = path_text[len(prefix) :]
    relative_path = Path(relative_text)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        return None
    return relative_path.as_posix()


def _pytest_config_ancestor_dirs(root: Path) -> tuple[str, ...]:
    if str(root) in {"", "."}:
        return ("",)
    dirs: list[str] = []
    current = root
    while str(current) not in {"", "."}:
        dirs.append(current.as_posix())
        current = current.parent
    dirs.append("")
    return tuple(dirs)


def _pytest_positional_args(module_args: list[str]) -> tuple[str, ...]:
    positional_args: list[str] = []
    index = 0
    while index < len(module_args):
        arg = module_args[index]
        if arg == "--":
            return tuple(positional_args)
        if arg in _PYTEST_SAFE_FLAGS:
            index += 1
            continue
        if arg in _PYTEST_SAFE_FLAGS_WITH_VALUES:
            index += 2
            continue
        if arg in {"-c", "--config-file"}:
            index += 2
            continue
        if any(arg.startswith(f"{flag}=") for flag in _PYTEST_SAFE_FLAGS_WITH_VALUES):
            index += 1
            continue
        if not arg.startswith("-"):
            positional_args.append(arg)
        index += 1
    return tuple(positional_args)


def _pytest_module_args_are_safe(module_args: list[str]) -> bool:
    index = 0
    while index < len(module_args):
        arg = module_args[index]
        if arg == "--":
            return False
        if arg in _PYTEST_SAFE_FLAGS:
            index += 1
            continue
        if arg in _PYTEST_SAFE_FLAGS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(f"{flag}=") for flag in _PYTEST_SAFE_FLAGS_WITH_VALUES):
            index += 1
            continue
        if arg.startswith("-"):
            return False
        index += 1
    return True


def _python_module_subcommand(module_root: str, module_args: list[str]) -> str | None:
    options_with_values = _PYTHON_MODULE_OPTIONS_WITH_VALUES.get(module_root, frozenset())
    index = 0
    while index < len(module_args):
        arg = module_args[index]
        if arg == "--":
            return None
        if arg in options_with_values:
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in options_with_values):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return None


__all__ = [
    "_is_shell_redirection_token",
    "_pytest_config_ancestor_dirs",
    "_pytest_config_assessment",
    "_pytest_config_may_add_unsafe_options",
    "_pytest_config_search_dirs",
    "_pytest_explicit_config_paths",
    "_pytest_module_args_are_safe",
    "_pytest_positional_args",
    "_pytest_selected_relative_path",
    "_python_module_args_are_safe",
    "_python_module_may_be_shadowed_from_execution_context",
    "_python_module_root_from_args",
    "_python_module_subcommand",
    "_python_module_unsafe_env_keys",
    "_python_segment_runs_safe_module",
    "_pythonpath_search_roots_from_segment",
    "_shell_args_without_trailing_redirections",
]
