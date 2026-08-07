"""Read-only interpreter and observer recognition."""

from __future__ import annotations

from pathlib import Path

from ..env_wrapper import parse_env_wrapper
from ..interpreter_options import shell_interpreter_command_payload as _shell_interpreter_command_payload
from .constants_core import (
    _PYTEST_UNSAFE_ENV_KEYS,
    _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES,
    _READ_ONLY_LOOKUP_COMMANDS,
    _READ_ONLY_LOOKUP_FILTERS,
    _SAFE_PYTHON_MODULE_SHADOW_PATHS,
    _SAFE_SHELL_REDIRECT_TARGETS,
    _SAFE_STATIC_SHELL_COMMANDS,
    _SHELL_COMMAND_STRING_INTERPRETERS,
    _SHELL_STARTUP_ENV_KEYS,
)
from .constants_patterns import _SINGLE_INTERPRETER_HEREDOC_PATTERN
from .destructive_shell_detection import (
    _normalized_redirect_target,
    _shell_script_targets_pytest,
    _single_interpreter_heredoc_script,
)
from .developer_inspection import (
    _is_read_only_observer_interpreter_command,
    _read_only_lookup_primary_segment_is_safe,
    _ripgrep_config_is_disabled,
    _static_shell_segment_is_safe,
)
from .github_pr_body_safety import _shell_heredoc_payloads
from .local_read_operands import _ripgrep_args_expand_hidden_files
from .read_only_filters import _read_only_lookup_filter_segment_is_safe, _split_attached_redirection_token
from .request_artifacts import _normalized_shell_command_name
from .shell_static_safety import (
    _is_python_interpreter_command,
    _is_script_interpreter_command,
    _script_interpreter_texts,
    _script_is_benign_wait,
    _script_is_read_only_observer,
)
from .shell_tokenization import (
    _iter_shell_command_segments,
    _shell_command_token_without_attached_redirection,
    _shell_segment_primary_command,
)


def _looks_like_safe_read_only_lookup_command(
    command_text: str,
    parts: list[str],
    *,
    home_dir: Path | None,
) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    if any(token in parts for token in {";", "&", "||", "|&"}):
        return False
    segments = _read_only_lookup_segments(parts)
    if not segments:
        return False
    for index, segment in enumerate(segments):
        if not segment:
            return False
        command, command_index = _shell_segment_primary_command(segment)
        if command is None or command_index is None:
            return False
        command_token = segment[command_index]
        args = segment[command_index + 1 :]
        if "/" in command_token or "\\" in command_token:
            return False
        if command_index > 0:
            direct_config_prefix = segment[:command_index]
            if (
                index != 0
                or command != "rg"
                or not _ripgrep_config_is_disabled(args)
                or any(_shell_env_assignment_key(token) != "RIPGREP_CONFIG_PATH" for token in direct_config_prefix)
            ):
                return False
        if index > 0 and command not in _READ_ONLY_LOOKUP_FILTERS:
            return False
        if index == 0:
            if command not in _READ_ONLY_LOOKUP_COMMANDS:
                return False
            if command == "rg" and _ripgrep_args_expand_hidden_files(args):
                return False
            if not _read_only_lookup_primary_segment_is_safe(command, args, home_dir=home_dir):
                return False
        elif not _read_only_lookup_filter_segment_is_safe(command, args, home_dir=home_dir):
            return False
    return True


def _read_only_lookup_segments(parts: list[str]) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    for token in parts:
        if token in {"|", "&&"}:
            if not segments[-1]:
                return []
            segments.append([])
            continue
        normalized_token = token.strip()
        if not normalized_token:
            continue
        if _read_only_lookup_token_is_safe_stderr_discard(normalized_token):
            continue
        if _split_attached_redirection_token(normalized_token) is not None:
            return []
        segments[-1].append(normalized_token)
    return [segment for segment in segments if segment]


def _read_only_lookup_token_is_safe_stderr_discard(token: str) -> bool:
    redirection = _split_attached_redirection_token(token)
    if redirection is None:
        return False
    prefix, fd, _op, target = redirection
    return not prefix and fd == "2" and _normalized_redirect_target(target).lower() in _SAFE_SHELL_REDIRECT_TARGETS


def _contains_pytest_env_shell_script_wrapper(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS or command_index is None:
            continue
        has_unsafe_env = any(
            _shell_segment_sets_env_key(segment, command_index, env_key)
            for env_key in _PYTEST_UNSAFE_ENV_KEYS | _SHELL_STARTUP_ENV_KEYS
        )
        if not has_unsafe_env:
            continue
        flag_payload = _shell_interpreter_command_payload(segment, command_index)
        if flag_payload is not None and _shell_script_targets_pytest(flag_payload.script_text):
            return True
    return False


def _looks_like_benign_interpreter_wait(command_text: str, parts: list[str], command_names: list[str]) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    if not command_names or not all(_is_script_interpreter_command(command_name) for command_name in command_names):
        return False
    scripts = _script_interpreter_texts(parts)
    if not scripts or len(scripts) != len(command_names):
        return False
    return all(_script_is_benign_wait(script_text) for script_text in scripts)


def _looks_like_benign_interpreter_wait_chain(command_text: str, parts: list[str]) -> bool:
    """Allow a bounded interpreter wait followed only by static completion markers."""

    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return False
    if any(token in parts for token in {";", "&", "||", "|", "|&"}):
        return False
    saw_wait = False
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            return False
        args = segment[command_index + 1 :]
        if _is_script_interpreter_command(command_name):
            scripts = _script_interpreter_texts(segment)
            if len(scripts) != 1 or not _script_is_benign_wait(scripts[0]):
                return False
            saw_wait = True
            continue
        if command_name in _SAFE_STATIC_SHELL_COMMANDS and _static_shell_segment_is_safe(args):
            continue
        return False
    return saw_wait


def _looks_like_read_only_interpreter_compound(
    command_text: str,
    parts: list[str],
    *,
    home_dir: Path | None = None,
) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return False
    segments = _iter_shell_command_segments(parts)
    if len(segments) < 2:
        return False
    saw_interpreter = False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            return False
        if _is_python_interpreter_command(command_name):
            scripts = list(_script_interpreter_texts(segment))
            if len(scripts) != 1 or not _script_is_read_only_observer(scripts[0]):
                return False
            saw_interpreter = True
            continue
        segment_text = " ".join(segment)
        if not _looks_like_safe_read_only_lookup_command(segment_text, segment, home_dir=home_dir):
            return False
    return saw_interpreter


def _looks_like_read_only_interpreter_command(command_text: str, parts: list[str], command_names: list[str]) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    if any(
        _is_python_interpreter_command(command_name) for command_name in command_names
    ) and _parts_use_python_module_mode(parts):
        return False
    heredoc_script = _single_interpreter_heredoc_script(command_text)
    if heredoc_script is not None:
        heredoc_interpreter = _single_interpreter_heredoc_interpreter(command_text)
        if heredoc_interpreter is None or not _is_read_only_observer_interpreter_command(heredoc_interpreter):
            return False
        heredoc_args = _single_interpreter_heredoc_args(command_text)
        if heredoc_args not in {"", "-"}:
            return False
        scripts = list(_script_interpreter_texts(parts))
        if scripts:
            scripts.append(heredoc_script)
            return all(_script_is_read_only_observer(script_text) for script_text in scripts)
        return _script_is_read_only_observer(heredoc_script)
    if not command_names or not all(
        _is_read_only_observer_interpreter_command(command_name) for command_name in command_names
    ):
        return False
    scripts = list(_script_interpreter_texts(parts))
    scripts.extend(_shell_heredoc_payloads(command_text))
    if not scripts or len(scripts) != len(command_names):
        return False
    return all(_script_is_read_only_observer(script_text) for script_text in scripts)


def _shell_env_assignment_key(token: str) -> str | None:
    append_index = token.find("+=")
    assignment_index = token.find("=")
    if append_index >= 0 and append_index < assignment_index:
        key = token.split("+=", 1)[0]
    elif assignment_index >= 0:
        key = token.split("=", 1)[0]
    else:
        return None
    if not key:
        return None
    return key.upper()


def _shell_segment_sets_env_key(segment: list[str], command_index: int, env_key: str) -> bool:
    is_set, _value, complete = _shell_segment_explicit_env_value(segment, command_index, env_key)
    return is_set or not complete


def _shell_segment_explicit_env_value(
    segment: list[str],
    command_index: int,
    env_key: str,
) -> tuple[bool, str | None, bool]:
    normalized_env_key = env_key.upper()
    is_set = False
    value: str | None = None
    index = 0
    while index < command_index:
        token = _shell_command_token_without_attached_redirection(segment[index])
        assignment_key = _shell_env_assignment_key(token)
        if assignment_key == normalized_env_key:
            is_set = True
            value = token.split("=", 1)[1] if "=" in token else ""
            index += 1
            continue
        if _normalized_shell_command_name(token) != "env":
            index += 1
            continue
        parsed = parse_env_wrapper(segment[index + 1 :])
        if not parsed.complete:
            return is_set, value, False
        if parsed.option_effects.ignore_environment or any(
            name.upper() == normalized_env_key for name in parsed.option_effects.unset_names
        ):
            is_set = False
            value = None
        for name, assignment_value in parsed.environment_delta.assignments:
            if name.upper() == normalized_env_key:
                is_set = True
                value = assignment_value
        if parsed.command_index is None or parsed.split_expansions:
            break
        index += parsed.command_index + 1
    return is_set, value, True


def _parts_use_python_module_mode(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None or not _is_python_interpreter_command(command_name):
            continue
        if _python_args_use_module_mode(segment[command_index + 1 :]):
            return True
    return False


def _python_args_use_module_mode(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--" or arg in {"-c", "--command"} or arg.startswith(("-c", "--command=")):
            return False
        if arg == "-m" or (arg.startswith("-m") and len(arg) > 2):
            return True
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if arg.startswith("-") and not arg.startswith("--"):
            module_index = arg.find("m", 1)
            clusterable_flags = frozenset("bBdEhiIOPqRsSuvV")
            if module_index >= 1 and all(flag in clusterable_flags for flag in arg[1:module_index]):
                return True
        if not arg.startswith("-"):
            return False
        index += 1
    return False


def _python_module_may_be_shadowed(module_root: str, cwd: Path | None) -> bool:
    return _python_module_may_be_shadowed_in_search_roots(module_root, [cwd] if cwd is not None else [])


def _python_module_may_be_shadowed_in_search_roots(module_root: str, search_roots: list[Path]) -> bool:
    if not search_roots:
        return True
    shadow_paths = _SAFE_PYTHON_MODULE_SHADOW_PATHS.get(module_root)
    if shadow_paths is None:
        return True
    for search_root in search_roots:
        if module_root == "pytest" and _pytest_local_entry_point_metadata_exists(search_root):
            return True
        try:
            if any((search_root / shadow_path).exists() for shadow_path in shadow_paths):
                return True
        except OSError:
            return True
    return False


def _pytest_local_entry_point_metadata_exists(cwd: Path) -> bool:
    try:
        return any(
            child.is_dir()
            and child.name.endswith((".dist-info", ".egg-info"))
            and (child / "entry_points.txt").exists()
            for child in cwd.iterdir()
        )
    except OSError:
        return True


def _single_interpreter_heredoc_interpreter(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    interpreter = match.group("interpreter").strip()
    return interpreter or None


def _single_interpreter_heredoc_args(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    return match.group("args").strip()


__all__ = [
    "_contains_pytest_env_shell_script_wrapper",
    "_looks_like_benign_interpreter_wait",
    "_looks_like_benign_interpreter_wait_chain",
    "_looks_like_read_only_interpreter_command",
    "_looks_like_read_only_interpreter_compound",
    "_looks_like_safe_read_only_lookup_command",
    "_parts_use_python_module_mode",
    "_pytest_local_entry_point_metadata_exists",
    "_python_args_use_module_mode",
    "_python_module_may_be_shadowed",
    "_python_module_may_be_shadowed_in_search_roots",
    "_read_only_lookup_segments",
    "_read_only_lookup_token_is_safe_stderr_discard",
    "_shell_env_assignment_key",
    "_shell_segment_explicit_env_value",
    "_shell_segment_sets_env_key",
    "_single_interpreter_heredoc_args",
    "_single_interpreter_heredoc_interpreter",
]
