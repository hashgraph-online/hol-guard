"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .commands_support_codex_commands import (
        _CODEX_READ_ONLY_PIPE_FILTERS,
        _CODEX_READ_ONLY_SEARCH_COMMANDS,
        _CODEX_READ_ONLY_SEARCH_WRAPPERS,
        _CODEX_READ_ONLY_VIEW_COMMANDS,
        _codex_unwrapped_command_parts,
    )
    from .commands_support_codex_git import (
        _codex_count_arg_is_bounded,
        _codex_git_diff_targets_are_source_like,
        _git_grep_search_args,
        _parse_codex_sed_read_only_args,
    )
    from .commands_support_codex_paths import (
        _codex_command_has_unquoted_shell_control,
        _codex_fd_exec_is_bounded_read_only,
        _codex_fd_targets,
        _codex_fd_targets_are_source_like,
        _codex_search_target_is_external_source_like,
        _codex_search_target_is_source_like,
        _codex_search_targets,
        _codex_search_targets_are_source_like,
        _git_grep_uses_external_execution,
        _shell_wrapper_script_index,
    )


from ..runtime.shell_execution_context import (
    ShellExecutionContext,
    model_shell_execution_context,
    validate_shell_execution_segment,
)
from ._commands_shared import *
from .commands_parser_helpers import *


def _codex_source_inspection_target_tokens(parts: list[str]) -> tuple[str, ...]:
    command_parts = _codex_unwrapped_command_parts(parts)
    if not command_parts:
        return ()
    executable = Path(command_parts[0]).name
    args = command_parts[1:]
    if executable in _CODEX_READ_ONLY_VIEW_COMMANDS:
        if executable == "sed":
            parsed = _parse_codex_sed_read_only_args(args)
            return parsed.targets if parsed is not None else ()
        if executable in {"head", "tail"}:
            targets, valid, skip_next = _parse_codex_head_tail_args(args)
            return tuple(targets) if valid and not skip_next else ()
        return tuple(_codex_cat_targets(args))
    if executable in _CODEX_READ_ONLY_SEARCH_COMMANDS:
        if executable == "fd":
            return _codex_fd_targets(args)
        return _codex_search_targets(args, executable=executable)
    if executable == "git":
        git_grep_args = _git_grep_search_args(args)
        if git_grep_args is not None:
            return _codex_search_targets(git_grep_args, executable=executable)
    script_index = (
        _shell_wrapper_script_index(command_parts) if executable in _CODEX_READ_ONLY_SEARCH_WRAPPERS else None
    )
    if script_index is not None and script_index < len(command_parts):
        try:
            nested_parts = shlex.split(command_parts[script_index])
        except ValueError:
            return ()
        return _codex_source_inspection_target_tokens(nested_parts)
    return ()


def _codex_command_has_external_source_search_target(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    chained_segments = _split_codex_safe_read_only_chain(command_text)
    if chained_segments is not None:
        return any(
            _codex_command_has_external_source_search_target(segment, cwd=cwd, home_dir=home_dir)
            for segment in chained_segments
        )
    pipeline_segments = _split_codex_safe_read_only_pipeline(command_text)
    if pipeline_segments:
        return any(
            _codex_command_has_external_source_search_target(segment, cwd=cwd, home_dir=home_dir)
            for segment in pipeline_segments
        )
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    return any(
        _codex_search_target_is_external_source_like(target, cwd=cwd, home_dir=home_dir)
        for target in _codex_source_inspection_target_tokens(parts)
    )


def _codex_cat_targets(args: list[str]) -> list[str]:
    targets: list[str] = []
    after_option_terminator = False
    for arg in args:
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg == "-" or arg.startswith("-"):
            continue
        targets.append(arg)
    return targets


def _codex_command_is_read_only_source_inspection(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    command = command_text.strip()
    if not command:
        return False
    if _codex_command_has_unquoted_glob_metachar(command):
        return False
    if _codex_command_has_external_source_search_target(command, cwd=cwd, home_dir=home_dir):
        try:
            parts = shlex.split(command)
        except ValueError:
            return False
        if not parts or parts[0] != "grep":
            return False
        # External targets are allowed only for one direct plain grep command.
        return _codex_command_is_read_only_source_search(command, cwd=cwd, home_dir=home_dir)
    execution_context = model_shell_execution_context(command, cwd=cwd, workspace_root=cwd)
    if execution_context.directory_change_present:
        return _codex_contextual_source_inspection_is_read_only(
            execution_context,
            home_dir=home_dir,
        )
    chained_segments = _split_codex_safe_read_only_chain(command)
    if chained_segments is not None:
        saw_source_inspection = False
        for segment in chained_segments:
            if not _codex_command_is_read_only_source_inspection(segment, cwd=cwd, home_dir=home_dir):
                return False
            saw_source_inspection = True
        return saw_source_inspection
    segments = _split_codex_safe_read_only_pipeline(command)
    if segments is None:
        return _codex_command_is_read_only_source_search(
            command,
            cwd=cwd,
            home_dir=home_dir,
        ) or _codex_command_is_read_only_source_view(command, cwd=cwd, home_dir=home_dir)
    if not segments:
        return False
    first_segment, *filter_segments = segments
    if not (
        _codex_command_is_read_only_source_search(first_segment, cwd=cwd, home_dir=home_dir)
        or _codex_command_is_read_only_source_view(first_segment, cwd=cwd, home_dir=home_dir)
    ):
        return False
    return all(_codex_command_is_bounded_read_only_filter(segment) for segment in filter_segments)


def _codex_contextual_source_inspection_is_read_only(
    context: ShellExecutionContext,
    *,
    home_dir: Path | None,
) -> bool:
    if not context.complete:
        return False
    saw_source_inspection = False
    pipeline_open = False
    for segment in context.segments:
        controls = (*segment.control_before, *segment.control_after)
        if any(operator in {"||", "&"} for operator in controls):
            return False
        if segment.directory_operation is not None:
            pipeline_open = False
            continue
        segment_cwd, reason = validate_shell_execution_segment(context, segment)
        if segment_cwd is None or reason is not None:
            return False
        if pipeline_open:
            if not _codex_command_is_bounded_read_only_filter(segment.command_text):
                return False
        elif not (
            _codex_command_is_read_only_source_search(
                segment.command_text,
                cwd=segment_cwd,
                home_dir=home_dir,
            )
            or _codex_command_is_read_only_source_view(
                segment.command_text,
                cwd=segment_cwd,
                home_dir=home_dir,
            )
        ):
            return False
        saw_source_inspection = True
        pipeline_open = segment.control_operator in {"|", "|&"}
    return saw_source_inspection and not pipeline_open


def _split_codex_safe_read_only_chain(command: str) -> list[str] | None:
    segments: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    found_chain = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if command.startswith("&&", index):
            segment = command[start:index].strip()
            if not segment:
                return None
            segments.append(segment)
            found_chain = True
            index += 2
            start = index
            continue
        if command.startswith("||", index) or char in {";", "&"}:
            return None
        index += 1
    if quote is not None or escaped or not found_chain:
        return None
    segment = command[start:].strip()
    if not segment:
        return None
    segments.append(segment)
    return segments if len(segments) > 1 else None


def _codex_command_has_unquoted_glob_metachar(command: str) -> bool:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if command.startswith("{}", index):
            index += 2
            continue
        if char in {"*", "?", "[", "]", "{", "}"}:
            return True
        index += 1
    return False


def _split_codex_safe_read_only_pipeline(command: str) -> list[str] | None:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            elif quote == '"' and (char == "`" or char == "$"):
                return None
            continue
        if char in {"'", '"'}:
            current.append(char)
            quote = char
            continue
        if char in {"\n", "\r", "&", ";", "<", "`"}:
            return None
        if char == "$":
            return None
        if char == "|":
            segment = "".join(current).strip()
            if not segment:
                return None
            stripped_segment = _strip_codex_safe_stderr_discard(segment)
            if stripped_segment is None:
                return None
            segments.append(stripped_segment)
            current = []
            continue
        current.append(char)
    segment = "".join(current).strip()
    if not segments:
        return None
    if not segment:
        return None
    stripped_segment = _strip_codex_safe_stderr_discard(segment)
    if stripped_segment is None:
        return None
    segments.append(stripped_segment)
    return segments


def _strip_codex_safe_stderr_discard(segment: str) -> str | None:
    cleaned_segment = _remove_codex_safe_stderr_discard(segment)
    if cleaned_segment is None:
        return None
    try:
        parts = shlex.split(cleaned_segment)
    except ValueError:
        return None
    if not parts:
        return None
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return None
    return shlex.join(parts)


def _remove_codex_safe_stderr_discard(segment: str) -> str | None:
    cleaned: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(segment):
        char = segment[index]
        if escaped:
            cleaned.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\":
            cleaned.append(char)
            escaped = True
            index += 1
            continue
        if quote is not None:
            cleaned.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            cleaned.append(char)
            quote = char
            index += 1
            continue
        if segment.startswith("2>", index):
            after_redirect = index + 2
            while after_redirect < len(segment) and segment[after_redirect].isspace():
                after_redirect += 1
            if segment.startswith("/dev/null", after_redirect):
                after_target = after_redirect + len("/dev/null")
                if after_target == len(segment) or segment[after_target].isspace():
                    index = after_target
                    continue
            return None
        if char == ">":
            return None
        cleaned.append(char)
        index += 1
    return "".join(cleaned).strip()


def _codex_command_is_bounded_read_only_filter(command_text: str) -> bool:
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    if not parts:
        return False
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return False
    executable = Path(parts[0]).name
    if executable not in _CODEX_READ_ONLY_PIPE_FILTERS:
        return False
    if executable == "sed":
        return _codex_sed_args_are_bounded_filter(parts[1:])
    return _codex_head_tail_args_are_bounded_filter(parts[1:])


def _codex_command_is_read_only_source_view(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    command = command_text.strip()
    if not command:
        return False
    if _codex_command_has_unquoted_shell_control(command):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return False
    executable = Path(parts[0]).name
    if executable not in _CODEX_READ_ONLY_VIEW_COMMANDS:
        return executable == "git" and _codex_git_diff_targets_are_source_like(parts[1:], cwd=cwd, home_dir=home_dir)
    if executable == "sed":
        return _codex_sed_targets_are_read_only_source_like(parts[1:], cwd=cwd, home_dir=home_dir)
    if executable in {"head", "tail"}:
        return _codex_head_tail_targets_are_source_like(parts[1:], cwd=cwd, home_dir=home_dir)
    return _codex_cat_targets_are_source_like(parts[1:], cwd=cwd, home_dir=home_dir)


def _codex_command_is_read_only_source_search(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    command = command_text.strip()
    if not command:
        return False
    if _codex_command_has_unquoted_shell_control(command):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    if _codex_command_uses_untrusted_search_binary(parts[0]):
        return False
    executable = Path(parts[0]).name
    if executable in _CODEX_READ_ONLY_SEARCH_COMMANDS:
        if executable == "fd":
            return _codex_fd_targets_are_source_like(
                parts[1:],
                cwd=cwd,
                home_dir=home_dir,
            ) and _codex_fd_exec_is_bounded_read_only(parts[1:])
        if executable == "rg" and "--no-config" not in parts and os.environ.get("RIPGREP_CONFIG_PATH"):
            return False
        return _codex_search_targets_are_source_like(parts[1:], cwd=cwd, home_dir=home_dir, executable=executable)
    git_grep_args = _git_grep_search_args(parts[1:]) if executable == "git" else None
    if git_grep_args is not None:
        if _git_grep_uses_external_execution(git_grep_args):
            return False
        return _codex_search_targets_are_source_like(git_grep_args, cwd=cwd, home_dir=home_dir, executable=executable)
    script_index = _shell_wrapper_script_index(parts) if executable in _CODEX_READ_ONLY_SEARCH_WRAPPERS else None
    if script_index is not None and script_index < len(parts):
        return _codex_command_is_read_only_source_search(parts[script_index], cwd=cwd, home_dir=home_dir)
    return False


def _codex_command_uses_untrusted_search_binary(executable_token: str) -> bool:
    return executable_token.startswith(".") or "/" in executable_token or "\\" in executable_token


def _codex_cat_targets_are_source_like(args: list[str], *, cwd: Path | None, home_dir: Path | None) -> bool:
    targets: list[str] = []
    after_option_terminator = False
    for arg in args:
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg == "-":
            return False
        if arg.startswith("-"):
            continue
        targets.append(arg)
    return bool(targets) and all(
        _codex_search_target_is_source_like(target, cwd=cwd, home_dir=home_dir) for target in targets
    )


def _codex_head_tail_args_are_bounded_filter(args: list[str]) -> bool:
    targets, valid, skip_next = _parse_codex_head_tail_args(args)
    return valid and not skip_next and not targets


def _codex_head_tail_targets_are_source_like(args: list[str], *, cwd: Path | None, home_dir: Path | None) -> bool:
    targets, valid, skip_next = _parse_codex_head_tail_args(args)
    return (
        valid
        and not skip_next
        and bool(targets)
        and all(_codex_search_target_is_source_like(target, cwd=cwd, home_dir=home_dir) for target in targets)
    )


def _parse_codex_head_tail_args(args: list[str]) -> tuple[list[str], bool, bool]:
    targets: list[str] = []
    skip_next = False
    after_option_terminator = False
    for arg in args:
        if skip_next:
            skip_next = False
            if not _codex_count_arg_is_bounded(arg):
                return [], False, False
            continue
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            skip_next = True
            continue
        if arg.startswith("--lines=") or arg.startswith("--bytes="):
            _, value = arg.split("=", 1)
            if not _codex_count_arg_is_bounded(value):
                return [], False, False
            continue
        if re.fullmatch(r"-\d{1,6}", arg):
            continue
        if arg == "-":
            return [], False, False
        if arg.startswith("-"):
            return [], False, False
        targets.append(arg)
    return targets, True, skip_next


def _codex_sed_targets_are_read_only_source_like(args: list[str], *, cwd: Path | None, home_dir: Path | None) -> bool:
    parsed = _parse_codex_sed_read_only_args(args)
    if parsed is None:
        return False
    return (
        bool(parsed.targets)
        and parsed.saw_print_suppression
        and all(sed_script_is_bounded_print(script) for script in parsed.scripts)
        and all(_codex_search_target_is_source_like(target, cwd=cwd, home_dir=home_dir) for target in parsed.targets)
    )


def _codex_sed_args_are_bounded_filter(args: list[str]) -> bool:
    parsed = _parse_codex_sed_read_only_args(args)
    if parsed is None:
        return False
    return (
        not parsed.targets
        and parsed.saw_print_suppression
        and all(sed_script_is_bounded_print(script) for script in parsed.scripts)
    )


__all__ = [
    "_codex_cat_targets",
    "_codex_cat_targets_are_source_like",
    "_codex_command_has_external_source_search_target",
    "_codex_command_has_unquoted_glob_metachar",
    "_codex_command_is_bounded_read_only_filter",
    "_codex_command_is_read_only_source_inspection",
    "_codex_command_is_read_only_source_search",
    "_codex_command_is_read_only_source_view",
    "_codex_command_uses_untrusted_search_binary",
    "_codex_head_tail_args_are_bounded_filter",
    "_codex_head_tail_targets_are_source_like",
    "_codex_sed_args_are_bounded_filter",
    "_codex_sed_targets_are_read_only_source_like",
    "_codex_source_inspection_target_tokens",
    "_parse_codex_head_tail_args",
    "_remove_codex_safe_stderr_discard",
    "_split_codex_safe_read_only_chain",
    "_split_codex_safe_read_only_pipeline",
    "_strip_codex_safe_stderr_discard",
]
