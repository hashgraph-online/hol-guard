"""Kubernetes heredoc command detection helpers."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .data_flow import (
    _split_top_level_pipes,
    extract_command_segments,
    extract_command_substitutions,
    extract_input_redirects,
)
from .kubernetes_command_support import (
    WRITE_ONLY_COMMANDS,
    is_output_redirect_target,
    is_secret_volume_path,
    kubernetes_option_tokens_consumed,
    script_reads_sensitive_env,
    secret_volume_argument_value,
)

_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
_HEREDOC_WRAPPER_COMMANDS = frozenset({"command", "env", "nice", "nohup", "stdbuf", "sudo", "time"})
_HEREDOC_WRAPPER_OPTIONS_WITH_VALUES = {
    "env": frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "--input", "-o", "--output", "-e", "--error"}),
    "sudo": frozenset(
        {
            "-C",
            "-D",
            "-R",
            "-T",
            "-g",
            "-h",
            "-p",
            "-r",
            "-t",
            "-u",
            "--chdir",
            "--chroot",
            "--close-from",
            "--command-timeout",
            "--group",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--user",
        }
    ),
    "time": frozenset({"-f", "--format", "-o", "--output"}),
}
_KUBECTL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--as",
        "--as-group",
        "--as-uid",
        "--cache-dir",
        "--certificate-authority",
        "--chunk-size",
        "--client-certificate",
        "--client-key",
        "--cluster",
        "--context",
        "--field-manager",
        "--field-selector",
        "--filename",
        "--kubeconfig",
        "--label-selector",
        "--namespace",
        "--output",
        "--password",
        "--profile",
        "--profile-output",
        "--request-timeout",
        "--selector",
        "--server",
        "--sort-by",
        "--subresource",
        "--template",
        "--token",
        "--user",
        "--username",
        "-c",
        "-f",
        "-l",
        "-n",
        "-o",
    }
)
_KUBECTL_BOOLEAN_OPTIONS = frozenset({"-A", "--all-namespaces"})
_EXEC_OPTIONS_WITH_VALUES = frozenset(
    {
        "--container",
        "--namespace",
        "--pod-running-timeout",
        "--profile",
        "--profile-output",
        "--request-timeout",
        "--shell",
        "-c",
        "-n",
    }
)
_EXEC_BOOLEAN_OPTIONS = frozenset({"--quiet", "--stdin", "--tty", "-T", "-i", "-q", "-t"})
_EXEC_BOOLEAN_SHORT_CLUSTER = frozenset({"i", "q", "t"})
_OUTPUT_REDIRECT_TOKENS = frozenset({">", "1>", "2>", ">>", "1>>", "2>>"})
_SHELL_EXECUTABLES = frozenset({"ash", "bash", "dash", "ksh", "sh", "zsh"})


def kubernetes_heredoc_secret_source(command: str) -> str | None:
    for before, after, body in _iter_kubernetes_heredocs(command):
        source_kind = _kubernetes_heredoc_remote_kind(before, after)
        if source_kind is None:
            continue
        if source_kind == "interpreter":
            if script_reads_sensitive_env(body):
                return "Kubernetes pod environment"
            continue
        if _script_body_reads_secret_volume(body):
            return "Kubernetes secret volume"
        if script_reads_sensitive_env(body):
            return "Kubernetes pod environment"
    return None


def _env_looks_like_wrapper(tokens: tuple[str, ...]) -> bool:
    index = 0
    saw_wrapper_syntax = False
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return saw_wrapper_syntax and index + 1 < len(tokens)
        if _ASSIGNMENT_PATTERN.match(token):
            saw_wrapper_syntax = True
            index += 1
            continue
        if token.startswith("-"):
            saw_wrapper_syntax = True
            index += _wrapper_option_tokens_consumed("env", token)
            continue
        return saw_wrapper_syntax
    return False


def _interpreter_reads_stdin(args: tuple[str, ...]) -> bool:
    for token in args:
        if token == "--":
            continue
        if token in {"-c", "-e"} or (token.startswith(("-c", "-e")) and len(token) > 2):
            return False
        if token == "-":
            return True
        if token.startswith("-"):
            continue
        return False
    return False


def _is_inline_interpreter_command(command_name: str) -> bool:
    return command_name.startswith("python") or command_name in {"node", "nodejs", "perl", "php", "ruby"}


def _iter_kubernetes_heredocs(command: str) -> tuple[tuple[str, str, str], ...]:
    heredocs: list[tuple[str, str, str]] = []
    command_start = 0
    index = 0
    quote: str | None = None
    in_backtick = False
    subshell_depth = 0
    while index < len(command):
        char = command[index]
        if char == "\\":
            index += 2
            continue
        if char == "`" and quote != "'":
            in_backtick = not in_backtick
            index += 1
            continue
        if in_backtick:
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "'" and quote is None:
            quote = "'"
            index += 1
            continue
        if char == '"':
            if quote == '"':
                quote = None
            elif quote is None:
                quote = '"'
            index += 1
            continue
        if quote != "'" and command.startswith("$(", index):
            subshell_depth += 1
            index += 2
            continue
        if quote is None and char == "(" and subshell_depth > 0:
            subshell_depth += 1
            index += 1
            continue
        if quote is None and char == ")" and subshell_depth > 0:
            subshell_depth -= 1
            index += 1
            continue
        if quote is None and subshell_depth == 0:
            if _starts_command_separator(command, index):
                index += 2
                command_start = _skip_command_whitespace(command, index)
                continue
            if char in {";", "\n"} or _is_background_separator(command, index):
                index += 1
                command_start = _skip_command_whitespace(command, index)
                continue
            if _looks_like_heredoc_operator(command, index):
                parsed = _parse_heredoc(command, index)
                if parsed is not None:
                    tag, after_tag_start, body_start, line_end = parsed
                    body, next_index = _heredoc_body_and_end(command, tag=tag, start=body_start)
                    if body is not None:
                        before = command[command_start:index].strip()
                        after = command[after_tag_start:line_end].strip()
                        heredocs.append((before, after, body))
                        command_start = _skip_command_whitespace(command, next_index)
                        index = command_start
                        continue
        index += 1
    return tuple(heredocs)


def _kubernetes_heredoc_remote_kind(before: str, after: str) -> str | None:
    remote_tokens = _kubernetes_remote_kind_from_command(_last_pipe_segment(before))
    if remote_tokens is not None:
        return remote_tokens
    if not after.lstrip().startswith("|"):
        return None
    for segment in _pipe_segments(after.lstrip()[1:]):
        remote_tokens = _kubernetes_remote_kind_from_command(segment)
        if remote_tokens is not None:
            return remote_tokens
    return None


def _kubernetes_remote_kind_from_command(command: str) -> str | None:
    command_name, kubernetes_tokens = _unwrap_heredoc_remote_command(_shell_tokens(command))
    if command_name not in {"kubectl", "oc"} or not kubernetes_tokens:
        return None
    remote_tokens = _kubernetes_exec_remote_tokens(kubernetes_tokens)
    if not remote_tokens:
        return None
    command_name, args = _unwrap_heredoc_remote_command(remote_tokens)
    if command_name is None:
        return None
    if command_name in _SHELL_EXECUTABLES and _shell_reads_stdin(args):
        return "shell"
    if _is_inline_interpreter_command(command_name) and _interpreter_reads_stdin(args):
        return "interpreter"
    return None


def _kubernetes_exec_remote_tokens(tokens: tuple[str, ...]) -> tuple[str, ...]:
    subcommand_index = _skip_kubectl_options(tokens, 0)
    if subcommand_index >= len(tokens) or tokens[subcommand_index].lower() not in {"exec", "rsh"}:
        return ()
    tokens = tokens[subcommand_index + 1 :]
    resource_seen = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return tokens[index + 1 :]
        option_consumed = kubernetes_option_tokens_consumed(
            tokens,
            index,
            base_value_flags=_KUBECTL_OPTIONS_WITH_VALUES,
            base_boolean_flags=_KUBECTL_BOOLEAN_OPTIONS,
            base_boolean_short_cluster=_EXEC_BOOLEAN_SHORT_CLUSTER,
            value_flags=_EXEC_OPTIONS_WITH_VALUES,
            boolean_flags=_EXEC_BOOLEAN_OPTIONS,
            boolean_short_cluster=_EXEC_BOOLEAN_SHORT_CLUSTER,
        )
        if option_consumed is not None:
            index += option_consumed
            continue
        if not resource_seen:
            resource_seen = True
            index += 1
            continue
        return tokens[index:]
    return ()


def _script_body_reads_secret_volume(body: str) -> bool:
    if any(is_secret_volume_path(target) for target in extract_input_redirects(body)):
        return True
    if any(_script_body_reads_secret_volume(substitution) for substitution in extract_command_substitutions(body)):
        return True
    return any(_segment_reads_secret_volume(_shell_tokens(segment)) for segment in extract_command_segments(body))


def _segment_reads_secret_volume(tokens: tuple[str, ...]) -> bool:
    if not tokens:
        return False
    command_name = Path(tokens[0]).name.lower()
    if command_name in _SHELL_EXECUTABLES:
        script = _shell_c_script(tokens[1:])
        return bool(script) and _script_body_reads_secret_volume(script)
    if command_name in WRITE_ONLY_COMMANDS:
        return False
    previous_token: str | None = None
    for token in tokens[1:]:
        if token in _OUTPUT_REDIRECT_TOKENS:
            previous_token = token
            continue
        normalized = secret_volume_argument_value(token)
        if token.startswith("-") and "=" not in token:
            previous_token = token
            continue
        if not is_secret_volume_path(normalized):
            previous_token = token
            continue
        if is_output_redirect_target(token, previous_token=previous_token):
            previous_token = token
            continue
        return True
    return False


def _shell_c_script(tokens: tuple[str, ...]) -> str | None:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-c" and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith("-") and "c" in token[1:] and index + 1 < len(tokens):
            return tokens[index + 1]
        index += 1
    return None


def _shell_reads_stdin(args: tuple[str, ...]) -> bool:
    for token in args:
        if token == "--":
            continue
        if token == "-s":
            return True
        if token == "-c" or (token.startswith("-") and "c" in token[1:]):
            return False
        if token.startswith("-"):
            continue
        return token == "-"
    return True


def _shell_tokens(command: str) -> tuple[str, ...]:
    try:
        return tuple(shlex.split(command))
    except ValueError:
        return tuple(command.split())


def _unwrap_heredoc_remote_command(tokens: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _ASSIGNMENT_PATTERN.match(token):
            index += 1
            continue
        command_name = Path(token).name.lower()
        if command_name not in _HEREDOC_WRAPPER_COMMANDS:
            return command_name, tokens[index + 1 :]
        if command_name == "env" and not _env_looks_like_wrapper(tokens[index + 1 :]):
            return command_name, tokens[index + 1 :]
        index += 1
        while index < len(tokens):
            current = tokens[index]
            if current == "--":
                index += 1
                break
            if _ASSIGNMENT_PATTERN.match(current):
                index += 1
                continue
            if not current.startswith("-"):
                break
            index += _wrapper_option_tokens_consumed(command_name, current)
    return None, ()


def _last_pipe_segment(command: str) -> str:
    segments = _pipe_segments(command)
    return segments[-1] if segments else command.strip()


def _pipe_segments(command: str) -> tuple[str, ...]:
    stripped = command.strip()
    if not stripped:
        return ()
    segments = tuple(segment.strip() for segment in _split_top_level_pipes(stripped) if segment.strip())
    return segments or (stripped,)


def _heredoc_body_and_end(command: str, *, tag: str, start: int) -> tuple[str | None, int]:
    terminator = re.compile(rf"(?m)^[\t ]*{re.escape(tag)}[\t ]*(?:\r?\n|$)")
    end_match = terminator.search(command, start)
    if end_match is None:
        return None, start
    return command[start : end_match.start()], end_match.end()


def _is_background_separator(command: str, index: int) -> bool:
    previous_char = command[index - 1] if index > 0 else ""
    next_char = command[index + 1] if index + 1 < len(command) else ""
    return command[index] == "&" and previous_char not in {">", "<", "|"} and next_char not in {"&", ">"}


def _looks_like_heredoc_operator(command: str, index: int) -> bool:
    return command.startswith("<<", index) and not command.startswith("<<<", index)


def _parse_heredoc(command: str, index: int) -> tuple[str, int, int, int] | None:
    cursor = index + 2
    if cursor < len(command) and command[cursor] == "-":
        cursor += 1
    while cursor < len(command) and command[cursor] in {" ", "\t"}:
        cursor += 1
    if cursor >= len(command):
        return None
    quote = command[cursor] if command[cursor] in {"'", '"'} else None
    if quote is not None:
        cursor += 1
    tag_start = cursor
    while cursor < len(command):
        current = command[cursor]
        if quote is not None:
            if current == quote:
                break
        elif current.isspace() or current in "'\"`;&|<>":
            break
        cursor += 1
    if cursor == tag_start:
        return None
    tag = command[tag_start:cursor]
    if quote is not None:
        if cursor >= len(command) or command[cursor] != quote:
            return None
        cursor += 1
    newline_index = command.find("\n", cursor)
    if newline_index == -1:
        return None
    line_end = newline_index - 1 if newline_index > cursor and command[newline_index - 1] == "\r" else newline_index
    return tag, cursor, newline_index + 1, line_end


def _skip_kubectl_options(tokens: tuple[str, ...], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if not token.startswith("-"):
            return index
        option_consumed = kubernetes_option_tokens_consumed(
            tokens,
            index,
            base_value_flags=_KUBECTL_OPTIONS_WITH_VALUES,
            base_boolean_flags=_KUBECTL_BOOLEAN_OPTIONS,
            base_boolean_short_cluster=_EXEC_BOOLEAN_SHORT_CLUSTER,
        )
        index += option_consumed if option_consumed is not None else 1
    return index


def _skip_command_whitespace(command: str, index: int) -> int:
    while index < len(command) and command[index].isspace():
        index += 1
    return index


def _starts_command_separator(command: str, index: int) -> bool:
    return command.startswith("&&", index) or command.startswith("||", index)


def _wrapper_option_tokens_consumed(command_name: str, token: str) -> int:
    options_with_values = _HEREDOC_WRAPPER_OPTIONS_WITH_VALUES.get(command_name, frozenset())
    if token in options_with_values:
        return 2
    if any(token.startswith(f"{option}=") for option in options_with_values if option.startswith("--")):
        return 1
    return 1


__all__ = ["kubernetes_heredoc_secret_source"]
