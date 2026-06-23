"""Kubernetes shell-command secret source detection."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .data_flow import extract_command_segments, extract_command_substitutions, extract_input_redirects
from .kubernetes_command_support import (
    interpreter_reads_sensitive_env,
    is_output_redirect_target,
    is_secret_volume_path,
    is_sensitive_env_name,
    raw_secret_api_path,
    resource_token_includes_secret,
    script_reads_sensitive_env,
    strip_redirect_prefix,
)

_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
_OUTPUT_REDIRECT_TOKENS = frozenset({">", "1>", "2>", ">>", "1>>", "2>>"})
_WRAPPER_COMMANDS = frozenset({"command", "env", "nice", "nohup", "stdbuf", "sudo", "time"})
_WRAPPER_OPTIONS_WITH_VALUES = {
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
        "--cache-dir",
        "--certificate-authority",
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
_KUBECTL_VALUE_PREFIXES = tuple(f"{flag}=" for flag in _KUBECTL_OPTIONS_WITH_VALUES if flag.startswith("--"))
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
_CP_OPTIONS_WITH_VALUES = frozenset({"--container", "--namespace", "--retries", "-c", "-n"})
_CP_BOOLEAN_OPTIONS = frozenset({"--no-preserve"})
_REMOTE_CP_OPTIONS_WITH_VALUES = frozenset({"--target-directory", "-t"})
_SHELL_EXECUTABLES = frozenset({"ash", "bash", "dash", "ksh", "sh", "zsh"})
_WRITE_ONLY_REMOTE_COMMANDS = frozenset(
    {"chmod", "chown", "echo", "install", "mkdir", "printf", "rm", "rmdir", "tee", "touch", "truncate"}
)
_INTERPRETER_HEREDOC_PATTERN = re.compile(
    r"(?is)\b(?:kubectl|oc)\b.*?\b(?:exec|rsh)\b.*?"
    r"\b(?:python(?:\d+(?:\.\d+)*)?|node|perl|php|ruby)\b[^\n]*?\s-\s*<<-?\s*(['\"]?)(?P<tag>[^\s'\"`;&|<>]+)\1\s*\n"
    r"(?P<body>.*?)\n(?P=tag)(?=$|\s)"
)


def kubernetes_secret_read_source(command: str | None) -> str | None:
    if not isinstance(command, str) or not command.strip():
        return None
    for candidate in _command_candidates(command):
        source = _kubernetes_secret_read_source_for_candidate(candidate)
        if source is not None:
            return source
    return None


def _command_candidates(command: str, *, depth: int = 0) -> tuple[str, ...]:
    if depth > 3:
        return (command,)
    candidates: list[str] = [command]
    for substitution in extract_command_substitutions(command):
        candidates.extend(_command_candidates(substitution, depth=depth + 1))
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate.strip()))


def _kubernetes_secret_read_source_for_candidate(command: str) -> str | None:
    if (source := _interpreter_heredoc_secret_source(command)) is not None:
        return source
    for segment in extract_command_segments(command):
        tokens = _shell_tokens(segment)
        if not tokens:
            continue
        source = _kubectl_secret_read_source_from_tokens(tokens)
        if source is not None:
            return source
    return None


def _shell_tokens(command: str) -> tuple[str, ...]:
    try:
        return tuple(shlex.split(command))
    except ValueError:
        return tuple(command.split())


def _interpreter_heredoc_secret_source(command: str) -> str | None:
    match = _INTERPRETER_HEREDOC_PATTERN.search(command)
    if match is None:
        return None
    body = str(match.group("body") or "")
    return "Kubernetes pod environment" if script_reads_sensitive_env(body) else None


def _kubectl_secret_read_source_from_tokens(tokens: tuple[str, ...]) -> str | None:
    index = _unwrap_command_start(tokens)
    if index >= len(tokens) or Path(tokens[index]).name.lower() not in {"kubectl", "oc"}:
        return None
    subcommand_index = _skip_kubectl_options(tokens, index + 1)
    if subcommand_index >= len(tokens):
        return None
    subcommand = tokens[subcommand_index].lower()
    if subcommand == "get" and _kubectl_get_raw_secret_path(tokens, subcommand_index + 1):
        return "Kubernetes Secret resource"
    if subcommand in {"get", "describe", "edit"} and _kubectl_resource_is_secret(tokens, subcommand_index + 1):
        return "Kubernetes Secret resource"
    if subcommand in {"exec", "rsh"}:
        return _kubectl_exec_secret_source(tokens[subcommand_index + 1 :])
    if subcommand == "cp" and _kubectl_cp_reads_secret_volume(tokens[subcommand_index + 1 :]):
        return "Kubernetes secret volume"
    return None


def _unwrap_command_start(tokens: tuple[str, ...]) -> int:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _ASSIGNMENT_PATTERN.match(token):
            index += 1
            continue
        command_name = Path(token).name.lower()
        if command_name not in _WRAPPER_COMMANDS:
            return index
        if command_name == "env" and not _env_looks_like_wrapper(tokens[index + 1 :]):
            return index
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
            index += _option_tokens_consumed(command_name, current)
    return index


def _skip_kubectl_options(tokens: tuple[str, ...], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if not token.startswith("-"):
            return index
        if token in _KUBECTL_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if token.startswith(_KUBECTL_VALUE_PREFIXES):
            index += 1
            continue
        if token.startswith(("-n", "-o", "-l")) and len(token) > 2:
            index += 1
            continue
        index += 1
    return index


def _kubectl_resource_is_secret(tokens: tuple[str, ...], index: int) -> bool:
    index = _skip_kubectl_options(tokens, index)
    if index >= len(tokens):
        return False
    return resource_token_includes_secret(tokens[index])


def _kubectl_get_raw_secret_path(tokens: tuple[str, ...], index: int) -> bool:
    while index < len(tokens):
        token = tokens[index]
        if token == "--raw" and index + 1 < len(tokens):
            return raw_secret_api_path(tokens[index + 1])
        if token.startswith("--raw="):
            return raw_secret_api_path(token.split("=", 1)[1])
        index += 1
    return False


def _kubectl_exec_secret_source(tokens: tuple[str, ...]) -> str | None:
    remote_tokens = _kubectl_exec_remote_tokens(tokens)
    if not remote_tokens:
        return None
    if _remote_command_reads_secret_volume(remote_tokens):
        return "Kubernetes secret volume"
    if _remote_command_reads_pod_environment(remote_tokens):
        return "Kubernetes pod environment"
    return None


def _kubectl_exec_remote_tokens(tokens: tuple[str, ...]) -> tuple[str, ...]:
    resource_seen = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return tokens[index + 1 :]
        option_consumed = _exec_option_tokens_consumed(tokens, index)
        if option_consumed is not None:
            index += option_consumed
            continue
        if not resource_seen:
            resource_seen = True
            index += 1
            continue
        return tokens[index:]
    return ()


def _exec_option_tokens_consumed(tokens: tuple[str, ...], index: int) -> int | None:
    token = tokens[index]
    if token in _EXEC_OPTIONS_WITH_VALUES and index + 1 < len(tokens):
        return 2
    if any(token.startswith(f"{flag}=") for flag in _EXEC_OPTIONS_WITH_VALUES if flag.startswith("--")):
        return 1
    if token in _EXEC_BOOLEAN_OPTIONS:
        return 1
    if token.startswith(("-c", "-n")) and len(token) > 2:
        return 1
    if token.startswith("-") and not token.startswith("--") and set(token[1:]).issubset(_EXEC_BOOLEAN_SHORT_CLUSTER):
        return 1
    return None


def _remote_command_reads_pod_environment(tokens: tuple[str, ...], *, depth: int = 0) -> bool:
    if depth > 3 or not tokens:
        return False
    unwrapped_index = _unwrap_command_start(tokens)
    if 0 < unwrapped_index < len(tokens):
        return _remote_command_reads_pod_environment(tokens[unwrapped_index:], depth=depth + 1)
    command_name = Path(tokens[0]).name.lower()
    if command_name == "printenv":
        env_names = tuple(token for token in _tokens_before_pipe(tokens[1:]) if not token.startswith("-"))
        return not env_names or any(is_sensitive_env_name(name) for name in env_names)
    if command_name == "env":
        env_names = tuple(
            token
            for token in _tokens_before_pipe(tokens[1:])
            if not token.startswith("-") and not _ASSIGNMENT_PATTERN.match(token)
        )
        return not env_names
    if command_name in _SHELL_EXECUTABLES:
        script = _shell_c_script(tokens[1:])
        if script is None:
            return False
        if script_reads_sensitive_env(script):
            return True
        for candidate in _command_candidates(script):
            candidate_tokens = _shell_tokens(candidate)
            if _remote_command_reads_pod_environment(candidate_tokens, depth=depth + 1):
                return True
        return False
    return interpreter_reads_sensitive_env(command_name, tokens[1:])


def _remote_command_reads_secret_volume(tokens: tuple[str, ...], *, depth: int = 0) -> bool:
    if depth > 3 or not tokens:
        return False
    unwrapped_index = _unwrap_command_start(tokens)
    if 0 < unwrapped_index < len(tokens):
        return _remote_command_reads_secret_volume(tokens[unwrapped_index:], depth=depth + 1)
    command_name = Path(tokens[0]).name.lower()
    if command_name in _SHELL_EXECUTABLES:
        script = _shell_c_script(tokens[1:])
        if script is None:
            return False
        for candidate in _command_candidates(script):
            if _remote_command_reads_secret_volume(_shell_tokens(candidate), depth=depth + 1):
                return True
        return False
    if _command_input_redirects_secret_volume(" ".join(tokens)):
        return True
    if command_name == "cp":
        return _remote_copy_source_reads_secret_volume(tokens[1:])
    source_arguments = _secret_volume_source_arguments(tokens)
    if not source_arguments:
        return False
    return command_name not in _WRITE_ONLY_REMOTE_COMMANDS


def _kubectl_cp_reads_secret_volume(tokens: tuple[str, ...]) -> bool:
    operands = _kubectl_cp_operands(tokens)
    if len(operands) < 2:
        return False
    remote_source = _remote_cp_path(operands[0])
    return remote_source is not None and is_secret_volume_path(remote_source)


def _kubectl_cp_operands(tokens: tuple[str, ...]) -> tuple[str, ...]:
    operands: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in _CP_OPTIONS_WITH_VALUES and index + 1 < len(tokens):
            index += 2
            continue
        if any(token.startswith(f"{flag}=") for flag in _CP_OPTIONS_WITH_VALUES if flag.startswith("--")):
            index += 1
            continue
        if token in _CP_BOOLEAN_OPTIONS:
            index += 1
            continue
        if token.startswith(("-c", "-n")) and len(token) > 2:
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        operands.append(token)
        index += 1
    return tuple(operands)


def _remote_copy_source_reads_secret_volume(tokens: tuple[str, ...]) -> bool:
    source_operands = _remote_cp_operands(tokens)
    if not source_operands:
        return False
    return any(
        is_secret_volume_path(operand) and not is_output_redirect_target(operand, previous_token=None)
        for operand in source_operands
    )


def _secret_volume_source_arguments(tokens: tuple[str, ...]) -> tuple[str, ...]:
    sources: list[str] = []
    previous_token: str | None = None
    for token in tokens[1:]:
        if token in _OUTPUT_REDIRECT_TOKENS:
            previous_token = token
            continue
        if token.startswith("-"):
            previous_token = token
            continue
        normalized_token = strip_redirect_prefix(token)
        if not is_secret_volume_path(normalized_token):
            previous_token = token
            continue
        if is_output_redirect_target(token, previous_token=previous_token):
            previous_token = token
            continue
        sources.append(normalized_token)
        previous_token = token
    return tuple(dict.fromkeys(sources))


def _tokens_before_pipe(tokens: tuple[str, ...]) -> tuple[str, ...]:
    if "|" not in tokens:
        return tokens
    return tokens[: tokens.index("|")]


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
            index += _option_tokens_consumed("env", token)
            continue
        return saw_wrapper_syntax
    return False


def _remote_cp_operands(tokens: tuple[str, ...]) -> tuple[str, ...]:
    operands: list[str] = []
    has_target_directory = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in _REMOTE_CP_OPTIONS_WITH_VALUES and index + 1 < len(tokens):
            has_target_directory = has_target_directory or token in {"--target-directory", "-t"}
            index += 2
            continue
        if any(token.startswith(f"{flag}=") for flag in _REMOTE_CP_OPTIONS_WITH_VALUES if flag.startswith("--")):
            has_target_directory = has_target_directory or token.startswith("--target-directory=")
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        operands.append(token)
        index += 1
    if has_target_directory:
        return tuple(operands)
    return tuple(operands[:-1]) if len(operands) >= 2 else ()


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


def _command_input_redirects_secret_volume(command_text: str) -> bool:
    return any(is_secret_volume_path(target) for target in extract_input_redirects(command_text))


def _remote_cp_path(value: str) -> str | None:
    if "://" in value:
        return None
    prefix, separator, path = value.partition(":")
    if not separator or not prefix or not path:
        return None
    return path


def _option_tokens_consumed(command_name: str, token: str) -> int:
    options_with_values = _WRAPPER_OPTIONS_WITH_VALUES.get(command_name, frozenset())
    if token in options_with_values:
        return 2
    if any(token.startswith(f"{option}=") for option in options_with_values if option.startswith("--")):
        return 1
    return 1


__all__ = ["kubernetes_secret_read_source"]
