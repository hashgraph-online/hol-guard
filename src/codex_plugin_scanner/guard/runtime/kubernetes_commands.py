"""Kubernetes shell-command secret source detection."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .data_flow import extract_command_segments, extract_command_substitutions

_SENSITIVE_ENV_NAME_PATTERN = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|auth|credential|credentials|key|password|private[_-]?key|secret|token)(?:[_-]|$)"
)
_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
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
_SHELL_EXECUTABLES = frozenset({"ash", "bash", "dash", "sh", "zsh"})
_SERVICE_ACCOUNT_PATH_MARKERS = (
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/run/secrets/kubernetes.io/serviceaccount",
)
_SECRET_VOLUME_PATH_MARKERS = (
    "/etc/secrets/",
    "/etc/secret/",
    "/var/run/secrets/",
    "/run/secrets/",
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


def _kubectl_secret_read_source_from_tokens(tokens: tuple[str, ...]) -> str | None:
    index = _unwrap_command_start(tokens)
    if index >= len(tokens) or Path(tokens[index]).name.lower() not in {"kubectl", "oc"}:
        return None
    subcommand_index = _skip_kubectl_options(tokens, index + 1)
    if subcommand_index >= len(tokens):
        return None
    subcommand = tokens[subcommand_index].lower()
    if subcommand in {"get", "describe", "edit"} and _kubectl_resource_is_secret(tokens, subcommand_index + 1):
        return "Kubernetes Secret resource"
    if subcommand == "exec":
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
    resource = tokens[index].lower().split("/", 1)[0]
    return resource in {"secret", "secrets"}


def _kubectl_exec_secret_source(tokens: tuple[str, ...]) -> str | None:
    delimiter_index = _exec_delimiter_index(tokens)
    remote_tokens = tokens[delimiter_index + 1 :] if delimiter_index is not None else ()
    if not remote_tokens:
        return None
    if _remote_command_reads_pod_environment(remote_tokens):
        return "Kubernetes pod environment"
    if _remote_command_reads_secret_volume(remote_tokens):
        return "Kubernetes secret volume"
    return None


def _exec_delimiter_index(tokens: tuple[str, ...]) -> int | None:
    for index, token in enumerate(tokens):
        if token == "--":
            return index
    return None


def _remote_command_reads_pod_environment(tokens: tuple[str, ...], *, depth: int = 0) -> bool:
    if depth > 3:
        return False
    if not tokens:
        return False
    command_name = Path(tokens[0]).name.lower()
    if command_name == "printenv":
        args = _tokens_before_pipe(tokens[1:])
        env_names = tuple(token for token in args if not token.startswith("-"))
        return not env_names or any(_is_sensitive_env_name(name) for name in env_names)
    if command_name == "env":
        args = _tokens_before_pipe(tokens[1:])
        env_names = tuple(token for token in args if not token.startswith("-") and not _ASSIGNMENT_PATTERN.match(token))
        return not env_names
    if command_name in _SHELL_EXECUTABLES:
        script = _shell_c_script(tokens[1:])
        if script is None:
            return False
        for candidate in _command_candidates(script):
            candidate_tokens = _shell_tokens(candidate)
            if _remote_command_reads_pod_environment(candidate_tokens, depth=depth + 1):
                return True
            if _remote_command_reads_secret_volume(candidate_tokens):
                return True
    return False


def _remote_command_reads_secret_volume(tokens: tuple[str, ...]) -> bool:
    joined = " ".join(tokens)
    lowered = joined.lower()
    if any(marker in lowered for marker in _SERVICE_ACCOUNT_PATH_MARKERS):
        return True
    return any(marker in lowered for marker in _SECRET_VOLUME_PATH_MARKERS) and any(
        Path(token).name.lower() in {"cat", "cp", "head", "less", "more", "sed", "tail"}
        for token in tokens
    )


def _kubectl_cp_reads_secret_volume(tokens: tuple[str, ...]) -> bool:
    return any(any(marker in token.lower() for marker in _SECRET_VOLUME_PATH_MARKERS) for token in tokens)


def _tokens_before_pipe(tokens: tuple[str, ...]) -> tuple[str, ...]:
    if "|" not in tokens:
        return tokens
    return tokens[: tokens.index("|")]


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


def _is_sensitive_env_name(name: str) -> bool:
    return _SENSITIVE_ENV_NAME_PATTERN.search(name.strip()) is not None


def _option_tokens_consumed(command_name: str, token: str) -> int:
    options_with_values = _WRAPPER_OPTIONS_WITH_VALUES.get(command_name, frozenset())
    if token in options_with_values:
        return 2
    if any(token.startswith(f"{option}=") for option in options_with_values if option.startswith("--")):
        return 1
    return 1


__all__ = ["kubernetes_secret_read_source"]
