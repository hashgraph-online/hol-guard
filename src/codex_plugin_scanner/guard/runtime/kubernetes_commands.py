"""Kubernetes shell-command secret source detection."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .data_flow import extract_command_segments, extract_command_substitutions, extract_input_redirects

_SENSITIVE_ENV_NAME_PATTERN = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|auth|credential|credentials|key|password|private[_-]?key|secret|token)(?:[_-]|$)"
)
_ENV_EXPANSION_PATTERN = re.compile(
    r"(?<!\\)\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)[^}]*\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_INTERPRETER_ENV_LOOKUP_PATTERNS = (
    re.compile(r"os\.environ\s*\[\s*['\"](?P<name>[^'\"]+)['\"]\s*\]", re.IGNORECASE),
    re.compile(r"os\.getenv\(\s*['\"](?P<name>[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"process\.env(?:\.\s*(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])"),
    re.compile(r"ENV\[\s*['\"](?P<name>[^'\"]+)['\"]\s*\]"),
    re.compile(r"System\.getenv\(\s*['\"](?P<name>[^'\"]+)['\"]\s*\)", re.IGNORECASE),
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
_SHELL_EXECUTABLES = frozenset({"ash", "bash", "dash", "ksh", "sh", "zsh"})
_WRITE_ONLY_REMOTE_COMMANDS = frozenset(
    {"chmod", "chown", "echo", "install", "mkdir", "printf", "rm", "rmdir", "tee", "touch", "truncate"}
)
_SERVICE_ACCOUNT_PATH_MARKERS = (
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/run/secrets/kubernetes.io/serviceaccount",
)
_SECRET_VOLUME_PATH_MARKERS = (
    "/etc/secrets",
    "/etc/secret",
    "/var/run/secrets",
    "/run/secrets",
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
    return _resource_token_includes_secret(tokens[index])


def _kubectl_get_raw_secret_path(tokens: tuple[str, ...], index: int) -> bool:
    while index < len(tokens):
        token = tokens[index]
        if token == "--raw" and index + 1 < len(tokens):
            return _raw_secret_api_path(tokens[index + 1])
        if token.startswith("--raw="):
            return _raw_secret_api_path(token.split("=", 1)[1])
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
        return not env_names or any(_is_sensitive_env_name(name) for name in env_names)
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
        if _script_reads_sensitive_env(script):
            return True
        for candidate in _command_candidates(script):
            candidate_tokens = _shell_tokens(candidate)
            if _remote_command_reads_pod_environment(candidate_tokens, depth=depth + 1):
                return True
        return False
    return _interpreter_reads_sensitive_env(command_name, tokens[1:])


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
    return remote_source is not None and _is_secret_volume_path(remote_source)


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
    operands = tuple(token for token in tokens if token and not token.startswith("-"))
    if len(operands) < 2:
        return False
    return _is_secret_volume_path(operands[0]) and not _is_output_redirect_target(operands[0], previous_token=None)


def _secret_volume_source_arguments(tokens: tuple[str, ...]) -> tuple[str, ...]:
    sources: list[str] = []
    previous_token: str | None = None
    for token in tokens[1:]:
        if _ASSIGNMENT_PATTERN.match(token):
            previous_token = token
            continue
        if token in _OUTPUT_REDIRECT_TOKENS:
            previous_token = token
            continue
        if token.startswith("-"):
            previous_token = token
            continue
        normalized_token = _strip_redirect_prefix(token)
        if not _is_secret_volume_path(normalized_token):
            previous_token = token
            continue
        if _is_output_redirect_target(token, previous_token=previous_token):
            previous_token = token
            continue
        sources.append(normalized_token)
        previous_token = token
    return tuple(dict.fromkeys(sources))


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


def _script_reads_sensitive_env(script: str) -> bool:
    if any(
        _is_sensitive_env_name(match.group("braced") or match.group("plain") or "")
        for match in _ENV_EXPANSION_PATTERN.finditer(script)
    ):
        return True
    for pattern in _INTERPRETER_ENV_LOOKUP_PATTERNS:
        for match in pattern.finditer(script):
            names = [group for group in match.groupdict().values() if group]
            if any(_is_sensitive_env_name(name) for name in names):
                return True
    return False


def _interpreter_reads_sensitive_env(command_name: str, args: tuple[str, ...]) -> bool:
    if not _is_inline_interpreter_command(command_name):
        return False
    script = _interpreter_inline_script(args)
    return _script_reads_sensitive_env(script) if script is not None else False


def _command_input_redirects_secret_volume(command_text: str) -> bool:
    return any(_is_secret_volume_path(target) for target in extract_input_redirects(command_text))


def _remote_cp_path(value: str) -> str | None:
    if "://" in value:
        return None
    prefix, separator, path = value.partition(":")
    if not separator or not prefix or not path:
        return None
    return path


def _strip_redirect_prefix(token: str) -> str:
    for prefix in (">>", "1>>", "2>>", ">", "1>", "2>", "<", "0<"):
        if token.startswith(prefix):
            return token[len(prefix) :]
    return token


def _is_output_redirect_target(token: str, *, previous_token: str | None) -> bool:
    return token.startswith((">", "1>", "2>", ">>", "1>>", "2>>")) or previous_token in _OUTPUT_REDIRECT_TOKENS


def _is_secret_volume_path(path: str) -> bool:
    lowered = path.strip().strip("'\"").lower()
    if not lowered:
        return False
    return any(marker in lowered for marker in (*_SERVICE_ACCOUNT_PATH_MARKERS, *_SECRET_VOLUME_PATH_MARKERS))


def _resource_token_includes_secret(token: str) -> bool:
    for item in token.lower().split(","):
        resource = item.split("/", 1)[0].split(".", 1)[0]
        if resource in {"secret", "secrets"}:
            return True
    return False


def _raw_secret_api_path(path: str) -> bool:
    normalized = path.strip().strip("'\"").lower()
    return (
        "/secret/" in normalized
        or "/secrets/" in normalized
        or normalized.endswith("/secret")
        or normalized.endswith("/secrets")
    )


def _is_inline_interpreter_command(command_name: str) -> bool:
    return command_name.startswith("python") or command_name in {"node", "perl", "php", "ruby"}


def _interpreter_inline_script(args: tuple[str, ...]) -> str | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-c", "-e"} and index + 1 < len(args):
            return args[index + 1]
        if token.startswith("-c") and len(token) > 2:
            return token[2:]
        if token.startswith("-e") and len(token) > 2:
            return token[2:]
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
