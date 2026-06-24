"""Support helpers for Kubernetes runtime command detection."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
_SENSITIVE_ENV_NAME_PATTERN = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|auth|credential|credentials|key|password|private[_-]?key|secret|token)(?:[_-]|$)"
)
_ENV_EXPANSION_PATTERN = re.compile(
    r"(?<!\\)\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)[^}]*\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_INTERPRETER_ENV_LOOKUP_PATTERNS = (
    re.compile(r"os\.environ\s*\[\s*['\"](?P<name>[^'\"]+)['\"]\s*\]", re.IGNORECASE),
    re.compile(r"os\.environ\s*\[\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\]", re.IGNORECASE),
    re.compile(r"os\.environ\.get\(\s*['\"](?P<name>[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"os\.getenv\(\s*['\"](?P<name>[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"process\.env(?:\.\s*(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])"),
    re.compile(r"ENV\[\s*['\"](?P<name>[^'\"]+)['\"]\s*\]"),
    re.compile(r"System\.getenv\(\s*['\"](?P<name>[^'\"]+)['\"]\s*\)", re.IGNORECASE),
)
_OUTPUT_REDIRECT_TOKENS = frozenset({">", "1>", "2>", ">>", "1>>", "2>>"})
_SERVICE_ACCOUNT_PATH_MARKERS = (
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/run/secrets/kubernetes.io/serviceaccount",
)
_SECRET_VOLUME_PATH_MARKERS = (
    "/etc/secrets",
    "/etc/secret",
    "/mnt/secrets-store",
    "/var/run/secrets",
    "/var/run/secrets-store",
    "/run/secrets",
    "/run/secrets-store",
)
_KUBERNETES_HEREDOC_HEADER_PATTERN = re.compile(
    r"(?im)(?P<header>\b(?:kubectl|oc)\b[^\n]*\b(?:exec|rsh)\b[^\n]*?)"
    r"<<-?\s*(?P<quote>['\"]?)(?P<tag>[^\s'\"`;&|<>]+)(?P=quote)[ \t]*\n"
)
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
_SHELL_EXECUTABLES = frozenset({"ash", "bash", "dash", "ksh", "sh", "zsh"})
_RAW_SECRET_RESOURCE_PATH_PATTERN = re.compile(
    r"^/(?:api/[^/]+|apis/[^/]+/[^/]+)/(?:watch/)?(?:namespaces/[^/]+/)?secrets?(?:/[^/?#]+)?$",
    re.IGNORECASE,
)


def interpreter_reads_sensitive_env(command_name: str, args: tuple[str, ...]) -> bool:
    if not _is_inline_interpreter_command(command_name):
        return False
    script = _interpreter_inline_script(args)
    if script is not None:
        return script_reads_sensitive_env(script)
    joined = " ".join(args)
    return "-" in args and any(token.startswith("<<") for token in args) and script_reads_sensitive_env(joined)


def kubernetes_heredoc_secret_source(command: str) -> str | None:
    for match in _KUBERNETES_HEREDOC_HEADER_PATTERN.finditer(command):
        source_kind = _kubernetes_heredoc_remote_kind(str(match.group("header") or ""))
        if source_kind is None:
            continue
        body = _heredoc_body(command, tag=str(match.group("tag") or ""), start=match.end())
        if body is None:
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


def kubernetes_option_tokens_consumed(
    tokens: tuple[str, ...],
    index: int,
    *,
    base_value_flags: frozenset[str],
    base_boolean_flags: frozenset[str],
    base_boolean_short_cluster: frozenset[str],
    value_flags: frozenset[str] = frozenset(),
    boolean_flags: frozenset[str] = frozenset(),
    boolean_short_cluster: frozenset[str] = frozenset(),
) -> int | None:
    token = tokens[index]
    all_value_flags = base_value_flags | value_flags
    if token in all_value_flags and index + 1 < len(tokens):
        return 2
    if any(token.startswith(f"{flag}=") for flag in all_value_flags if flag.startswith("--")):
        return 1
    if token in (base_boolean_flags | boolean_flags):
        return 1
    if any(token.startswith(flag) and len(token) > len(flag) for flag in all_value_flags if flag.startswith("-")):
        return 1
    short_cluster = base_boolean_short_cluster | boolean_short_cluster
    if token.startswith("-") and not token.startswith("--") and set(token[1:]).issubset(short_cluster):
        return 1
    return None


def is_output_redirect_target(token: str, *, previous_token: str | None) -> bool:
    return token.startswith((">", "1>", "2>", ">>", "1>>", "2>>")) or previous_token in _OUTPUT_REDIRECT_TOKENS


def is_secret_volume_path(path: str) -> bool:
    return any(
        candidate == marker or candidate.startswith(f"{marker}/")
        for candidate in _path_candidates(path)
        for marker in (*_SERVICE_ACCOUNT_PATH_MARKERS, *_SECRET_VOLUME_PATH_MARKERS)
    )


def is_sensitive_env_name(name: str) -> bool:
    return _SENSITIVE_ENV_NAME_PATTERN.search(name.strip()) is not None


def raw_secret_api_path(path: str) -> bool:
    normalized = path.strip().strip("'\"").lower()
    base_path = normalized.split("#", 1)[0].split("?", 1)[0]
    return _RAW_SECRET_RESOURCE_PATH_PATTERN.fullmatch(base_path) is not None


def remote_cp_path(value: str) -> str | None:
    if "://" in value:
        return None
    prefix, separator, path = value.partition(":")
    if not separator or not prefix or not path:
        return None
    return path


def resource_token_includes_secret(token: str) -> bool:
    for item in token.lower().split(","):
        resource = item.split("/", 1)[0].split(".", 1)[0]
        if resource in {"secret", "secrets"}:
            return True
    return False


def script_reads_sensitive_env(script: str) -> bool:
    if any(
        is_sensitive_env_name(match.group("braced") or match.group("plain") or "")
        for match in _ENV_EXPANSION_PATTERN.finditer(script)
    ):
        return True
    for pattern in _INTERPRETER_ENV_LOOKUP_PATTERNS:
        for match in pattern.finditer(script):
            names = [group for group in match.groupdict().values() if group]
            if any(is_sensitive_env_name(name) for name in names):
                return True
    return False


def secret_volume_argument_value(token: str) -> str:
    normalized_token = strip_redirect_prefix(token)
    if normalized_token.startswith("-") and "=" in normalized_token:
        return normalized_token.split("=", 1)[1]
    return normalized_token


def strip_redirect_prefix(token: str) -> str:
    for prefix in (">>", "1>>", "2>>", ">", "1>", "2>", "<", "0<"):
        if token.startswith(prefix):
            return token[len(prefix) :]
    return token


def _script_body_reads_secret_volume(body: str) -> bool:
    try:
        tokens = shlex.split(body)
    except ValueError:
        tokens = body.split()
    return any(is_secret_volume_path(strip_redirect_prefix(token)) for token in tokens)


def _path_candidates(path: str) -> tuple[str, ...]:
    normalized = path.strip().strip("'\"").lower()
    if not normalized:
        return ()
    candidates = [normalized]
    if "=" in normalized and not normalized.startswith("="):
        _key, _separator, value = normalized.partition("=")
        value = value.strip().strip("'\"")
        if value:
            candidates.append(value)
    return tuple(dict.fromkeys(candidates))


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


def _is_inline_interpreter_command(command_name: str) -> bool:
    return command_name.startswith("python") or command_name in {"node", "perl", "php", "ruby"}


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


def _heredoc_body(command: str, *, tag: str, start: int) -> str | None:
    terminator = re.compile(rf"(?m)^[\t ]*{re.escape(tag)}[\t ]*(?:\r?$)")
    end_match = terminator.search(command, start)
    if end_match is None:
        return None
    return command[start : end_match.start()]


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


def _kubernetes_heredoc_remote_kind(header: str) -> str | None:
    remote_tokens = _kubernetes_heredoc_remote_tokens(header)
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


def _kubernetes_heredoc_remote_tokens(header: str) -> tuple[str, ...]:
    try:
        tokens = tuple(shlex.split(header))
    except ValueError:
        tokens = tuple(header.split())
    if not tokens:
        return ()
    kubernetes_index = next(
        (index for index, token in enumerate(tokens) if Path(token).name.lower() in {"kubectl", "oc"}),
        None,
    )
    if kubernetes_index is None:
        return ()
    subcommand_index = next(
        (index for index in range(kubernetes_index + 1, len(tokens)) if tokens[index].lower() in {"exec", "rsh"}),
        None,
    )
    if subcommand_index is None:
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


def _wrapper_option_tokens_consumed(command_name: str, token: str) -> int:
    options_with_values = _HEREDOC_WRAPPER_OPTIONS_WITH_VALUES.get(command_name, frozenset())
    if token in options_with_values:
        return 2
    if any(token.startswith(f"{option}=") for option in options_with_values if option.startswith("--")):
        return 1
    return 1


__all__ = [
    "interpreter_reads_sensitive_env",
    "is_output_redirect_target",
    "is_secret_volume_path",
    "is_sensitive_env_name",
    "kubernetes_heredoc_secret_source",
    "kubernetes_option_tokens_consumed",
    "raw_secret_api_path",
    "remote_cp_path",
    "resource_token_includes_secret",
    "script_reads_sensitive_env",
    "secret_volume_argument_value",
    "strip_redirect_prefix",
]
