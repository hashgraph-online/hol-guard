"""Support helpers for Kubernetes runtime command detection."""

from __future__ import annotations

import re
import shlex

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
    "/var/run/secrets",
    "/run/secrets",
)
_KUBERNETES_REMOTE_PREFIX = r"(?is)\b(?:kubectl|oc)\b[^\n;&|]*\b(?:exec|rsh)\b[^\n;&|]*"
_KUBERNETES_INTERPRETER_HEREDOC_PATTERN = re.compile(
    _KUBERNETES_REMOTE_PREFIX
    + (
        r"\b(?:python(?:\d+(?:\.\d+)*)?|node|perl|php|ruby)\b[^\n;&|]*\s-\s*<<-?\s*"
        r"(['\"]?)(?P<tag>[^\s'\"`;&|<>]+)\1\s*\n"
    )
    + r"(?P<body>.*?)\n(?P=tag)(?=$|\s)"
)
_KUBERNETES_SHELL_HEREDOC_PATTERN = re.compile(
    _KUBERNETES_REMOTE_PREFIX
    + r"\b(?:ash|bash|dash|ksh|sh|zsh)\b[^\n;&|]*<<-?\s*(['\"]?)(?P<tag>[^\s'\"`;&|<>]+)\1\s*\n"
    + r"(?P<body>.*?)\n(?P=tag)(?=$|\s)"
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
    for pattern, source_hint in (
        (_KUBERNETES_INTERPRETER_HEREDOC_PATTERN, "Kubernetes pod environment"),
        (_KUBERNETES_SHELL_HEREDOC_PATTERN, None),
    ):
        match = pattern.search(command)
        if match is None:
            continue
        body = str(match.group("body") or "")
        if source_hint is not None:
            return source_hint if script_reads_sensitive_env(body) else None
        if _script_body_reads_secret_volume(body):
            return "Kubernetes secret volume"
        if script_reads_sensitive_env(body):
            return "Kubernetes pod environment"
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
    base_path = normalized.split("?", 1)[0]
    return (
        "/secret/" in base_path
        or "/secrets/" in base_path
        or base_path.endswith("/secret")
        or base_path.endswith("/secrets")
    )


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


__all__ = [
    "interpreter_reads_sensitive_env",
    "is_output_redirect_target",
    "is_secret_volume_path",
    "is_sensitive_env_name",
    "kubernetes_heredoc_secret_source",
    "raw_secret_api_path",
    "resource_token_includes_secret",
    "script_reads_sensitive_env",
    "strip_redirect_prefix",
]
