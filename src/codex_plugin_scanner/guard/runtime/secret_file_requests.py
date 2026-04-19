"""Classify sensitive runtime file-read requests without touching the filesystem."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from ..models import GuardArtifact

_FILE_READ_TOOL_NAMES = frozenset(
    {
        "read",
        "read_file",
        "open_file",
        "view",
        "view_file",
        "cat_file",
    }
)
_PATH_KEYS = (
    "path",
    "file_path",
    "filePath",
    "filepath",
    "file",
    "filename",
    "target_path",
    "targetPath",
)
_PATH_LIST_KEYS = ("paths", "file_paths", "filePaths")
_COMMAND_KEYS = ("command", "cmd", "shell_command", "shellCommand")
_COMMAND_LIST_KEYS = ("argv", "command_args", "commandArgs")
_DOCKER_SUBCOMMANDS = frozenset({"build", "compose", "login", "push", "run"})
_SHELL_TOOL_NAMES = frozenset(
    {
        "bash",
        "cmd",
        "powershell",
        "pwsh",
        "run_command",
        "run_terminal_command",
        "shell",
        "sh",
        "terminal",
        "zsh",
    }
)
_DESTRUCTIVE_SHELL_COMMANDS = frozenset(
    {
        "chmod",
        "chown",
        "dd",
        "mv",
        "perl",
        "python",
        "python3",
        "rm",
        "ruby",
        "tee",
        "truncate",
    }
)
_SCRIPT_INTERPRETER_COMMANDS = frozenset({"perl", "python", "python3", "ruby"})
_SAFE_SHELL_REDIRECT_TARGETS = frozenset(
    {
        "/dev/null",
        "/dev/stdout",
        "/dev/stderr",
        "nul",
    }
)
_SENSITIVE_BASENAME_LABELS = {
    ".npmrc": "npm registry credentials",
    ".pypirc": "Python package credentials",
    ".netrc": "netrc credentials",
    ".git-credentials": "Git credential store",
}
_SENSITIVE_SUFFIX_LABELS = {
    (".aws", "credentials"): "AWS shared credentials file",
    (".aws", "config"): "AWS shared config file",
    (".docker", "config.json"): "Docker client config",
    (".ssh", "id_rsa"): "SSH private key",
    (".ssh", "id_ed25519"): "SSH private key",
    (".ssh", "config"): "SSH client config",
}
_SENSITIVE_PATH_REASONS = {
    "local .env file": "Guard treats .env files as sensitive because they commonly store local secrets.",
    "npm registry credentials": "Guard treats .npmrc as sensitive because it may contain registry tokens.",
    "Python package credentials": "Guard treats .pypirc as sensitive because it may contain package credentials.",
    "netrc credentials": "Guard treats .netrc as sensitive because it may contain login secrets.",
    "Git credential store": "Guard treats .git-credentials as sensitive because it may contain repository credentials.",
    "AWS shared credentials file": (
        "Guard treats AWS shared credentials as sensitive because they contain cloud access keys."
    ),
    "AWS shared config file": "Guard treats AWS shared config as sensitive because it may contain credential profiles.",
    "Docker client config": "Guard treats Docker client config as sensitive because it may contain registry auth.",
    "SSH private key": "Guard treats SSH private keys as sensitive because they provide direct host access.",
    "SSH client config": "Guard treats SSH config as sensitive because it may reveal or shape host credentials.",
}


@dataclass(frozen=True, slots=True)
class SensitivePathMatch:
    """A normalized sensitive path classification."""

    requested_path: str
    normalized_path: str
    path_class: str
    reason: str


@dataclass(frozen=True, slots=True)
class FileReadRequestMatch:
    """A sensitive file-read tool call."""

    tool_name: str
    normalized_tool_name: str
    path_match: SensitivePathMatch


@dataclass(frozen=True, slots=True)
class ToolActionRequestMatch:
    """A sensitive native tool action that should block before execution."""

    tool_name: str
    normalized_tool_name: str
    command_text: str
    action_class: str
    reason: str


def is_file_read_tool_name(tool_name: str | None) -> bool:
    """Return whether the tool name looks like a file-read tool."""

    if not isinstance(tool_name, str) or not tool_name.strip():
        return False
    return tool_name.strip().lower() in _FILE_READ_TOOL_NAMES


def classify_sensitive_path(
    path: str | None,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> SensitivePathMatch | None:
    """Classify a path if it points at a high-confidence sensitive local file."""

    if not isinstance(path, str):
        return None
    requested_path = path.strip().strip("'").strip('"')
    if not requested_path:
        return None
    expanded_home = _expand_home(requested_path, home_dir)
    normalized_path = _normalize_path(expanded_home, cwd)
    lowered_segments = tuple(segment for segment in normalized_path.replace("\\", "/").lower().split("/") if segment)
    if not lowered_segments:
        return None
    basename = lowered_segments[-1]
    if basename == ".env" or basename.startswith(".env."):
        return SensitivePathMatch(
            requested_path=requested_path,
            normalized_path=normalized_path,
            path_class="local .env file",
            reason=_SENSITIVE_PATH_REASONS["local .env file"],
        )
    if basename in _SENSITIVE_BASENAME_LABELS:
        path_class = _SENSITIVE_BASENAME_LABELS[basename]
        return SensitivePathMatch(
            requested_path=requested_path,
            normalized_path=normalized_path,
            path_class=path_class,
            reason=_SENSITIVE_PATH_REASONS[path_class],
        )
    for suffix, path_class in _SENSITIVE_SUFFIX_LABELS.items():
        if lowered_segments[-len(suffix) :] == suffix:
            return SensitivePathMatch(
                requested_path=requested_path,
                normalized_path=normalized_path,
                path_class=path_class,
                reason=_SENSITIVE_PATH_REASONS[path_class],
            )
    return None


def extract_sensitive_file_read_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Extract a sensitive file-read request from tool arguments."""

    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name is None or normalized_tool_name not in _FILE_READ_TOOL_NAMES:
        return None
    for candidate in _candidate_paths(arguments):
        path_match = classify_sensitive_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileReadRequestMatch(
                tool_name=str(tool_name).strip(),
                normalized_tool_name=normalized_tool_name,
                path_match=path_match,
            )
    return None


def build_file_read_request_artifact(
    harness: str,
    request: FileReadRequestMatch,
    *,
    config_path: str,
    source_scope: str,
) -> GuardArtifact:
    """Build a Guard artifact for an exact sensitive runtime file-read request."""

    fingerprint = _file_read_request_fingerprint(
        harness=harness,
        tool_name=request.normalized_tool_name,
        normalized_path=request.path_match.normalized_path,
    )
    request_summary = (
        f"Requested `{request.tool_name}` access to `{request.path_match.normalized_path}` "
        f"({request.path_match.path_class})."
    )
    risk_summary = f"Requests access to a sensitive local file: {request.path_match.path_class}."
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:file-read:{fingerprint}",
        name=f"{request.tool_name} {Path(request.path_match.normalized_path).name}",
        harness=harness,
        artifact_type="file_read_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "tool_name": request.tool_name,
            "normalized_path": request.path_match.normalized_path,
            "path_class": request.path_match.path_class,
            "request_summary": request_summary,
            "runtime_request_signals": ["requests access to a sensitive local file"],
            "runtime_request_summary": risk_summary,
            "runtime_request_reason": request.path_match.reason,
        },
    )


def extract_sensitive_tool_action_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> ToolActionRequestMatch | None:
    """Extract a sensitive native tool action from arguments."""

    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name is None:
        return None
    requested_tool_name = str(tool_name).strip()
    for command_text in _candidate_command_texts(arguments):
        docker_sensitive_request = _docker_sensitive_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
        )
        if docker_sensitive_request is not None:
            return docker_sensitive_request
        docker_config_request = _docker_config_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            cwd=cwd,
            home_dir=home_dir,
        )
        if docker_config_request is not None:
            return docker_config_request
        destructive_shell_request = _destructive_shell_tool_action_request(
            tool_name=requested_tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
        )
        if destructive_shell_request is not None:
            return destructive_shell_request
    return None


def _docker_sensitive_tool_action_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
) -> ToolActionRequestMatch | None:
    if _normalize_docker_command(command_text) is None:
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class="docker-sensitive command",
        reason=(
            "Guard treats Docker login, build, run, push, and compose actions as sensitive because they can expose "
            "credentials or execute privileged container workflows."
        ),
    )


def _docker_config_tool_action_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
) -> ToolActionRequestMatch | None:
    if _docker_config_path_from_command(command_text, cwd=cwd, home_dir=home_dir) is None:
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class="Docker client config access",
        reason=_SENSITIVE_PATH_REASONS["Docker client config"],
    )


def _destructive_shell_tool_action_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
) -> ToolActionRequestMatch | None:
    if normalized_tool_name not in _SHELL_TOOL_NAMES:
        return None
    if not _looks_destructive_shell_command(command_text):
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class="destructive shell command",
        reason=(
            "Guard treats destructive shell writes and delete operations as sensitive because they can mutate the "
            "local machine before the user confirms the action."
        ),
    )


def build_tool_action_request_artifact(
    harness: str,
    request: ToolActionRequestMatch,
    *,
    config_path: str,
    source_scope: str,
) -> GuardArtifact:
    """Build a Guard artifact for a sensitive native tool action request."""

    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "harness": harness,
                "tool_name": request.normalized_tool_name,
                "command_text": request.command_text,
                "action_class": request.action_class,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    request_summary = f"Requested `{request.tool_name}` action `{request.command_text}` ({request.action_class})."
    risk_summary = f"Requests a sensitive native tool action: {request.action_class}."
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:tool-action:{fingerprint}",
        name=f"{request.tool_name} {request.action_class}",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "tool_name": request.tool_name,
            "command_text": request.command_text,
            "request_summary": request_summary,
            "runtime_request_signals": [f"invokes a sensitive native tool action: {request.action_class}"],
            "runtime_request_summary": risk_summary,
            "runtime_request_reason": request.reason,
        },
    )


def _candidate_paths(value: object) -> list[str]:
    results: list[str] = []
    _collect_candidate_paths(value, results, depth=0)
    return results


def _collect_candidate_paths(value: object, results: list[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, dict):
        for key in _PATH_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                results.append(candidate)
        for key in _PATH_LIST_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, list):
                results.extend(item for item in candidate if isinstance(item, str) and item.strip())
        for child in value.values():
            if isinstance(child, (dict, list)):
                _collect_candidate_paths(child, results, depth=depth + 1)
        return
    if isinstance(value, list):
        for child in value:
            if isinstance(child, str) and child.strip():
                results.append(child)
            elif isinstance(child, (dict, list)):
                _collect_candidate_paths(child, results, depth=depth + 1)
        return


def _candidate_command_texts(value: object) -> list[str]:
    results: list[str] = []
    _collect_candidate_commands(value, results, depth=0)
    return results


def _collect_candidate_commands(value: object, results: list[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            results.append(stripped)
        return
    if isinstance(value, list):
        string_values = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        if string_values:
            results.append(" ".join(string_values))
        for child in value:
            if isinstance(child, (dict, list)):
                _collect_candidate_commands(child, results, depth=depth + 1)
        return
    if not isinstance(value, dict):
        return
    for key in _COMMAND_KEYS:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            results.append(candidate.strip())
    for key in _COMMAND_LIST_KEYS:
        candidate = value.get(key)
        if isinstance(candidate, list):
            string_values = [item.strip() for item in candidate if isinstance(item, str) and item.strip()]
            if string_values:
                results.append(" ".join(string_values))
    for child in value.values():
        if isinstance(child, (dict, list)):
            _collect_candidate_commands(child, results, depth=depth + 1)


def _expand_home(value: str, home_dir: Path | None) -> str:
    if value == "~":
        return str(home_dir or Path.home())
    if value.startswith("~/") or value.startswith("~\\"):
        base = home_dir or Path.home()
        return str(base / value[2:])
    return value


def _normalize_path(value: str, cwd: Path | None) -> str:
    if os.path.isabs(value):
        return os.path.normpath(value)
    if cwd is not None:
        return os.path.normpath(os.path.join(str(cwd), value))
    return os.path.normpath(value)


def _normalize_tool_name(tool_name: object) -> str | None:
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    return tool_name.strip().lower()


def _normalize_docker_command(command_text: str) -> str | None:
    normalized = command_text.strip().lower()
    if not normalized.startswith("docker "):
        return None
    parts = normalized.split()
    if len(parts) < 2:
        return None
    subcommand = parts[1]
    if subcommand in _DOCKER_SUBCOMMANDS:
        return normalized
    return None


def _docker_config_path_from_command(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    normalized_command = command_text.replace("\\", "/")
    if ".docker/config.json" not in normalized_command:
        return None
    match = classify_sensitive_path(".docker/config.json", cwd=cwd, home_dir=home_dir)
    if match is None:
        return None
    return match.normalized_path


def _looks_destructive_shell_command(command_text: str) -> bool:
    normalized = command_text.strip()
    if not normalized:
        return False
    lowered = normalized.lower()
    if _contains_mutating_shell_redirection(lowered):
        return True
    raw_command_names = list(_shell_command_names(_redacted_shell_text_for_command_names(lowered)))
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    if _looks_like_benign_interpreter_wait(normalized, parts, raw_command_names):
        return False
    command_names = list(raw_command_names)
    command_names.extend(_shell_command_names_from_parts(parts))
    if any(command_name in _DESTRUCTIVE_SHELL_COMMANDS for command_name in command_names):
        return True
    for shell_script in _shell_command_scripts(parts):
        if _looks_destructive_shell_command(shell_script):
            return True
    return any(
        command_name == "sed" and any(part == "-i" or part.startswith("-i") for part in parts[1:])
        for command_name in command_names
    )


def _contains_mutating_shell_redirection(command_text: str) -> bool:
    for match in re.finditer(r"(?<!<)(?P<fd>[0-2]?)(?P<op>>\||>>|>)\s*(?P<target>\S+)", command_text):
        fd = match.group("fd")
        target = _normalized_redirect_target(match.group("target"))
        if fd == "2" and target in _SAFE_SHELL_REDIRECT_TARGETS:
            continue
        if target in _SAFE_SHELL_REDIRECT_TARGETS or target.startswith("&"):
            continue
        return True
    return False


def _normalized_redirect_target(target: str) -> str:
    return target.strip().strip(");,").strip("'\"")


def _shell_command_names(command_text: str) -> tuple[str, ...]:
    pattern = re.compile(r"(?:^|&&|\|\||[;&|\n])\s*(?:[a-z_][a-z0-9_]*=\S+\s+)*(?P<command>[a-z0-9_./\\\\-]+)")
    return tuple(_normalized_shell_command_name(match.group("command")) for match in pattern.finditer(command_text))


def _normalized_shell_command_name(command_name: str) -> str:
    normalized_command = command_name.replace("\\", "/").strip()
    if "/" not in normalized_command:
        return normalized_command
    return normalized_command.rsplit("/", 1)[-1]


def _redacted_shell_text_for_command_names(command_text: str) -> str:
    return re.sub(r"'[^']*'|\"[^\"]*\"", "Q", command_text)


def _split_shell_parts(command_text: str) -> list[str]:
    try:
        lexer = shlex.shlex(command_text, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command_text.split()


def _shell_command_names_from_parts(parts: list[str]) -> tuple[str, ...]:
    command_names: list[str] = []
    expect_command = True
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in {"&&", "||", ";", "|", "&"}:
            expect_command = True
            continue
        normalized_token = token.lstrip("(").rstrip(")")
        if not normalized_token:
            continue
        if not expect_command:
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", normalized_token):
            continue
        normalized_command = _normalized_shell_command_name(normalized_token)
        if normalized_command in {"env", "command", "builtin", "nohup", "nice", "time", "stdbuf"}:
            expect_command = True
            continue
        command_names.append(normalized_command)
        expect_command = False
    return tuple(command_names)


def _shell_command_scripts(parts: list[str]) -> tuple[str, ...]:
    scripts: list[str] = []
    for index, part in enumerate(parts[:-1]):
        if not _is_shell_command_flag(part):
            continue
        script = parts[index + 1].strip()
        if script:
            scripts.append(script)
    return tuple(scripts)


def _script_interpreter_texts(parts: list[str]) -> tuple[str, ...]:
    scripts: list[str] = []
    current_command: str | None = None
    expect_command = True
    index = 0
    while index < len(parts):
        token = parts[index].strip()
        if not token:
            index += 1
            continue
        if token in {"&&", "||", ";", "|", "&"}:
            current_command = None
            expect_command = True
            index += 1
            continue
        normalized_token = token.lstrip("(").rstrip(")")
        if not normalized_token:
            index += 1
            continue
        if expect_command:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", normalized_token):
                index += 1
                continue
            normalized_command = _normalized_shell_command_name(normalized_token)
            if normalized_command in {"env", "command", "builtin", "nohup", "nice", "time", "stdbuf"}:
                current_command = None
                index += 1
                continue
            current_command = normalized_command
            expect_command = False
            index += 1
            continue
        if current_command in _SCRIPT_INTERPRETER_COMMANDS:
            flag_payload = _interpreter_flag_payload(parts, index)
            if flag_payload is not None:
                scripts.append(flag_payload.script_text)
                index += flag_payload.tokens_consumed
                continue
        index += 1
    return tuple(scripts)


def _looks_like_benign_interpreter_wait(command_text: str, parts: list[str], command_names: list[str]) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    if not command_names or not all(command_name in _SCRIPT_INTERPRETER_COMMANDS for command_name in command_names):
        return False
    scripts = _script_interpreter_texts(parts)
    if not scripts or len(scripts) != len(command_names):
        return False
    return all(_script_is_benign_wait(script_text) for script_text in scripts)


def _script_is_benign_wait(script_text: str) -> bool:
    normalized_script = script_text.strip()
    if not normalized_script:
        return False
    return bool(
        re.fullmatch(r"sleep\s+\d+(?:\.\d+)?", normalized_script)
        or re.fullmatch(r"(?:import\s+time\s*;\s*)?time\.sleep\(\s*\d+(?:\.\d+)?\s*\)", normalized_script)
    )


@dataclass(frozen=True, slots=True)
class _InterpreterFlagPayload:
    script_text: str
    tokens_consumed: int


def _interpreter_flag_payload(parts: list[str], index: int) -> _InterpreterFlagPayload | None:
    normalized_token = parts[index].strip().lstrip("(").rstrip(")")
    if not normalized_token.startswith("-"):
        return None
    flag_text = normalized_token[1:]
    for flag_name in ("c", "e"):
        flag_index = flag_text.find(flag_name)
        if flag_index == -1:
            continue
        attached_script = flag_text[flag_index + 1 :].strip()
        if attached_script:
            return _InterpreterFlagPayload(script_text=attached_script, tokens_consumed=1)
        if index + 1 >= len(parts):
            return None
        next_script = parts[index + 1].strip()
        if not next_script:
            return None
        return _InterpreterFlagPayload(script_text=next_script, tokens_consumed=2)
    return None


def _is_shell_command_flag(value: str) -> bool:
    if value == "-c":
        return True
    if not value.startswith("-"):
        return False
    flag_characters = value[1:]
    return bool(flag_characters) and set(flag_characters) <= {"c", "l"}


def _file_read_request_fingerprint(*, harness: str, tool_name: str, normalized_path: str) -> str:
    payload = {
        "harness": harness,
        "tool_name": tool_name,
        "normalized_path": normalized_path,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
