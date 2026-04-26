"""Classify sensitive runtime file-read requests without touching the filesystem."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import stat
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
        "ash",
        "bash",
        "cmd",
        "dash",
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
_SHELL_SCRIPT_INTERPRETER_COMMANDS = frozenset({"ash", "bash", "dash", "sh", "zsh", ".", "source"})
_SHELL_COMMAND_STRING_INTERPRETERS = frozenset({"ash", "bash", "dash", "sh", "zsh"})
_DESTRUCTIVE_SHELL_COMMANDS = frozenset(
    {
        "chmod",
        "chown",
        "dd",
        "del",
        "erase",
        "mv",
        "perl",
        "python",
        "python3",
        "rd",
        "remove-item",
        "rm",
        "rmdir",
        "ruby",
        "tee",
        "truncate",
        "unlink",
    }
)
_SCRIPT_INTERPRETER_COMMANDS = frozenset({"perl", "python", "python3", "ruby"})
_READ_ONLY_OBSERVER_INTERPRETER_COMMANDS = frozenset({"python", "python3"})
_UNMODELED_INLINE_INTERPRETER_COMMANDS = frozenset({"perl", "ruby"})
_SAFE_SHELL_REDIRECT_TARGETS = frozenset(
    {
        "/dev/null",
        "/dev/stdout",
        "/dev/stderr",
        "nul",
    }
)
_NODE_INLINE_EVAL_FLAGS = frozenset({"-e", "--eval", "-p", "--print"})
_NODE_OPTION_FLAGS_WITH_VALUE = frozenset(
    {
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--input-type",
        "--conditions",
        "--debug-port",
        "--inspect-port",
        "--redirect-warnings",
        "--title",
    }
)
_CURL_AT_FILE_FLAGS_WITH_VALUE = frozenset({"--data", "--data-ascii", "--data-binary", "--json", "-d"})
_CURL_CONFIG_FLAGS_WITH_VALUE = frozenset({"--config", "-K"})
_CURL_DATA_URLENCODE_FLAGS_WITH_VALUE = frozenset({"--data-urlencode", "--url-query"})
_CURL_EXPAND_FLAGS_WITH_VALUE = frozenset(
    {"--expand-data", "--expand-header", "--expand-url", "--expand-user", "--expand-variable"}
)
_CURL_FORM_FLAGS_WITH_VALUE = frozenset({"--form", "-F"})
_CURL_DIRECT_FILE_FLAGS_WITH_VALUE = frozenset({"--upload-file", "-T"})
_CURL_VARIABLE_FLAGS_WITH_VALUE = frozenset({"--variable"})
_CURL_SHORT_FLAGS_WITH_VALUES = frozenset(
    {
        "A",
        "b",
        "C",
        "c",
        "d",
        "D",
        "e",
        "E",
        "F",
        "H",
        "h",
        "K",
        "m",
        "o",
        "P",
        "Q",
        "r",
        "t",
        "T",
        "u",
        "U",
        "w",
        "x",
        "X",
        "y",
        "Y",
        "z",
    }
)
_WGET_UPLOAD_FLAGS_WITH_VALUE = frozenset({"--body-file", "--post-file"})
_SHELL_COMMAND_SEPARATORS = frozenset({"&&", "||", ";", "|", "&", "|&"})
_SHELL_COMMAND_WRAPPERS = frozenset({"command", "env", "nice", "nohup", "stdbuf", "sudo", "time"})
_BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS = frozenset({"cat", "curl", "echo", "printf", "sed", "tr", "wget"})
_SHELL_ASSIGNMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
_SHELL_NEWLINE_SEPARATOR = ";"
_HEREDOC_PATTERN = re.compile(r"<<-?\s*(['\"]?)([^\s'\";|&<>]+)\1")
_SAFE_INTERPRETER_SETUP_SEGMENT_PATTERN = r"(?:cd\b[^\n;&|]*)"
_SINGLE_INTERPRETER_HEREDOC_PATTERN = re.compile(
    rf"^\s*(?:(?:{_SAFE_INTERPRETER_SETUP_SEGMENT_PATTERN})\s*&&\s*)*(?P<interpreter>perl|python|python3|ruby)\b[^\n;&|]*<<-?\s*(?P<quote>['\"]?)(?P<tag>[^\s'\";|&<>]+)(?P=quote)\s*\n(?P<body>.*)\n(?P=tag)\s*$",
    re.IGNORECASE | re.DOTALL,
)
_DESTRUCTIVE_NODE_INLINE_CALLS = frozenset(
    {
        "appendFile",
        "appendFileSync",
        "chmod",
        "chmodSync",
        "chown",
        "chownSync",
        "copyFile",
        "copyFileSync",
        "mkdir",
        "mkdirSync",
        "rename",
        "renameSync",
        "rm",
        "rmSync",
        "truncate",
        "truncateSync",
        "unlink",
        "unlinkSync",
        "writeFile",
        "writeFileSync",
    }
)
_DESTRUCTIVE_GIT_SUBCOMMANDS = frozenset({"clean", "reset", "restore", "rm"})
_READ_ONLY_INTERPRETER_MUTATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bwrite_(?:text|bytes)\s*\(", re.IGNORECASE),
    re.compile(r"\bunlink\b", re.IGNORECASE),
    re.compile(
        r"\b(?:unlink|rmdir|remove|removedirs|rename|replace|chmod|chown|mkdir|makedirs|truncate)\s*\(", re.IGNORECASE
    ),
    re.compile(r"\b(?:copy|copy2|copyfile|copyfileobj|copytree|move|rmtree|symlink|link)\s*\(", re.IGNORECASE),
    re.compile(
        r"\bopen\s*\([^)]*(?:,\s*['\"][^'\"]*[wax+][^'\"]*['\"]|\bmode\s*=\s*['\"][^'\"]*[wax+][^'\"]*['\"])",
        re.IGNORECASE,
    ),
    re.compile(r"\.\s*open\s*\(\s*['\"][^'\"]*[wax+][^'\"]*['\"]", re.IGNORECASE),
    re.compile(r"\b(?:fdopen|os\.fdopen)\s*\([^)]*,\s*['\"][^'\"]*[wax+][^'\"]*['\"]", re.IGNORECASE),
    re.compile(r"\bos\.open\s*\([^)]*\b(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b", re.IGNORECASE),
    re.compile(r"\bos\.write\s*\(", re.IGNORECASE),
    re.compile(
        r"\b(?:os\.system|subprocess\.(?:run|popen|call|check_call|check_output)|run|popen|call|check_call|check_output|system)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bpath\s*\([^)]*\)\s*\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\.\s*(?:write_text|write_bytes|touch|unlink|rename|replace|chmod|mkdir|rmdir|symlink_to|hardlink_to|link_to)\s*\(",
        re.IGNORECASE,
    ),
)
_GIT_GLOBAL_OPTIONS_WITH_VALUE = frozenset(
    {
        "-C",
        "-c",
        "--config-env",
        "--exec-path",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    }
)
_WRAPPER_FLAGS_WITH_VALUES = {
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
_ENCODED_EXECUTION_TARGET_PATTERN = (
    r"(?:(?:[A-Za-z0-9_./~-]+/)?env"
    r"(?:(?:\s+--?[A-Za-z][A-Za-z-]*(?:=\S+)?|\s+--|\s+[A-Za-z_][A-Za-z0-9_]*=\S+|\s+\S+))*\s+)?"
    r"(?:[A-Za-z0-9_./~-]+/)?(?:ash|bash|dash|sh|zsh|python(?:3)?|node|perl|ruby|pwsh|powershell)\b"
)
_ENCODED_EXECUTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"\bbase64\b(?=[^\n|;]*\s(?:--decode|-[A-Za-z]*[dD][A-Za-z]*))[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bxxd\s+(?:-r\s+-p|-rp)\b[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bopenssl\s+enc\b[^\n|;]*\s-(?:d|decrypt)\b[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:gpg|gpg2)\b[^\n|;]*(?:--decrypt|-d)\b[^\n|;]*(?:\|\s*{_ENCODED_EXECUTION_TARGET_PATTERN})",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:powershell|pwsh)\b[^\n;]*\s-(?:e|ec|enc|encodedcommand)\b", re.IGNORECASE),
    re.compile(r"\b(?:powershell|pwsh)\b[^\n;]*\bfrombase64string\s*\(", re.IGNORECASE),
)
_BASE64_LITERAL_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_LITERAL_PATTERN = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{24,}(?![A-Fa-f0-9])")
_MAX_DECODED_PAYLOAD_BYTES = 32 * 1024
_SENSITIVE_DECODED_PAYLOAD_TOKENS = (
    ".env",
    ".ssh/",
    ".aws/credentials",
    ".git-credentials",
    "process.env",
    "os.environ",
    "getenv(",
    "curl ",
    "wget ",
    "requests.",
    "fetch(",
    "axios.",
    "approval_policy",
    "hol-guard",
    "guard-bypass",
    ".codex/config.toml",
    "scp ",
)
_SECRET_EXFILTRATION_SECRET_PATTERN = re.compile(
    r"\b(?:api[_-]?key|auth[_-]?token|credential|credentials|npm[_-]?token|private[_-]?key|secret|token)\b",
    re.IGNORECASE,
)
_SECRET_EXFILTRATION_NETWORK_PATTERN = re.compile(
    r"\b(?:axios\.post|fetch\s*\(|http\.client|requests\.post|urllib\.request|urlopen\s*\()|https?://",
    re.IGNORECASE,
)
_SECRET_EXFILTRATION_DESTINATION_PATTERN = re.compile(
    r"\b(?:collect|exfil|evil|leak|post|upload|webhook)\b",
    re.IGNORECASE,
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
    (".ssh", "id_ecdsa"): "SSH private key",
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
            cwd=cwd,
            home_dir=home_dir,
        )
        if destructive_shell_request is not None:
            return destructive_shell_request
    return None


def is_explicitly_benign_tool_action_request(tool_name: object, arguments: object) -> bool:
    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name not in _SHELL_TOOL_NAMES:
        return False
    for command_text in _candidate_command_texts(arguments):
        stripped_command = command_text.strip()
        if not stripped_command:
            continue
        parts = _split_shell_parts(stripped_command)
        if not parts:
            continue
        parsed_command_names = list(_shell_command_names_from_parts(parts))
        if _looks_like_benign_interpreter_wait(stripped_command, parts, parsed_command_names):
            return True
        if _looks_like_read_only_interpreter_command(stripped_command, parts, parsed_command_names):
            return True
    return False


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
    cwd: Path | None,
    home_dir: Path | None,
) -> ToolActionRequestMatch | None:
    if normalized_tool_name not in _SHELL_TOOL_NAMES:
        return None
    if _contains_encoded_or_encrypted_shell_command(command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="encoded or encrypted shell command",
            reason=(
                "Guard treats encoded or encrypted decode-and-exec shell flows as sensitive and inspects bounded "
                "payloads in-process without executing them during evaluation."
            ),
        )
    if _contains_shell_credential_exfiltration(command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="credential exfiltration shell command",
            reason=(
                "Guard treats shell scripts that combine credential-looking material with outbound HTTP posting as "
                "sensitive because they can exfiltrate local secrets before the user confirms the action."
            ),
        )
    if _contains_shell_network_file_upload(command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="shell file upload command",
            reason=(
                "Guard treats shell-driven local file uploads as sensitive because they can exfiltrate local file "
                "contents to a network endpoint before the user confirms the action."
            ),
        )
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


def _contains_shell_credential_exfiltration(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    if _shell_segments_contain_credential_exfiltration(parts):
        return True
    for heredoc_payload in _shell_heredoc_payloads(normalized):
        if _text_contains_credential_exfiltration(heredoc_payload):
            return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_shell_credential_exfiltration(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _contains_shell_credential_exfiltration(
            substitution_payload,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_shell_credential_exfiltration(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_shell_credential_exfiltration(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _shell_segments_contain_credential_exfiltration(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if command_name in _BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS:
            continue
        if _text_contains_credential_exfiltration(" ".join(segment[command_index:])):
            return True
    return False


def _text_contains_credential_exfiltration(text: str) -> bool:
    if not _SECRET_EXFILTRATION_SECRET_PATTERN.search(text):
        return False
    if not _SECRET_EXFILTRATION_NETWORK_PATTERN.search(text):
        return False
    return _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(text) is not None


def _contains_encoded_or_encrypted_shell_command(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    executable_surface = _shell_text_without_quoted_literals(normalized)
    if any(pattern.search(executable_surface) for pattern in _ENCODED_EXECUTION_PATTERNS):
        return True
    if _contains_command_substitution_decode_exec(normalized):
        return True
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    for payload in _decoded_shell_payloads(executable_surface):
        if _decoded_payload_looks_sensitive(
            payload,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_encoded_or_encrypted_shell_command(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_encoded_or_encrypted_shell_command(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_encoded_or_encrypted_shell_command(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _contains_command_substitution_decode_exec(command_text: str) -> bool:
    substitution_payloads = _shell_command_substitution_payloads(command_text)
    if not substitution_payloads:
        return False
    if not any(_contains_decode_primitive(payload) for payload in substitution_payloads):
        return False
    lowered = command_text.lower()
    if re.search(r"\b(?:ash|bash|dash|sh|zsh)\b[^\n;|&]*-[A-Za-z]*c[A-Za-z]*", lowered):
        return True
    return bool(re.search(r"\beval\b[^\n;|&]*\$\(", lowered))


def _contains_shell_network_file_upload(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    if _curl_stdin_config_uses_file_upload(normalized, parts, cwd=cwd, home_dir=home_dir):
        return True
    for pipeline in _iter_shell_pipelines(parts):
        for index, segment in enumerate(pipeline):
            if _segment_uses_network_file_upload(
                segment,
                cwd=cwd,
                home_dir=home_dir,
                stdin_uses_local_file=_shell_pipeline_stdin_uses_local_file(
                    pipeline,
                    index,
                    cwd=cwd,
                    home_dir=home_dir,
                ),
            ):
                return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_shell_network_file_upload(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _contains_shell_network_file_upload(
            substitution_payload,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_shell_network_file_upload(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_shell_network_file_upload(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _segment_uses_network_file_upload(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    stdin_uses_local_file: bool = False,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    segment_args = segment[command_index + 1 :]
    if command_name == "curl":
        return _curl_segment_uses_file_upload(
            segment_args,
            cwd=cwd,
            home_dir=home_dir,
            stdin_uses_local_file=stdin_uses_local_file,
        )
    if command_name == "wget":
        return _wget_segment_uses_file_upload(segment_args, stdin_uses_local_file=stdin_uses_local_file)
    return False


def _curl_segment_uses_file_upload(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    visited_config_paths: frozenset[str] = frozenset(),
    stdin_config_payloads: tuple[tuple[str, Path | None], ...] = (),
    stdin_uses_local_file: bool = False,
) -> bool:
    index = 0
    saw_variable_file_input = False
    saw_variable_expansion = False
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            break
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _curl_config_uses_file_upload(
                value,
                cwd=cwd,
                home_dir=home_dir,
                visited_config_paths=visited_config_paths,
                stdin_config_payloads=stdin_config_payloads,
            ):
                return True
            index += 2
            continue
        if (
            token in _CURL_AT_FILE_FLAGS_WITH_VALUE
            or token in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE
            or token in _CURL_FORM_FLAGS_WITH_VALUE
            or token in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE
        ):
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _curl_upload_value_uses_local_file(token, value, stdin_uses_local_file=stdin_uses_local_file):
                return True
            index += 2
            continue
        if token in _CURL_VARIABLE_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            saw_variable_file_input = saw_variable_file_input or _curl_variable_value_uses_local_file(value)
            index += 2
            continue
        if token in _CURL_EXPAND_FLAGS_WITH_VALUE:
            saw_variable_expansion = True
            index += 2
            continue
        if token.startswith("--config=") and _curl_config_uses_file_upload(
            token.split("=", 1)[1],
            cwd=cwd,
            home_dir=home_dir,
            visited_config_paths=visited_config_paths,
            stdin_config_payloads=stdin_config_payloads,
        ):
            return True
        if token.startswith("--data=") and _curl_upload_value_uses_local_file(
            "--data",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-ascii=") and _curl_upload_value_uses_local_file(
            "--data-ascii",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-binary=") and _curl_upload_value_uses_local_file(
            "--data-binary",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--json=") and _curl_upload_value_uses_local_file(
            "--json",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--url-query=") and _curl_upload_value_uses_local_file(
            "--url-query",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-urlencode=") and _curl_upload_value_uses_local_file(
            "--data-urlencode",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-raw=") and _curl_upload_value_uses_local_file(
            "--data-raw",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--form=") and _curl_upload_value_uses_local_file(
            "--form",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--upload-file=") and _curl_upload_value_uses_local_file(
            "--upload-file",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--variable="):
            saw_variable_file_input = saw_variable_file_input or _curl_variable_value_uses_local_file(
                token.split("=", 1)[1]
            )
            index += 1
            continue
        if token.startswith("--expand-"):
            saw_variable_expansion = True
            index += 1
            continue
        clustered_tokens_consumed = _curl_clustered_short_flag_tokens_consumed(segment_args, index)
        clustered_upload_value = _curl_clustered_short_flag_value(segment_args, index, "T")
        if clustered_upload_value is not None and _curl_upload_value_uses_local_file(
            "-T",
            clustered_upload_value,
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        clustered_config_value = _curl_clustered_short_flag_value(segment_args, index, "K")
        if clustered_config_value is not None and _curl_config_uses_file_upload(
            clustered_config_value,
            cwd=cwd,
            home_dir=home_dir,
            visited_config_paths=visited_config_paths,
            stdin_config_payloads=stdin_config_payloads,
        ):
            return True
        clustered_form_value = _curl_clustered_short_flag_value(segment_args, index, "F")
        if clustered_form_value is not None and _curl_upload_value_uses_local_file("-F", clustered_form_value):
            return True
        clustered_data_value = _curl_clustered_short_flag_value(segment_args, index, "d")
        if clustered_data_value is not None and _curl_upload_value_uses_local_file(
            "-d",
            clustered_data_value,
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        index += clustered_tokens_consumed
    return saw_variable_file_input and saw_variable_expansion


def _curl_stdin_config_uses_file_upload(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    heredoc_payloads = _shell_heredoc_payloads(command_text)
    for pipeline in _iter_shell_pipelines(parts):
        for index, segment in enumerate(pipeline):
            command_name, command_index = _shell_segment_primary_command(segment)
            if command_name != "curl" or command_index is None:
                continue
            segment_args = segment[command_index + 1 :]
            pipeline_stdin_payloads = _shell_pipeline_stdin_payloads(
                pipeline,
                index,
                cwd=cwd,
                home_dir=home_dir,
            )
            pipeline_stdin_uses_local_file = _shell_pipeline_stdin_uses_local_file(
                pipeline,
                index,
                cwd=cwd,
                home_dir=home_dir,
            )
            if pipeline_stdin_payloads and _curl_segment_uses_file_upload(
                segment_args,
                cwd=cwd,
                home_dir=home_dir,
                stdin_config_payloads=pipeline_stdin_payloads,
                stdin_uses_local_file=pipeline_stdin_uses_local_file,
            ):
                return True
            if (
                heredoc_payloads
                and not pipeline_stdin_payloads
                and _curl_segment_reads_config_from_stdin(segment_args)
                and _command_uses_curl_stdin_heredoc(command_text)
                and _curl_segment_uses_file_upload(
                    segment_args,
                    cwd=cwd,
                    home_dir=home_dir,
                    stdin_config_payloads=tuple((payload, cwd) for payload in heredoc_payloads),
                )
            ):
                return True
    return False


def _curl_segment_reads_config_from_stdin(segment_args: list[str]) -> bool:
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            return False
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _strip_cli_value(value) == "-":
                return True
            index += 2
            continue
        if token.startswith("--config=") and _strip_cli_value(token.split("=", 1)[1]) == "-":
            return True
        clustered_config_value = _curl_clustered_short_flag_value(segment_args, index, "K")
        if clustered_config_value is not None and _strip_cli_value(clustered_config_value) == "-":
            return True
        index += 1
    return False


def _curl_inline_config_text_uses_file_upload(config_text: str, *, cwd: Path | None, home_dir: Path | None) -> bool:
    if not config_text or len(config_text.encode("utf-8", errors="ignore")) > _MAX_DECODED_PAYLOAD_BYTES:
        return False
    config_args = _curl_config_arguments(config_text)
    if not config_args:
        return False
    return _curl_segment_uses_file_upload(config_args, cwd=cwd, home_dir=home_dir)


def _shell_pipeline_stdin_uses_local_file(
    pipeline: list[list[str]],
    index: int,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    stdin_uses_local_file = False
    for upstream_segment in pipeline[:index]:
        stdin_uses_local_file = _shell_segment_stdout_uses_local_file(
            upstream_segment,
            stdin_uses_local_file=stdin_uses_local_file,
            cwd=cwd,
            home_dir=home_dir,
        )
    return stdin_uses_local_file or _shell_stdin_redirect_uses_local_file(
        pipeline[index],
        cwd=cwd,
        home_dir=home_dir,
    )


def _shell_pipeline_stdin_payloads(
    pipeline: list[list[str]],
    index: int,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: tuple[tuple[str, Path | None], ...] = ()
    for upstream_segment in pipeline[:index]:
        payloads = _shell_segment_stdout_payloads(
            upstream_segment,
            stdin_payloads=payloads,
            cwd=cwd,
            home_dir=home_dir,
        )
    current_redirect_payloads = _shell_stdin_redirect_payloads(pipeline[index], cwd=cwd, home_dir=home_dir)
    return current_redirect_payloads or payloads


def _shell_stdout_payloads(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[tuple[str, Path | None], ...]:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return ()
    segment_args = segment[command_index + 1 :]
    if command_name == "printf":
        payloads = _printf_stdout_payloads(segment_args)
        return tuple((payload, cwd) for payload in payloads)
    if command_name == "echo":
        payload = _echo_stdout_payload(segment_args)
        return ((payload, cwd),) if payload else ()
    if command_name == "cat":
        return _cat_stdout_payloads(segment_args, cwd=cwd, home_dir=home_dir)
    return ()


def _shell_segment_stdout_payloads(
    segment: list[str],
    *,
    stdin_payloads: tuple[tuple[str, Path | None], ...],
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[tuple[str, Path | None], ...]:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return stdin_payloads
    segment_args = segment[command_index + 1 :]
    redirected_input_payloads = _shell_stdin_redirect_payloads(segment, cwd=cwd, home_dir=home_dir)
    effective_input_payloads = redirected_input_payloads or stdin_payloads
    if command_name == "printf":
        payloads = _printf_stdout_payloads(segment_args)
        return tuple((payload, cwd) for payload in payloads)
    if command_name == "echo":
        payload = _echo_stdout_payload(segment_args)
        return ((payload, cwd),) if payload else ()
    if command_name == "cat":
        return _cat_stdout_payloads(segment_args, cwd=cwd, home_dir=home_dir) or effective_input_payloads
    if command_name in {"sed", "tr"}:
        return effective_input_payloads
    return ()


def _shell_stdout_uses_local_file(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name != "cat" or command_index is None:
        return False
    return _cat_reads_local_file(segment[command_index + 1 :], cwd=cwd, home_dir=home_dir)


def _shell_segment_stdout_uses_local_file(
    segment: list[str],
    *,
    stdin_uses_local_file: bool,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return stdin_uses_local_file
    if _shell_stdin_redirect_uses_local_file(segment, cwd=cwd, home_dir=home_dir):
        return True
    segment_args = segment[command_index + 1 :]
    if command_name == "cat":
        return _cat_reads_local_file(segment_args, cwd=cwd, home_dir=home_dir) or stdin_uses_local_file
    if command_name in {"echo", "printf"}:
        return False
    return stdin_uses_local_file


def _printf_stdout_payloads(segment_args: list[str]) -> tuple[str, ...]:
    args = list(segment_args)
    if args and args[0] == "--":
        args = args[1:]
    decoded_args = tuple(decoded for decoded in (_decode_shell_text_literal(arg) for arg in args) if decoded)
    if not decoded_args:
        return ()
    if len(decoded_args) == 1:
        return decoded_args
    return (*decoded_args, "\n".join(decoded_args))


def _echo_stdout_payload(segment_args: list[str]) -> str | None:
    args = list(segment_args)
    while args and args[0] in {"-n", "-e", "-E"}:
        args = args[1:]
    if not args:
        return None
    decoded_parts = [decoded for decoded in (_decode_shell_text_literal(arg) for arg in args) if decoded]
    if not decoded_parts:
        return None
    return " ".join(decoded_parts)


def _cat_stdout_payloads(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: list[tuple[str, Path | None]] = []
    consume_all = False
    for token in segment_args:
        if token == "--":
            consume_all = True
            continue
        if not consume_all and token.startswith("-"):
            continue
        if token == "-":
            continue
        config_path = _resolved_runtime_path(token, cwd=cwd, home_dir=home_dir)
        payload_text = _read_small_runtime_text_file(config_path)
        if payload_text is None:
            continue
        payloads.append((payload_text, config_path.parent))
    return tuple(payloads)


def _cat_reads_local_file(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    consume_all = False
    for token in segment_args:
        if token == "--":
            consume_all = True
            continue
        if not consume_all and token.startswith("-"):
            continue
        if token == "-":
            continue
        if _looks_like_local_stdin_source(token):
            return True
    return False


def _shell_stdin_redirect_payloads(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: list[tuple[str, Path | None]] = []
    index = 0
    while index < len(segment):
        token = segment[index]
        if token == "<<<" and index + 1 < len(segment):
            payload_text = _decode_shell_text_literal(segment[index + 1])
            if payload_text:
                payloads.append((payload_text, cwd))
            index += 2
            continue
        if token.startswith("<<<"):
            payload_text = _decode_shell_text_literal(token[3:])
            if payload_text:
                payloads.append((payload_text, cwd))
            index += 1
            continue
        redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
            token,
            next_token=segment[index + 1] if index + 1 < len(segment) else None,
        )
        if redirect_target is not None:
            redirect_payload = _stdin_redirect_payload(redirect_target, cwd=cwd, home_dir=home_dir)
            if redirect_payload is not None:
                payloads.append(redirect_payload)
            index += tokens_consumed
            continue
        index += 1
    return tuple(payloads)


def _shell_stdin_redirect_uses_local_file(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    index = 0
    while index < len(segment):
        token = segment[index]
        if token == "<" and index + 1 < len(segment):
            if _stdin_redirect_uses_local_file(segment[index + 1], cwd=cwd, home_dir=home_dir):
                return True
            index += 2
            continue
        redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
            token,
            next_token=segment[index + 1] if index + 1 < len(segment) else None,
        )
        if redirect_target is not None and _stdin_redirect_uses_local_file(
            redirect_target,
            cwd=cwd,
            home_dir=home_dir,
        ):
            return True
        index += tokens_consumed if redirect_target is not None else 1
    return False


def _stdin_redirect_payload(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[str, Path | None] | None:
    config_path = _resolved_runtime_path(target, cwd=cwd, home_dir=home_dir)
    payload_text = _read_small_runtime_text_file(config_path)
    if payload_text is None:
        return None
    return payload_text, config_path.parent


def _stdin_redirect_uses_local_file(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    return _looks_like_local_stdin_source(target)


def _looks_like_local_stdin_source(value: str) -> bool:
    stripped_value = _strip_cli_value(value).lower()
    return bool(
        stripped_value
        and stripped_value not in {"-", "@-"}
        and stripped_value not in _SAFE_SHELL_REDIRECT_TARGETS
        and not stripped_value.startswith("&")
    )


def _stdin_redirect_target_from_token(token: str, *, next_token: str | None) -> tuple[str | None, int]:
    if token.startswith("<<"):
        return None, 1
    if token in {"<", "0<"}:
        if next_token is None:
            return None, 1
        return next_token, 2
    match = re.fullmatch(r"(?P<fd>\d*)<(?P<target>.+)", token)
    if match is None or match.group("fd") not in {"", "0"}:
        return None, 1
    return match.group("target"), 1


def _decode_shell_text_literal(value: str) -> str | None:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return None
    try:
        return bytes(stripped_value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return stripped_value


def _wget_segment_uses_file_upload(segment_args: list[str], *, stdin_uses_local_file: bool = False) -> bool:
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            return False
        if token in _WGET_UPLOAD_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _direct_file_operand_uses_local_file(value, stdin_uses_local_file=stdin_uses_local_file):
                return True
            index += 2
            continue
        if token.startswith("--body-file=") and _direct_file_operand_uses_local_file(
            token.split("=", 1)[1], stdin_uses_local_file=stdin_uses_local_file
        ):
            return True
        if token.startswith("--post-file=") and _direct_file_operand_uses_local_file(
            token.split("=", 1)[1], stdin_uses_local_file=stdin_uses_local_file
        ):
            return True
        index += 1
    return False


def _curl_upload_value_uses_local_file(flag: str, value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = value.strip()
    if flag in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE:
        return _direct_file_operand_uses_local_file(stripped_value, stdin_uses_local_file=stdin_uses_local_file)
    if flag in _CURL_FORM_FLAGS_WITH_VALUE:
        return _curl_form_value_uses_local_file(stripped_value)
    if flag in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE:
        return _curl_data_urlencode_value_uses_local_file(stripped_value)
    if flag == "--data-raw":
        return False
    return _value_uses_local_file(stripped_value, stdin_uses_local_file=stdin_uses_local_file)


def _curl_form_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    field_value = stripped_value.split("=", 1)[1] if "=" in stripped_value else stripped_value
    if not field_value or field_value[0] not in {"@", "<"}:
        return False
    return _direct_file_operand_uses_local_file(re.split(r"[;,]", field_value[1:], maxsplit=1)[0])


def _curl_data_urlencode_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value.startswith("@"):
        return _value_uses_local_file(stripped_value)
    if "@" not in stripped_value:
        return False
    name, file_candidate = stripped_value.split("@", 1)
    if "=" in name:
        return False
    return _direct_file_operand_uses_local_file(file_candidate)


def _curl_variable_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if "@" not in stripped_value:
        return False
    variable_name, file_candidate = stripped_value.split("@", 1)
    normalized_name = variable_name.lstrip("%")
    if not normalized_name or "=" in normalized_name:
        return False
    return _direct_file_operand_uses_local_file(file_candidate)


def _curl_config_uses_file_upload(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    visited_config_paths: frozenset[str],
    stdin_config_payloads: tuple[tuple[str, Path | None], ...] = (),
) -> bool:
    stripped_value = _strip_cli_value(value)
    if stripped_value == "-":
        return any(
            _curl_inline_config_text_uses_file_upload(payload_text, cwd=payload_cwd, home_dir=home_dir)
            for payload_text, payload_cwd in stdin_config_payloads
        )
    config_file = _resolved_runtime_path(value, cwd=cwd, home_dir=home_dir)
    normalized_config_path = str(config_file)
    if normalized_config_path in visited_config_paths:
        return False
    config_text = _read_small_runtime_text_file(config_file)
    if config_text is None:
        return False
    config_args = _curl_config_arguments(config_text)
    if not config_args:
        return False
    return _curl_segment_uses_file_upload(
        config_args,
        cwd=config_file.parent,
        home_dir=home_dir,
        visited_config_paths=visited_config_paths | frozenset({normalized_config_path}),
        stdin_config_payloads=stdin_config_payloads,
    )


def _curl_config_arguments(config_text: str) -> list[str]:
    arguments: list[str] = []
    for raw_line in config_text.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped_line, comments=True, posix=True)
        except ValueError:
            continue
        if not tokens:
            continue
        if len(tokens) == 1 and not tokens[0].startswith("-") and ":" in tokens[0] and not tokens[0].endswith(":"):
            option_name, option_value = tokens[0].split(":", 1)
            if option_name and option_value:
                tokens = [option_name, option_value]
        if tokens[0].endswith(":"):
            tokens[0] = tokens[0][:-1]
        elif len(tokens) >= 3 and tokens[1] in {"=", ":"}:
            tokens = [tokens[0], *tokens[2:]]
        first_token = tokens[0]
        if not first_token.startswith("-"):
            first_token = f"--{first_token}"
        tokens[0] = first_token
        arguments.extend(tokens)
    return arguments


def _command_uses_curl_stdin_heredoc(command_text: str) -> bool:
    return bool(
        re.search(
            r"\bcurl\b[^\n;|&]*(?:--config(?:=|\s+)-|-K(?:\s+-|-?[^\s;|&]*))[^\n;|&]*<<",
            command_text,
        )
    )


def _shell_heredoc_payloads(command_text: str) -> tuple[str, ...]:
    payloads: list[str] = []
    lines = command_text.splitlines()
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        match = _HEREDOC_PATTERN.search(line)
        if match is None:
            line_index += 1
            continue
        delimiter = match.group(2)
        strip_tabs = line[match.start() :].startswith("<<-")
        body_lines: list[str] = []
        line_index += 1
        while line_index < len(lines):
            candidate_line = lines[line_index]
            normalized_line = candidate_line.lstrip("\t") if strip_tabs else candidate_line
            if normalized_line == delimiter:
                line_index += 1
                break
            body_lines.append(normalized_line if strip_tabs else candidate_line)
            line_index += 1
        payload = "\n".join(body_lines).strip()
        if payload:
            payloads.append(payload)
    return tuple(payloads)


def _curl_clustered_short_flag_value(segment_args: list[str], index: int, flag_character: str) -> str | None:
    token = segment_args[index]
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    cluster = token[1:]
    for flag_index, cluster_flag in enumerate(cluster):
        if cluster_flag == flag_character:
            attached_value = cluster[flag_index + 1 :]
            if attached_value:
                return attached_value
            return segment_args[index + 1] if index + 1 < len(segment_args) else ""
        if cluster_flag in _CURL_SHORT_FLAGS_WITH_VALUES:
            return None
    return None


def _curl_clustered_short_flag_tokens_consumed(segment_args: list[str], index: int) -> int:
    token = segment_args[index]
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return 1
    cluster = token[1:]
    for flag_index, cluster_flag in enumerate(cluster):
        if cluster_flag not in _CURL_SHORT_FLAGS_WITH_VALUES:
            continue
        attached_value = cluster[flag_index + 1 :]
        if attached_value:
            return 1
        return 2 if index + 1 < len(segment_args) else 1
    return 1


def _direct_file_operand_uses_local_file(value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value in {"-", "@-"}:
        return stdin_uses_local_file
    return True


def _strip_cli_value(value: str) -> str:
    return value.strip().strip("'").strip('"')


def _value_uses_local_file(value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value == "@-":
        return stdin_uses_local_file
    if stripped_value.startswith("@"):
        return stripped_value[1:] != "-"
    return False


def _contains_decode_primitive(command_text: str) -> bool:
    lowered = command_text.lower()
    return bool(
        re.search(r"\bbase64\b(?=[^\n|;]*\s(?:--decode|-[A-Za-z]*[dD][A-Za-z]*))", lowered)
        or re.search(r"\bxxd\s+(?:-r\s+-p|-rp)\b", lowered)
        or re.search(r"\bopenssl\s+enc\b[^\n|;]*\s-(?:d|decrypt)\b", lowered)
        or re.search(r"\b(?:gpg|gpg2)\b[^\n|;]*(?:--decrypt|-d)\b", lowered)
    )


def _shell_text_without_quoted_literals(command_text: str) -> str:
    characters: list[str] = []
    index = 0
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        character = command_text[index]
        if single_quoted:
            if character == "'":
                single_quoted = False
            characters.append(" ")
            index += 1
            continue
        if double_quoted:
            if character == "\\":
                characters.append(" ")
                if index + 1 < len(command_text):
                    characters.append(" ")
                    index += 2
                else:
                    index += 1
                continue
            if character == '"':
                double_quoted = False
                characters.append(" ")
                index += 1
                continue
            if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
                payload, next_index = _read_command_substitution(command_text, index + 2)
                characters.append(f"$({payload})")
                index = next_index
                continue
            if character == "`":
                payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
                characters.append(f"`{payload}`")
                index = next_index
                continue
            characters.append(" ")
            index += 1
            continue
        if character == "'":
            single_quoted = True
            characters.append(" ")
            index += 1
            continue
        if character == '"':
            double_quoted = True
            characters.append(" ")
            index += 1
            continue
        characters.append(character)
        index += 1
    return "".join(characters)


def _shell_command_substitution_payloads(command_text: str) -> tuple[str, ...]:
    payloads: list[str] = []
    index = 0
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        if single_quoted:
            if command_text[index] == "'":
                single_quoted = False
            index += 1
            continue
        if double_quoted:
            if command_text[index] == "\\" and index + 1 < len(command_text):
                index += 2
                continue
            if command_text[index] == '"':
                double_quoted = False
                index += 1
                continue
            if command_text[index] == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
                payload, next_index = _read_command_substitution(command_text, index + 2)
                if payload.strip():
                    payloads.append(payload)
                index = next_index
                continue
            if command_text[index] == "`":
                payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
                if payload.strip():
                    payloads.append(payload)
                index = next_index
                continue
            index += 1
            continue
        if command_text[index] == "\\" and index + 1 < len(command_text):
            index += 2
            continue
        if command_text[index] == "'":
            single_quoted = True
            index += 1
            continue
        if command_text[index] == '"':
            double_quoted = True
            index += 1
            continue
        if command_text[index] == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            payload, next_index = _read_command_substitution(command_text, index + 2)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        if command_text[index] in "<>" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            payload, next_index = _read_command_substitution(command_text, index + 2)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        if command_text[index] == "`":
            payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        index += 1
    return tuple(payloads)


def _read_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    index = start_index
    depth = 1
    payload_characters: list[str] = []
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        character = command_text[index]
        if single_quoted:
            payload_characters.append(character)
            if character == "'":
                single_quoted = False
            index += 1
            continue
        if double_quoted:
            payload_characters.append(character)
            if character == "\\" and index + 1 < len(command_text):
                payload_characters.append(command_text[index + 1])
                index += 2
                continue
            if character == '"':
                double_quoted = False
            index += 1
            continue
        if character == "'":
            single_quoted = True
            payload_characters.append(character)
            index += 1
            continue
        if character == '"':
            double_quoted = True
            payload_characters.append(character)
            index += 1
            continue
        if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            nested_payload, next_index = _read_command_substitution(command_text, index + 2)
            payload_characters.append(f"$({nested_payload})")
            index = next_index
            continue
        if character == "(":
            depth += 1
            payload_characters.append(character)
            index += 1
            continue
        if character == ")":
            depth -= 1
            if depth == 0:
                return "".join(payload_characters), index + 1
            payload_characters.append(character)
            index += 1
            continue
        payload_characters.append(character)
        index += 1
    return "".join(payload_characters), index


def _read_backtick_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    index = start_index
    payload_characters: list[str] = []
    while index < len(command_text):
        character = command_text[index]
        if character == "\\" and index + 1 < len(command_text):
            payload_characters.append(character)
            payload_characters.append(command_text[index + 1])
            index += 2
            continue
        if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            nested_payload, next_index = _read_command_substitution(command_text, index + 2)
            payload_characters.append(f"$({nested_payload})")
            index = next_index
            continue
        if character == "`":
            return "".join(payload_characters), index + 1
        payload_characters.append(character)
        index += 1
    return "".join(payload_characters), index


def _decoded_payload_looks_sensitive(
    payload: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    depth: int,
    visited_script_paths: frozenset[str],
) -> bool:
    lowered = payload.lower()
    if _looks_destructive_shell_command(payload):
        return True
    if any(token in lowered for token in _SENSITIVE_DECODED_PAYLOAD_TOKENS):
        return True
    return _contains_encoded_or_encrypted_shell_command(
        payload,
        cwd=cwd,
        home_dir=home_dir,
        depth=depth,
        visited_script_paths=visited_script_paths,
    )


def _decoded_shell_payloads(command_text: str) -> tuple[str, ...]:
    lowered = command_text.lower()
    payloads: list[str] = []
    if any(
        token in lowered
        for token in ("base64", "b64decode", "frombase64string", "-encodedcommand", " -enc ", "openssl", "gpg")
    ):
        for literal in _BASE64_LITERAL_PATTERN.findall(command_text):
            decoded = _decode_base64_literal(literal)
            if decoded is not None:
                payloads.append(decoded)
    if "xxd" in lowered:
        for literal in _HEX_LITERAL_PATTERN.findall(command_text):
            decoded = _decode_hex_literal(literal)
            if decoded is not None:
                payloads.append(decoded)
    return tuple(payloads)


def _decode_base64_literal(literal: str) -> str | None:
    try:
        decoded_bytes = base64.b64decode(literal, validate=True)
    except binascii.Error:
        return None
    return _decoded_bytes_to_text(decoded_bytes)


def _decode_hex_literal(literal: str) -> str | None:
    if len(literal) % 2 != 0:
        return None
    try:
        decoded_bytes = binascii.unhexlify(literal)
    except binascii.Error:
        return None
    return _decoded_bytes_to_text(decoded_bytes)


def _decoded_bytes_to_text(decoded_bytes: bytes) -> str | None:
    if not decoded_bytes or len(decoded_bytes) > _MAX_DECODED_PAYLOAD_BYTES:
        return None
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = decoded_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _text_is_probably_source(text):
            return text
    return None


def _text_is_probably_source(text: str) -> bool:
    if not text.strip():
        return False
    printable = sum(1 for character in text if character.isprintable() or character in "\n\r\t")
    return printable / len(text) >= 0.85


def _local_shell_script_payloads(
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    visited_script_paths: frozenset[str],
) -> tuple[tuple[str, Path | None, str], ...]:
    payloads: list[tuple[str, Path | None, str]] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_index is None:
            continue
        script_path = _shell_script_path_for_segment(segment, command_name=command_name, command_index=command_index)
        if script_path is None:
            continue
        normalized_script_path = _normalize_path(_expand_home(script_path, home_dir), cwd)
        if normalized_script_path in visited_script_paths:
            continue
        script_file = Path(normalized_script_path)
        script_text = _read_small_runtime_text_file(script_file)
        if script_text is None:
            continue
        payloads.append((script_text, script_file.parent, normalized_script_path))
    return tuple(payloads)


def _shell_script_path_for_segment(
    segment: list[str],
    *,
    command_name: str | None,
    command_index: int,
) -> str | None:
    if command_name in _SHELL_SCRIPT_INTERPRETER_COMMANDS:
        return _shell_script_path_from_segment(segment[command_index + 1 :])
    command_token = segment[command_index].strip()
    if not command_token or command_token.startswith("-") or _SHELL_ASSIGNMENT_PATTERN.match(command_token):
        return None
    if not _is_explicit_shell_script_path_token(command_token):
        return None
    return command_token


def _shell_script_path_from_segment(segment_args: list[str]) -> str | None:
    index = 0
    while index < len(segment_args):
        token = segment_args[index].strip()
        if not token:
            index += 1
            continue
        if token == "--":
            index += 1
            break
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            index += 1
            continue
        if token == "-s":
            return None
        if token.startswith("-") and not token.startswith("--") and "c" in token[1:]:
            return None
        if not token.startswith("-") and not token.startswith("+"):
            return token
        if token in {"-c", "--command"} or token.startswith(("-c", "--command=")):
            return None
        if token in {"-O", "-o", "+O", "+o", "--rcfile", "--init-file"}:
            index += 2
            continue
        if token.startswith(("--rcfile=", "--init-file=")):
            index += 1
            continue
        index += 1
    while index < len(segment_args):
        token = segment_args[index].strip()
        if token:
            return token
        index += 1
    return None


def _is_explicit_shell_script_path_token(token: str) -> bool:
    normalized_token = token.strip()
    if not normalized_token:
        return False
    return (
        normalized_token.startswith((".", "/", "~"))
        or normalized_token.startswith("../")
        or normalized_token.startswith("./")
        or "/" in normalized_token
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
            "action_class": request.action_class,
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


def _resolved_runtime_path(value: str, *, cwd: Path | None, home_dir: Path | None) -> Path:
    stripped_value = _strip_cli_value(value)
    expanded_value = _expand_home(stripped_value, home_dir)
    return Path(_normalize_path(expanded_value, cwd))


def _read_small_runtime_text_file(path: Path) -> str | None:
    try:
        resolved_path = path.resolve(strict=True)
    except OSError:
        return None
    try:
        stat_result = resolved_path.stat()
    except OSError:
        return None
    if not stat.S_ISREG(stat_result.st_mode) or stat_result.st_size > _MAX_DECODED_PAYLOAD_BYTES:
        return None
    try:
        return resolved_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


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
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    lowered = normalized.lower()
    redacted_command_text = _redacted_shell_text_for_command_names(lowered)
    if _contains_mutating_shell_redirection(parts):
        return True
    raw_command_names = list(_shell_command_names(redacted_command_text))
    parsed_command_names = list(_shell_command_names_from_parts(parts))
    if _looks_like_benign_interpreter_wait(normalized, parts, parsed_command_names):
        return False
    if _looks_like_read_only_interpreter_command(normalized, parts, parsed_command_names):
        return False
    if _contains_unmodeled_inline_interpreter_eval(normalized, parts, parsed_command_names):
        return True
    if _contains_destructive_node_inline_eval(parts):
        return True
    if _contains_destructive_git_command(parts):
        return True
    command_names = list(raw_command_names)
    command_names.extend(_shell_command_names_from_parts(parts))
    if any(command_name in _DESTRUCTIVE_SHELL_COMMANDS for command_name in command_names):
        return True
    if _find_command_uses_delete(parts):
        return True
    for env_split_string in _env_split_string_payloads(parts):
        if _looks_destructive_shell_command(env_split_string):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _looks_destructive_shell_command(shell_script):
            return True
    return any(
        command_name == "sed" and any(part == "-i" or part.startswith("-i") for part in parts[1:])
        for command_name in command_names
    )


def _contains_destructive_node_inline_eval(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "node" or command_index is None:
            continue
        if _segment_contains_destructive_node_inline_eval(segment[command_index + 1 :]):
            return True
    return False


def _contains_destructive_node_inline_script(script: str) -> bool:
    redacted_script = _redacted_node_inline_string_literals(script)
    member_scan_script = _redacted_node_inline_string_literals(script, preserve_bracket_member_strings=True)
    for call_name in _DESTRUCTIVE_NODE_INLINE_CALLS:
        escaped_call_name = re.escape(call_name)
        if re.search(rf"(?<![A-Za-z0-9_$'\"]){escaped_call_name}\s*(?:\?\.\s*)?\(", redacted_script):
            return True
        for base_pattern in (
            rf"\.\s*{escaped_call_name}",
            rf"\[\s*['\"]{escaped_call_name}['\"]\s*\]",
        ):
            if re.search(rf"{base_pattern}\s*(?:\?\.\s*)?(?:\)\s*)?\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*call\s*\(", member_scan_script):
                return True
            if re.search(rf"{base_pattern}\s*(?:\?\s*)?\.\s*apply\s*\(", member_scan_script):
                return True
    return False


def _is_combined_node_inline_eval_flag(token: str) -> bool:
    return token in {"-pe", "-ep"}


def _find_command_uses_delete(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "find" or command_index is None:
            continue
        if _find_segment_uses_delete(segment[command_index + 1 :]):
            return True
    return False


def _iter_shell_command_segments(parts: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current_segment: list[str] = []
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in _SHELL_COMMAND_SEPARATORS:
            if current_segment:
                segments.append(current_segment)
                current_segment = []
            continue
        current_segment.append(token)
    if current_segment:
        segments.append(current_segment)
    return segments


def _iter_shell_pipelines(parts: list[str]) -> list[list[list[str]]]:
    pipelines: list[list[list[str]]] = []
    current_pipeline: list[list[str]] = []
    current_segment: list[str] = []
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in {"|", "|&"}:
            if current_segment:
                current_pipeline.append(current_segment)
                current_segment = []
            continue
        if token in _SHELL_COMMAND_SEPARATORS:
            if current_segment:
                current_pipeline.append(current_segment)
                current_segment = []
            if current_pipeline:
                pipelines.append(current_pipeline)
                current_pipeline = []
            continue
        current_segment.append(token)
    if current_segment:
        current_pipeline.append(current_segment)
    if current_pipeline:
        pipelines.append(current_pipeline)
    return pipelines


def _shell_segment_primary_command(segment: list[str]) -> tuple[str | None, int | None]:
    index = 0
    while index < len(segment):
        redirect_tokens_consumed = _leading_shell_redirection_tokens_consumed(
            segment,
            index,
        )
        if redirect_tokens_consumed > 0:
            index += redirect_tokens_consumed
            continue
        normalized_token = segment[index].lstrip("(").rstrip(")")
        if _SHELL_ASSIGNMENT_PATTERN.match(normalized_token):
            index += 1
            continue
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name == "env":
            index += 1
            while index < len(segment):
                token = segment[index]
                if not token.startswith("-") and not _SHELL_ASSIGNMENT_PATTERN.match(token):
                    break
                tokens_consumed = _wrapper_option_tokens_consumed(command_name, token)
                index += tokens_consumed
                continue
            continue
        if command_name in _SHELL_COMMAND_WRAPPERS:
            index += 1
            while index < len(segment):
                token = segment[index]
                if not token.startswith("-"):
                    break
                index += _wrapper_option_tokens_consumed(command_name, token)
            continue
        return command_name, index
    return None, None


def _leading_shell_redirection_tokens_consumed(segment: list[str], index: int) -> int:
    token = segment[index]
    redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
        token,
        next_token=segment[index + 1] if index + 1 < len(segment) else None,
    )
    if redirect_target is not None:
        return tokens_consumed
    if token in {"<<", "<<-", "<<<"}:
        return 2 if index + 1 < len(segment) else 1
    if token in {">", ">>", ">|", "0>", "0>>", "0>|", "1>", "1>>", "1>|", "2>", "2>>", "2>|"}:
        return 2 if index + 1 < len(segment) else 1
    if re.fullmatch(r"(?P<fd>[0-2]?)(?P<op>>\||>>|>)(?P<target>.+)", token):
        return 1
    return 0


def _segment_contains_destructive_node_inline_eval(segment_args: list[str]) -> bool:
    lowered_args = [arg.lower() for arg in segment_args]
    index = 0
    while index < len(lowered_args):
        token = lowered_args[index]
        if token == "--":
            break
        if token in _NODE_INLINE_EVAL_FLAGS and index + 1 < len(lowered_args):
            if token in {"-p", "--print"} and lowered_args[index + 1].startswith("-"):
                index += 1
                continue
            if _contains_destructive_node_inline_script(segment_args[index + 1]):
                return True
            index += 2
            continue
        if _is_combined_node_inline_eval_flag(token) and index + 1 < len(lowered_args):
            if _contains_destructive_node_inline_script(segment_args[index + 1]):
                return True
            index += 2
            continue
        if token.startswith("--eval="):
            if _contains_destructive_node_inline_script(segment_args[index].split("=", 1)[1]):
                return True
            index += 1
            continue
        if token.startswith("--print="):
            if _contains_destructive_node_inline_script(segment_args[index].split("=", 1)[1]):
                return True
            index += 1
            continue
        if token.startswith("-e") and token not in _NODE_INLINE_EVAL_FLAGS:
            if _contains_destructive_node_inline_script(segment_args[index][2:]):
                return True
            index += 1
            continue
        if token.startswith("-p") and token not in _NODE_INLINE_EVAL_FLAGS:
            if _contains_destructive_node_inline_script(segment_args[index][2:]):
                return True
            index += 1
            continue
        if token in _NODE_OPTION_FLAGS_WITH_VALUE and index + 1 < len(lowered_args):
            index += 2
            continue
        if not token.startswith("-"):
            break
        index += 1
    return False


def _find_segment_uses_delete(segment_args: list[str]) -> bool:
    value_taking_predicates = {
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-wholename",
        "-iwholename",
        "-regex",
        "-iregex",
        "-lname",
        "-ilname",
    }
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token in {"-exec", "-execdir", "-ok", "-okdir"}:
            index += 1
            if index < len(segment_args):
                command_name = _normalized_shell_command_name(segment_args[index])
                if command_name in _DESTRUCTIVE_SHELL_COMMANDS:
                    return True
            while index < len(segment_args) and segment_args[index] not in {";", "+"}:
                index += 1
            if index < len(segment_args):
                index += 1
            continue
        if token in value_taking_predicates and index + 1 < len(segment_args):
            index += 2
            continue
        if token == "-delete":
            return True
        index += 1
    return False


def _contains_destructive_git_command(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "git" or command_index is None:
            continue
        if _segment_uses_destructive_git_command(segment[command_index + 1 :]):
            return True
    return False


def _segment_uses_destructive_git_command(segment_args: list[str]) -> bool:
    subcommand_index = 0
    while subcommand_index < len(segment_args):
        token = segment_args[subcommand_index]
        if token == "--":
            subcommand_index += 1
            continue
        if token in {"-h", "--help", "--version"}:
            return False
        if token in _GIT_GLOBAL_OPTIONS_WITH_VALUE and subcommand_index + 1 < len(segment_args):
            subcommand_index += 2
            continue
        if any(token.startswith(f"{option}=") for option in _GIT_GLOBAL_OPTIONS_WITH_VALUE if option.startswith("--")):
            subcommand_index += 1
            continue
        if token.startswith("-"):
            subcommand_index += 1
            continue
        normalized_token = token.strip().lower()
        if normalized_token == "help":
            return False
        return normalized_token in _DESTRUCTIVE_GIT_SUBCOMMANDS
    return False


def _env_split_string_payloads(parts: list[str]) -> tuple[str, ...]:
    payloads: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        env_index = _shell_segment_env_index(segment)
        if env_index is None:
            continue
        index = env_index + 1
        while index < len(segment):
            token = segment[index]
            if _SHELL_ASSIGNMENT_PATTERN.match(token):
                index += 1
                continue
            if token == "--":
                break
            if not token.startswith("-"):
                break
            if token in {"-S", "--split-string"} and index + 1 < len(segment):
                payload = segment[index + 1].strip()
                if payload:
                    payloads.append(payload)
                index += _wrapper_option_tokens_consumed("env", token)
                continue
            if token.startswith("--split-string="):
                payload = token.split("=", 1)[1].strip()
                if payload:
                    payloads.append(payload)
                index += _wrapper_option_tokens_consumed("env", token)
                continue
            clustered_split_string_payload = _env_clustered_split_string_payload(token)
            if clustered_split_string_payload is not None:
                payload = clustered_split_string_payload.strip()
                if not payload and index + 1 < len(segment):
                    payload = segment[index + 1].strip()
                if payload:
                    payloads.append(payload)
                index += _wrapper_option_tokens_consumed("env", token)
                continue
            index += _wrapper_option_tokens_consumed("env", token)
    return tuple(payloads)


def _shell_segment_env_index(segment: list[str]) -> int | None:
    index = 0
    while index < len(segment):
        normalized_token = segment[index].lstrip("(").rstrip(")")
        if _SHELL_ASSIGNMENT_PATTERN.match(normalized_token):
            index += 1
            continue
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name == "env":
            return index
        if command_name in _SHELL_COMMAND_WRAPPERS:
            index += 1
            while index < len(segment):
                token = segment[index]
                if not token.startswith("-"):
                    break
                index += _wrapper_option_tokens_consumed(command_name, token)
            continue
        return None
    return None


def _contains_mutating_shell_redirection(parts: list[str]) -> bool:
    index = 0
    while index < len(parts):
        token = parts[index].strip()
        if not token:
            index += 1
            continue
        fd = ""
        target: str | None = None
        if token in {">", ">>", ">|", "1>", "1>>", "1>|", "2>", "2>>", "2>|"}:
            if token[0].isdigit():
                fd = token[0]
            if token.endswith(">") and index + 2 < len(parts) and parts[index + 1] == "|":
                target = parts[index + 2]
                index += 3
            elif index + 1 < len(parts):
                target = parts[index + 1]
                index += 2
            else:
                index += 1
        else:
            match = re.fullmatch(r"(?P<prefix>[^<>\s]*?)(?P<fd>[0-2]?)(?P<op>>\||>>|>)(?P<target>.*)", token)
            if match is None:
                index += 1
                continue
            prefix = match.group("prefix") or ""
            if prefix.endswith("="):
                index += 1
                continue
            fd = match.group("fd")
            target = match.group("target")
            if target:
                index += 1
            elif index + 1 < len(parts):
                target = parts[index + 1]
                index += 2
            else:
                index += 1
        if target is None:
            continue
        normalized_target = _normalized_redirect_target(target).lower()
        if fd == "2" and normalized_target in _SAFE_SHELL_REDIRECT_TARGETS:
            continue
        if normalized_target in _SAFE_SHELL_REDIRECT_TARGETS or normalized_target.startswith("&"):
            continue
        return True
    return False


def _normalized_redirect_target(target: str) -> str:
    return target.strip().strip(");,").strip("'\"")


def _redacted_node_inline_string_literals(script: str, *, preserve_bracket_member_strings: bool = False) -> str:
    result: list[str] = []
    quote_char: str | None = None
    escape_next = False
    preserve_string_contents = False
    template_expression_depth = 0
    comment_type: str | None = None
    regex_literal = False
    regex_escape_next = False
    regex_char_class = False
    index = 0
    while index < len(script):
        character = script[index]
        if quote_char is None:
            if template_expression_depth > 0:
                if comment_type == "line":
                    result.append(character)
                    if character in {"\n", "\r"}:
                        comment_type = None
                    index += 1
                    continue
                if comment_type == "block":
                    result.append(character)
                    if character == "/" and result[-2:-1] == ["*"]:
                        comment_type = None
                    index += 1
                    continue
                if regex_literal:
                    result.append(character)
                    if regex_escape_next:
                        regex_escape_next = False
                    elif character == "\\":
                        regex_escape_next = True
                    elif character == "[" and not regex_char_class:
                        regex_char_class = True
                    elif character == "]" and regex_char_class:
                        regex_char_class = False
                    elif character == "/" and not regex_char_class:
                        regex_literal = False
                    index += 1
                    continue
                if character == "/" and index + 1 < len(script):
                    next_character = script[index + 1]
                    if next_character == "/":
                        result.append("//")
                        comment_type = "line"
                        index += 2
                        continue
                    if next_character == "*":
                        result.append("/*")
                        comment_type = "block"
                        index += 2
                        continue
                    if _js_slash_starts_regex(result):
                        result.append(character)
                        regex_literal = True
                        regex_escape_next = False
                        regex_char_class = False
                        index += 1
                        continue
                if character == "{":
                    template_expression_depth += 1
                    result.append(character)
                    index += 1
                    continue
                if character == "}":
                    template_expression_depth -= 1
                    result.append(character)
                    if template_expression_depth == 0:
                        quote_char = "`"
                        comment_type = None
                        regex_literal = False
                        regex_escape_next = False
                        regex_char_class = False
                    index += 1
                    continue
            if character in {"'", '"', "`"}:
                preserve_string_contents = (
                    preserve_bracket_member_strings and _last_non_whitespace_character(result) == "["
                )
                quote_char = character
                result.append(character)
                index += 1
                continue
            result.append(character)
            index += 1
            continue
        if escape_next:
            result.append(character if preserve_string_contents else "Q")
            escape_next = False
            index += 1
            continue
        if character == "\\":
            result.append(character)
            escape_next = True
            index += 1
            continue
        if quote_char == "`" and character == "$" and index + 1 < len(script) and script[index + 1] == "{":
            result.append("${")
            quote_char = None
            preserve_string_contents = False
            template_expression_depth = 1
            index += 2
            continue
        if character == quote_char:
            result.append(character)
            quote_char = None
            preserve_string_contents = False
            index += 1
            continue
        result.append(character if preserve_string_contents else "Q")
        index += 1
    return "".join(result)


def _last_non_whitespace_character(result: list[str]) -> str | None:
    for chunk in reversed(result):
        for character in reversed(chunk):
            if not character.isspace():
                return character
    return None


def _js_slash_starts_regex(result: list[str]) -> bool:
    previous_character = _last_non_whitespace_character(result)
    if previous_character is None:
        return True
    return previous_character in {
        "(",
        "{",
        "[",
        "=",
        ":",
        ",",
        ";",
        "!",
        "?",
        "|",
        "&",
        "+",
        "-",
        "*",
        "%",
        "^",
        "~",
    }


def _shell_command_names(command_text: str) -> tuple[str, ...]:
    pattern = re.compile(r"(?:^|&&|\|\||[;&|\n])\s*(?:[a-z_][a-z0-9_]*=\S+\s+)*(?P<command>[a-z0-9_./\\\\-]+)")
    return tuple(_normalized_shell_command_name(match.group("command")) for match in pattern.finditer(command_text))


def _normalized_shell_command_name(command_name: str) -> str:
    normalized_command = command_name.replace("\\", "/").strip()
    if "/" not in normalized_command:
        return normalized_command.lower()
    return normalized_command.rsplit("/", 1)[-1].lower()


def _redacted_shell_text_for_command_names(command_text: str) -> str:
    return re.sub(r"'[^']*'|\"[^\"]*\"", "Q", command_text)


def _split_shell_parts(command_text: str) -> list[str]:
    try:
        lexer = shlex.shlex(
            _replace_unquoted_newlines_with_separators(command_text),
            posix=True,
            punctuation_chars=";&|",
        )
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command_text.split()


def _replace_unquoted_newlines_with_separators(command_text: str) -> str:
    result: list[str] = []
    quote_char: str | None = None
    escape_next = False
    for character in command_text:
        if escape_next:
            result.append(character)
            escape_next = False
            continue
        if character == "\\":
            result.append(character)
            escape_next = True
            continue
        if quote_char is None and character in {"'", '"', "`"}:
            quote_char = character
            result.append(character)
            continue
        if quote_char == character:
            quote_char = None
            result.append(character)
            continue
        if quote_char is None and character in {"\n", "\r"}:
            if not result or result[-1] != " ":
                result.append(" ")
            result.append("\n")
            result.append(_SHELL_NEWLINE_SEPARATOR)
            result.append("\n")
            continue
        result.append(character)
    return "".join(result)


def _wrapper_option_tokens_consumed(command_name: str, token: str) -> int:
    if not token.startswith("-"):
        return 1
    if command_name == "env":
        env_short_option_tokens = _env_short_option_tokens_consumed(token)
        if env_short_option_tokens is not None:
            return env_short_option_tokens
    if command_name == "sudo":
        sudo_short_option_tokens = _sudo_short_option_tokens_consumed(token)
        if sudo_short_option_tokens is not None:
            return sudo_short_option_tokens
    exact_flags = _WRAPPER_FLAGS_WITH_VALUES.get(command_name, frozenset())
    if token in exact_flags:
        return 2
    if _wrapper_flag_has_attached_value(command_name, token):
        return 1
    return 1


def _env_short_option_tokens_consumed(token: str) -> int | None:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "S", "u"}:
            continue
        if index < len(token) - 1:
            return 1
        return 2
    return 1


def _sudo_short_option_tokens_consumed(token: str) -> int | None:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "D", "R", "T", "g", "h", "p", "r", "t", "u"}:
            continue
        if index < len(token) - 1:
            return 1
        return 2
    return 1


def _env_clustered_split_string_payload(token: str) -> str | None:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    split_index = token.find("S", 1)
    if split_index == -1:
        return None
    if split_index + 1 >= len(token):
        return ""
    return token[split_index + 1 :]


def _wrapper_flag_has_attached_value(command_name: str, token: str) -> bool:
    if command_name == "env":
        return any(
            token.startswith(prefix)
            for prefix in (
                "--unset=",
                "--chdir=",
                "--split-string=",
                "-C",
            )
        )
    if command_name == "nice":
        return token.startswith("--adjustment=") or (token.startswith("-n") and token != "-n")
    if command_name == "stdbuf":
        return token.startswith(("--input=", "--output=", "--error=")) or (
            len(token) > 2 and token[:2] in {"-i", "-o", "-e"}
        )
    if command_name == "sudo":
        return token.startswith(
            (
                "--chdir=",
                "--chroot=",
                "--close-from=",
                "--command-timeout=",
                "--group=",
                "--host=",
                "--prompt=",
                "--role=",
                "--type=",
                "--user=",
            )
        ) or _sudo_short_option_has_attached_value(token)
    if command_name == "time":
        return token.startswith(("--format=", "--output=")) or (len(token) > 2 and token[:2] in {"-f", "-o"})
    return False


def _sudo_short_option_has_attached_value(token: str) -> bool:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return False
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "D", "R", "T", "g", "h", "p", "r", "t", "u"}:
            continue
        return index < len(token) - 1
    return False


def _shell_command_names_from_parts(parts: list[str]) -> tuple[str, ...]:
    command_names: list[str] = []
    expect_command = True
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in _SHELL_COMMAND_SEPARATORS:
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
        if normalized_command in {"env", "command", "builtin", "nohup", "nice", "sudo", "time", "stdbuf"}:
            expect_command = True
            continue
        command_names.append(normalized_command)
        expect_command = False
    return tuple(command_names)


def _shell_command_scripts(parts: list[str]) -> tuple[str, ...]:
    scripts: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS or command_index is None:
            continue
        index = command_index + 1
        while index < len(segment):
            flag_payload = _interpreter_flag_payload(segment, index)
            if flag_payload is not None:
                scripts.append(flag_payload.script_text)
                index += flag_payload.tokens_consumed
                continue
            index += 1
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
        if token in _SHELL_COMMAND_SEPARATORS:
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


def _looks_like_read_only_interpreter_command(command_text: str, parts: list[str], command_names: list[str]) -> bool:
    if "$(" in command_text or "`" in command_text or "<(" in command_text or ">(" in command_text:
        return False
    heredoc_script = _single_interpreter_heredoc_script(command_text)
    if heredoc_script is not None:
        heredoc_interpreter = _single_interpreter_heredoc_interpreter(command_text)
        if heredoc_interpreter not in _READ_ONLY_OBSERVER_INTERPRETER_COMMANDS:
            return False
        scripts = list(_script_interpreter_texts(parts))
        if scripts:
            scripts.append(heredoc_script)
            return all(_script_is_read_only_observer(script_text) for script_text in scripts)
        return _script_is_read_only_observer(heredoc_script)
    if not command_names or not all(
        command_name in _READ_ONLY_OBSERVER_INTERPRETER_COMMANDS for command_name in command_names
    ):
        return False
    scripts = list(_script_interpreter_texts(parts))
    scripts.extend(_shell_heredoc_payloads(command_text))
    if not scripts or len(scripts) != len(command_names):
        return False
    return all(_script_is_read_only_observer(script_text) for script_text in scripts)


def _contains_unmodeled_inline_interpreter_eval(
    command_text: str,
    parts: list[str],
    command_names: list[str],
) -> bool:
    heredoc_interpreter = _single_interpreter_heredoc_interpreter(command_text)
    if heredoc_interpreter is not None:
        return heredoc_interpreter in _UNMODELED_INLINE_INTERPRETER_COMMANDS
    if not command_names or not all(command_name in _SCRIPT_INTERPRETER_COMMANDS for command_name in command_names):
        return False
    if not any(command_name in _UNMODELED_INLINE_INTERPRETER_COMMANDS for command_name in command_names):
        return False
    return bool(_script_interpreter_texts(parts) or _shell_heredoc_payloads(command_text))


def _script_is_benign_wait(script_text: str) -> bool:
    normalized_script = script_text.strip()
    if not normalized_script:
        return False
    return bool(
        re.fullmatch(r"sleep\s+\d+(?:\.\d+)?", normalized_script)
        or re.fullmatch(r"(?:import\s+time\s*;\s*)?time\.sleep\(\s*\d+(?:\.\d+)?\s*\)", normalized_script)
    )


def _script_is_read_only_observer(script_text: str) -> bool:
    normalized_script = script_text.strip()
    if not normalized_script:
        return False
    if _script_is_benign_wait(normalized_script):
        return True
    if re.search(r"\bfrom\s+(?:os|pathlib|shutil|subprocess)\s+import\s+[^#\n]*\bas\b", normalized_script):
        return False
    return not any(pattern.search(normalized_script) for pattern in _READ_ONLY_INTERPRETER_MUTATION_PATTERNS)


def _single_interpreter_heredoc_script(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    script_text = match.group("body").strip()
    return script_text or None


def _single_interpreter_heredoc_interpreter(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    interpreter = match.group("interpreter").strip().lower()
    return interpreter or None


@dataclass(frozen=True, slots=True)
class _InterpreterFlagPayload:
    script_text: str
    tokens_consumed: int


def _interpreter_flag_payload(parts: list[str], index: int) -> _InterpreterFlagPayload | None:
    normalized_token = parts[index].strip().lstrip("(").rstrip(")")
    if not normalized_token.startswith("-"):
        return None
    if normalized_token.startswith("--"):
        for long_flag in ("--command", "--eval", "--execute"):
            if normalized_token == long_flag:
                if index + 1 >= len(parts):
                    return None
                next_script = parts[index + 1].strip()
                if not next_script:
                    return None
                return _InterpreterFlagPayload(script_text=next_script, tokens_consumed=2)
            if normalized_token.startswith(f"{long_flag}="):
                attached_script = normalized_token.split("=", 1)[1].strip()
                if not attached_script:
                    return None
                return _InterpreterFlagPayload(script_text=attached_script, tokens_consumed=1)
        return None
    flag_text = normalized_token[1:]
    for flag_index, flag_name in enumerate(flag_text):
        if flag_name not in {"c", "e"}:
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
