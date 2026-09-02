"""Request match models and sensitive path extraction."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from ..actions import GuardActionEnvelope, apply_patch_target_paths
from ..command_model import CanonicalCommand
from ..secret_sensitivity import SecretPathMatch as SensitivePathMatch
from ..secret_sensitivity import classify_secret_path
from .constants_core import _FILE_READ_TOOL_NAMES, _PATH_KEYS, _PATH_LIST_KEYS
from .constants_patterns import _ENCODED_EXECUTION_TARGET_PATTERN
from .tool_action_risk_summaries import tool_action_risk_summary

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
    raw_command_text: str | None = None
    wrapper_chain: tuple[str, ...] = ()
    canonical_command: CanonicalCommand | None = None
    shell_execution_context_hash: str | None = None
    shell_execution_context_reason_code: str | None = None
    shell_execution_effective_cwds: tuple[str, ...] = ()
    guard_default_action: str | None = None
    reason_code: str | None = None
    restricted_profile_version: str | None = None
    pytest_config_identity_sha256: str | None = None
    pytest_config_sources: tuple[str, ...] = ()
    pytest_config_reason_codes: tuple[str, ...] = ()
    interpreter_executable_identities: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class FileWriteRequestMatch:
    """A sensitive file-write tool call."""

    tool_name: str
    normalized_tool_name: str
    normalized_path: str
    path_class: str
    reason: str
    action_class: str


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

    return classify_secret_path(path, cwd=cwd, home_dir=home_dir)


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


def extract_sensitive_file_read_request_from_action(
    action: GuardActionEnvelope,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Extract a sensitive file-read request from a normalized action envelope."""

    if action.action_type != "file_read":
        return None
    normalized_tool_name = _normalize_tool_name(action.tool_name) or "read"
    tool_name = action.tool_name.strip() if isinstance(action.tool_name, str) and action.tool_name.strip() else "Read"
    if normalized_tool_name not in _FILE_READ_TOOL_NAMES:
        return None
    for candidate in action.target_paths:
        if _is_lossy_redacted_path(candidate):
            continue
        path_match = classify_sensitive_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileReadRequestMatch(
                tool_name=tool_name,
                normalized_tool_name=normalized_tool_name,
                path_match=path_match,
            )
    return None


def _normalized_candidate_path(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    stripped = value.strip().strip("'").strip('"')
    if not stripped:
        return None
    return _normalize_path(_expand_home(stripped, home_dir), cwd)


def _is_lossy_redacted_path(path: str) -> bool:
    return path.strip().startswith(".../")


def _candidate_paths(value: object, *, include_apply_patch: bool = False) -> list[str]:
    results: list[str] = []
    _collect_candidate_paths(value, results, depth=0)
    if include_apply_patch and isinstance(value, dict):
        results.extend(apply_patch_target_paths(value))
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


__all__ = [
    "_BASE64_LITERAL_PATTERN",
    "_ENCODED_EXECUTION_PATTERNS",
    "_HEX_LITERAL_PATTERN",
    "_MAX_DECODED_PAYLOAD_BYTES",
    "_SECRET_EXFILTRATION_DESTINATION_PATTERN",
    "_SECRET_EXFILTRATION_NETWORK_PATTERN",
    "_SECRET_EXFILTRATION_SECRET_PATTERN",
    "_SENSITIVE_BASENAME_LABELS",
    "_SENSITIVE_DECODED_PAYLOAD_TOKENS",
    "_SENSITIVE_PATH_REASONS",
    "_SENSITIVE_SUFFIX_LABELS",
    "FileReadRequestMatch",
    "FileWriteRequestMatch",
    "ToolActionRequestMatch",
    "_candidate_paths",
    "_collect_candidate_paths",
    "_expand_home",
    "_is_lossy_redacted_path",
    "_normalize_path",
    "_normalize_tool_name",
    "_normalized_candidate_path",
    "classify_sensitive_path",
    "extract_sensitive_file_read_request",
    "extract_sensitive_file_read_request_from_action",
    "is_file_read_tool_name",
    "tool_action_risk_summary",
]
