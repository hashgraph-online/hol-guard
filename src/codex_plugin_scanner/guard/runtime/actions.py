"""Typed runtime action envelopes for Guard hook payloads."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Literal

from ..redaction import redact_text

GuardActionType = Literal[
    "prompt",
    "shell_command",
    "file_read",
    "file_write",
    "mcp_tool",
    "package_script",
    "network_request",
    "config_change",
    "browser_action",
    "harness_start",
]

_VALID_ACTION_TYPES = frozenset(
    {
        "prompt",
        "shell_command",
        "file_read",
        "file_write",
        "mcp_tool",
        "package_script",
        "network_request",
        "config_change",
        "browser_action",
        "harness_start",
    }
)
_SCHEMA_VERSION = 1
_SHELL_TOOL_NAMES = frozenset({"bash", "shell", "sh", "zsh", "terminal", "run_command", "run_terminal_command"})
_FILE_READ_TOOL_NAMES = frozenset({"read", "read_file", "open_file", "view", "view_file", "cat_file"})
_FILE_WRITE_TOOL_NAMES = frozenset({"write", "edit", "multiedit", "write_file", "edit_file"})
_PATH_KEYS = ("path", "file_path", "filePath", "filepath", "file", "filename", "target_path", "targetPath")
_COMMAND_KEYS = ("command", "cmd", "shell_command", "shellCommand")
_SENSITIVE_RAW_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "access_token",
        "auth",
        "authorization",
        "client_secret",
        "content",
        "cookie",
        "credential",
        "credentials",
        "id_token",
        "output",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "session_token",
        "set_cookie",
        "stderr",
        "stdout",
        "token",
        "tool_response",
    }
)
_SENSITIVE_RAW_KEY_ALIASES = frozenset(key.replace("_", "") for key in _SENSITIVE_RAW_KEYS)
_HOOK_EVENT_NAME_MAP = {
    "userpromptsubmit": "UserPromptSubmit",
    "userpromptsubmitted": "UserPromptSubmit",
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
}
_PROMPT_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?P<path>(?:~|\.{1,2})?/?(?:[A-Za-z0-9_.-]+/)*"
    r"(?:\.npmrc|\.env(?:\.[A-Za-z0-9_-]+)?|id_rsa|id_ed25519|credentials))"
    r"(?![A-Za-z0-9_.-])"
)
_NETWORK_HOST_PATTERN = re.compile(r"(?:https?|wss?|grpcs?)://(?P<host>[A-Za-z0-9.-]+)(?::\d+)?(?:/|$)")
_PROMPT_EXCERPT_LIMIT = 240


@dataclass(frozen=True, slots=True)
class GuardActionEnvelope:
    """A redacted, typed view of one harness runtime action."""

    schema_version: int
    action_id: str
    harness: str
    event_name: str
    action_type: GuardActionType
    workspace: str | None
    workspace_hash: str | None
    tool_name: str | None
    command: str | None
    prompt_excerpt: str | None
    target_paths: tuple[str, ...]
    network_hosts: tuple[str, ...]
    mcp_server: str | None
    mcp_tool: str | None
    package_manager: str | None
    package_name: str | None
    script_name: str | None
    raw_payload_redacted: dict[str, object]

    def __post_init__(self) -> None:
        if not self.action_id:
            object.__setattr__(self, "action_id", stable_action_hash(self))

    def to_dict(self) -> dict[str, object]:
        """Return the stable JSON payload stored with approvals and receipts."""

        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "harness": self.harness,
            "event_name": self.event_name,
            "action_type": self.action_type,
            "workspace": self.workspace,
            "workspace_hash": self.workspace_hash,
            "tool_name": self.tool_name,
            "command": self.command,
            "prompt_excerpt": self.prompt_excerpt,
            "target_paths": list(self.target_paths),
            "network_hosts": list(self.network_hosts),
            "mcp_server": self.mcp_server,
            "mcp_tool": self.mcp_tool,
            "package_manager": self.package_manager,
            "package_name": self.package_name,
            "script_name": self.script_name,
            "raw_payload_redacted": dict(self.raw_payload_redacted),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardActionEnvelope:
        """Build an envelope from a persisted payload."""

        schema_version = _required_int(payload, "schema_version")
        action_type = _required_action_type(payload.get("action_type"))
        return cls(
            schema_version=schema_version,
            action_id=_string_value(payload.get("action_id")) or "",
            harness=_required_string(payload, "harness"),
            event_name=_required_string(payload, "event_name"),
            action_type=action_type,
            workspace=_string_value(payload.get("workspace")),
            workspace_hash=_string_value(payload.get("workspace_hash")),
            tool_name=_string_value(payload.get("tool_name")),
            command=_string_value(payload.get("command")),
            prompt_excerpt=_string_value(payload.get("prompt_excerpt")),
            target_paths=_string_tuple(payload.get("target_paths")),
            network_hosts=_string_tuple(payload.get("network_hosts")),
            mcp_server=_string_value(payload.get("mcp_server")),
            mcp_tool=_string_value(payload.get("mcp_tool")),
            package_manager=_string_value(payload.get("package_manager")),
            package_name=_string_value(payload.get("package_name")),
            script_name=_string_value(payload.get("script_name")),
            raw_payload_redacted=_dict_value(payload.get("raw_payload_redacted")),
        )


def stable_action_hash(envelope: GuardActionEnvelope) -> str:
    """Return a deterministic action identity without raw payload content."""

    payload = {
        "schema_version": envelope.schema_version,
        "harness": envelope.harness,
        "event_name": envelope.event_name,
        "action_type": envelope.action_type,
        "workspace_hash": envelope.workspace_hash,
        "tool_name": envelope.tool_name,
        "command": _normalized_command(envelope.command),
        "prompt_excerpt": envelope.prompt_excerpt,
        "target_paths": list(envelope.target_paths),
        "network_hosts": list(envelope.network_hosts),
        "mcp_server": envelope.mcp_server,
        "mcp_tool": envelope.mcp_tool,
        "package_manager": envelope.package_manager,
        "package_name": envelope.package_name,
        "script_name": envelope.script_name,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def redacted_workspace_label(workspace: Path | str | None, *, home_dir: Path | str | None = None) -> str | None:
    """Return a workspace label safe for local UI and persisted context."""

    if workspace is None:
        return None
    workspace_path = Path(workspace).expanduser()
    home_path = Path(home_dir).expanduser() if home_dir is not None else Path.home()
    resolved_workspace = _safe_resolve(workspace_path)
    resolved_home = _safe_resolve(home_path)
    if resolved_workspace.is_relative_to(resolved_home):
        relative = resolved_workspace.relative_to(resolved_home)
        return "~" if str(relative) == "." else f"~/{relative.as_posix()}"
    workspace_name = resolved_workspace.name or workspace_path.name or "workspace"
    return f".../{workspace_name}"


def normalize_codex_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Codex hook payload into a typed action envelope."""

    normalized_payload = dict(payload)
    event_name = _hook_event_name(normalized_payload)
    tool_name = _string_value(normalized_payload.get("tool_name")) or _string_value(normalized_payload.get("toolName"))
    tool_input = _tool_input_from_payload(normalized_payload)
    command = _command_from_payload(tool_input)
    prompt_excerpt = _prompt_excerpt(normalized_payload.get("prompt"))
    mcp_server, mcp_tool = _mcp_parts(tool_name)
    action_type = _codex_action_type(
        event_name=event_name,
        tool_name=tool_name,
        command=command,
        prompt_excerpt=prompt_excerpt,
        mcp_server=mcp_server,
    )
    target_paths = _target_paths(
        tool_input=tool_input,
        command=command,
        prompt_excerpt=prompt_excerpt,
        home_dir=home_dir,
    )
    network_hosts = _network_hosts(command, prompt_excerpt)
    workspace_label = redacted_workspace_label(workspace, home_dir=home_dir)
    workspace_hash = _workspace_hash(workspace)
    return GuardActionEnvelope(
        schema_version=_SCHEMA_VERSION,
        action_id="",
        harness="codex",
        event_name=event_name,
        action_type=action_type,
        workspace=workspace_label,
        workspace_hash=workspace_hash,
        tool_name=tool_name,
        command=command,
        prompt_excerpt=prompt_excerpt,
        target_paths=target_paths,
        network_hosts=network_hosts,
        mcp_server=mcp_server,
        mcp_tool=mcp_tool,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted=_redacted_payload(normalized_payload, home_dir=home_dir),
    )


def _required_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise ValueError(f"Guard action envelope missing required integer {key}.")
    return value


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Guard action envelope missing required string {key}.")
    return value


def _required_action_type(value: object) -> GuardActionType:
    if not isinstance(value, str) or value not in _VALID_ACTION_TYPES:
        raise ValueError("Guard action envelope missing valid action_type.")
    return value


def _string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


def _dict_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(key, str)}


def _mapping_value(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def _tool_input_from_payload(payload: Mapping[str, object]) -> Mapping[str, object]:
    for key in ("tool_input", "toolInput", "toolArgs", "arguments"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            return value
        if isinstance(value, str) and value.strip():
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, Mapping):
                return parsed
    return {}


def _hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("event", "hook_event_name", "hookEventName", "hook_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            stripped = value.strip()
            return _HOOK_EVENT_NAME_MAP.get(stripped.lower(), stripped)
    return "PreToolUse"


def _command_from_payload(tool_input: Mapping[str, object]) -> str | None:
    for key in _COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _prompt_excerpt(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    redacted = redact_text(value.strip()).text
    collapsed = " ".join(redacted.split())
    if not collapsed:
        return None
    return collapsed[:_PROMPT_EXCERPT_LIMIT]


def _mcp_parts(tool_name: str | None) -> tuple[str | None, str | None]:
    if tool_name is None or not tool_name.startswith("mcp__"):
        return None, None
    parts = tool_name.split("__", 2)
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None, None
    return parts[1], parts[2]


def _codex_action_type(
    *,
    event_name: str,
    tool_name: str | None,
    command: str | None,
    prompt_excerpt: str | None,
    mcp_server: str | None,
) -> GuardActionType:
    normalized_tool = tool_name.lower() if tool_name is not None else ""
    if event_name == "UserPromptSubmit" and prompt_excerpt is not None:
        return "prompt"
    if mcp_server is not None:
        return "mcp_tool"
    if normalized_tool in _FILE_READ_TOOL_NAMES:
        return "file_read"
    if normalized_tool in _FILE_WRITE_TOOL_NAMES:
        return "file_write"
    if normalized_tool in _SHELL_TOOL_NAMES or command is not None:
        return "shell_command"
    return "config_change"


def _target_paths(
    *,
    tool_input: Mapping[str, object],
    command: str | None,
    prompt_excerpt: str | None,
    home_dir: Path | str | None,
) -> tuple[str, ...]:
    paths: list[str] = []
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            paths.append(value.strip())
    for text in (command, prompt_excerpt):
        if text is not None:
            paths.extend(match.group("path") for match in _PROMPT_PATH_PATTERN.finditer(text))
    redacted_paths = (_redacted_target_path(path, home_dir=home_dir) for path in paths)
    return tuple(dict.fromkeys(path for path in redacted_paths if path is not None))


def _network_hosts(command: str | None, prompt_excerpt: str | None) -> tuple[str, ...]:
    text = "\n".join(value for value in (command, prompt_excerpt) if value)
    if not text:
        return ()
    return tuple(dict.fromkeys(match.group("host") for match in _NETWORK_HOST_PATTERN.finditer(text)))


def _workspace_hash(workspace: Path | str | None) -> str | None:
    if workspace is None:
        return None
    encoded = str(Path(workspace).expanduser()).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return path


def _redacted_target_path(path: str, *, home_dir: Path | str | None) -> str | None:
    stripped = path.strip()
    if not stripped:
        return None
    if stripped == "~" or stripped.startswith("~/"):
        return redact_text(stripped).text
    if stripped.startswith("~"):
        target_name = Path(stripped).name or "path"
        return f".../{target_name}"
    windows_path = PureWindowsPath(stripped)
    if windows_path.is_absolute():
        target_name = windows_path.name or "path"
        return f".../{target_name}"
    if _is_absolute_target_path(stripped):
        return redacted_workspace_label(stripped, home_dir=home_dir)
    return redact_text(stripped).text


def _is_absolute_target_path(path: str) -> bool:
    return Path(path).expanduser().is_absolute()


def _redacted_payload(payload: Mapping[str, object], *, home_dir: Path | str | None) -> dict[str, object]:
    return {
        str(key): _redacted_value(str(key), value, home_dir=home_dir)
        for key, value in payload.items()
        if isinstance(key, str)
    }


def _redacted_value(key: str, value: object, *, home_dir: Path | str | None) -> object:
    normalized_key = _normalized_secret_key(key)
    if normalized_key in _SENSITIVE_RAW_KEYS or normalized_key.replace("_", "") in _SENSITIVE_RAW_KEY_ALIASES:
        return "[redacted]"
    if isinstance(value, Mapping):
        return {
            str(child_key): _redacted_value(str(child_key), child_value, home_dir=home_dir)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redacted_value(key, item, home_dir=home_dir) for item in value]
    if isinstance(value, str):
        return _redacted_string_value(key, value, home_dir=home_dir)[:_PROMPT_EXCERPT_LIMIT]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)


def _redacted_string_value(key: str, value: str, *, home_dir: Path | str | None) -> str:
    if _is_path_like_key(key):
        redacted_path = _redacted_target_path(value, home_dir=home_dir)
        if redacted_path is not None:
            return redacted_path
    return _redact_path_mentions(redact_text(value).text, home_dir=home_dir)


def _is_path_like_key(key: str) -> bool:
    normalized_key = _normalized_secret_key(key)
    path_keys = {_normalized_secret_key(path_key) for path_key in _PATH_KEYS}
    return normalized_key in path_keys or normalized_key.replace("_", "") in {
        path_key.replace("_", "") for path_key in path_keys
    }


def _redact_path_mentions(text: str, *, home_dir: Path | str | None) -> str:
    def replace_path(match: re.Match[str]) -> str:
        return _redacted_target_path(match.group("path"), home_dir=home_dir) or match.group("path")

    return _PROMPT_PATH_PATTERN.sub(replace_path, text)


def _normalized_secret_key(key: str) -> str:
    normalized = key.replace("-", "_")
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized)
    return normalized.lower()


def _normalized_command(command: str | None) -> str | None:
    if command is None:
        return None
    return command.strip()


__all__ = [
    "GuardActionEnvelope",
    "GuardActionType",
    "normalize_codex_hook_payload",
    "redacted_workspace_label",
    "stable_action_hash",
]
