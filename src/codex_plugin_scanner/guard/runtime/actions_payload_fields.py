"""Extract command, MCP, event and target fields from harness payloads."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Mapping
from pathlib import Path

from .actions_envelope import GuardActionType, _string_value
from .actions_redaction import _PATH_KEYS, _PROMPT_PATH_PATTERN, _redacted_target_path
from .shell_command_wrappers import normalize_transparent_shell_command

_SHELL_TOOL_NAMES = frozenset({"bash", "shell", "sh", "zsh", "terminal", "run_command", "run_terminal_command"})


_FILE_READ_TOOL_NAMES = frozenset({"read", "read_file", "open_file", "view", "view_file", "cat_file"})


_FILE_WRITE_TOOL_NAMES = frozenset({"write", "edit", "multiedit", "write_file", "edit_file", "apply_patch"})


_COMMAND_KEYS = (
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "pattern",
    "query",
    "search",
    "regex",
)


_EXPLICIT_COMMAND_KEYS = ("command", "cmd", "shell_command", "shellCommand")


_SEARCH_PATTERN_KEYS = ("pattern", "query", "search", "regex")


_PATCH_INPUT_KEYS = ("patch", "input", "command")


_PATCH_FILE_HEADER_PATTERN = re.compile(r"^\*\*\* (?:Add|Delete|Update) File: (?P<path>.+)$", re.MULTILINE)


_HOOK_EVENT_NAME_MAP = {
    "prompt": "UserPromptSubmit",
    "userpromptsubmit": "UserPromptSubmit",
    "userpromptsubmitted": "UserPromptSubmit",
    "pretool": "PreToolUse",
    "pretooluse": "PreToolUse",
    "posttool": "PostToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
    "permissionrequestv2": "PermissionRequest",
}


_NETWORK_HOST_PATTERN = re.compile(r"(?:https?|wss?|grpcs?)://(?P<host>[A-Za-z0-9.-]+)(?::\d+)?(?:[/?#]|$)")


def _payload_with_default_event(payload: Mapping[str, object], event_name: str) -> dict[str, object]:
    normalized_payload = dict(payload)
    if not event_name.strip():
        return normalized_payload
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = normalized_payload.get(key)
        if isinstance(value, str) and value.strip():
            return normalized_payload
    normalized_payload["hook_event_name"] = event_name
    return normalized_payload


def _tool_name_from_payload(payload: Mapping[str, object]) -> str | None:
    for key in ("tool_name", "toolName", "name", "tool"):
        value = _string_value(payload.get(key))
        if value is not None:
            return value
    return None


def _tool_input_from_payload(payload: Mapping[str, object]) -> Mapping[str, object]:
    for key in ("tool_input", "toolInput", "toolArgs", "arguments"):
        parsed = _mapping_from_value(payload.get(key))
        if parsed is not None:
            return parsed
    return {}


def _tool_call_from_payload(
    value: object,
    *,
    expected_tool_name: str | None,
) -> tuple[str | None, Mapping[str, object] | None]:
    if not isinstance(value, list):
        return None, None
    fallback_tool_call: tuple[str, Mapping[str, object] | None] | None = None
    for item in value:
        if not isinstance(item, Mapping):
            continue
        tool_name = _string_value(item.get("name"))
        if tool_name is None:
            continue
        tool_input = _mapping_from_value(item.get("args"))
        if fallback_tool_call is None:
            fallback_tool_call = (tool_name, tool_input)
        if expected_tool_name is None or tool_name == expected_tool_name:
            return tool_name, tool_input
    if fallback_tool_call is not None:
        return fallback_tool_call
    return None, None


def _mapping_from_value(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, Mapping):
            return parsed
    return None


def _hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            stripped = value.strip()
            return _HOOK_EVENT_NAME_MAP.get(stripped.lower(), stripped)
    return "PreToolUse"


def _prompt_value(payload: Mapping[str, object]) -> object:
    for key in ("prompt", "userPrompt", "user_prompt", "message", "text", "input"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _command_from_payload(tool_input: Mapping[str, object]) -> str | None:
    for key in _COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def command_text_from_tool_payload(tool_name: object, tool_input: object) -> str | None:
    if not isinstance(tool_input, Mapping):
        return None
    for key in _EXPLICIT_COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    native_command = _native_tool_command_text(tool_name, tool_input)
    if native_command is not None:
        return native_command
    normalized_tool = tool_name.strip() if isinstance(tool_name, str) else None
    mcp_server, _mcp_tool = _mcp_parts(normalized_tool)
    if mcp_server is not None:
        # MCP search/query fields are tool data, not shell source. Explicit
        # command keys above remain eligible for command-risk inspection.
        return None
    return _command_from_payload(tool_input)


def _native_tool_command_text(tool_name: object, tool_input: Mapping[str, object]) -> str | None:
    if not isinstance(tool_name, str):
        return None
    normalized_tool = tool_name.strip().lower()
    if normalized_tool in {"grep", "egrep", "fgrep", "rg"}:
        return _grep_tool_command_text(normalized_tool, tool_input)
    return None


def _grep_tool_command_text(executable: str, tool_input: Mapping[str, object]) -> str | None:
    pattern = _first_tool_input_string(tool_input, _SEARCH_PATTERN_KEYS)
    if pattern is None:
        return None
    args = [executable]
    if tool_input.get("ignoreCase") is True or tool_input.get("ignore_case") is True:
        args.append("-i")
    if tool_input.get("literal") is True or executable == "fgrep":
        args.append("-F")
    context_value = _nonnegative_int(tool_input.get("context"))
    if context_value is not None and context_value > 0:
        args.extend(["-C", str(context_value)])
    glob_value = _first_tool_input_string(tool_input, ("glob", "include", "includes"))
    if glob_value is not None:
        args.extend(["--glob" if executable == "rg" else "--include", glob_value])
    args.append(pattern)
    path_value = _first_tool_input_string(tool_input, ("path", "file_path", "filePath", "filepath", "file", "filename"))
    args.append(path_value or ".")
    return shlex.join(args)


def _first_tool_input_string(tool_input: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float) and value.is_integer():
        return max(int(value), 0)
    return None


def _normalized_shell_command(
    tool_name: str | None,
    command: str | None,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[str | None, tuple[str, ...]]:
    if command is None:
        return None, ()
    if not isinstance(tool_name, str) or tool_name.strip().lower() not in _SHELL_TOOL_NAMES:
        return command, ()
    normalized = normalize_transparent_shell_command(command, cwd=cwd, home_dir=home_dir)
    return normalized.normalized_command, normalized.wrapper_chain


def _mcp_details(payload: Mapping[str, object], tool_name: str | None) -> tuple[str | None, str | None]:
    explicit_server = _string_from_keys(payload, ("mcp_server", "mcpServer", "server", "serverName"))
    explicit_tool = _string_from_keys(payload, ("mcp_tool", "mcpTool"))
    tool_name_value = _string_from_keys(payload, ("tool_name", "toolName"))
    parts_server, parts_tool = _mcp_parts(tool_name, known_servers=_known_mcp_servers(payload))
    server = explicit_server or parts_server
    tool = explicit_tool or parts_tool
    if tool is None and server is not None and tool_name_value is not None:
        tool = tool_name_value
    return server, tool


def _string_from_keys(payload: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _string_value(payload.get(key))
        if value is not None:
            return value
    return None


def _known_mcp_servers(payload: Mapping[str, object]) -> tuple[str, ...]:
    servers: set[str] = set()
    for key in ("mcp_servers", "mcpServers", "servers"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            servers.update(str(server_name).strip() for server_name in value if isinstance(server_name, str))
        elif isinstance(value, list):
            servers.update(item.strip() for item in value if isinstance(item, str) and item.strip())
    return tuple(
        sorted(
            (server for server in servers if server), key=lambda server: len(_mcp_server_token(server)), reverse=True
        )
    )


def _mcp_parts(tool_name: str | None, *, known_servers: tuple[str, ...] = ()) -> tuple[str | None, str | None]:
    if tool_name is None:
        return None, None
    if "/" in tool_name:
        server, tool = tool_name.split("/", 1)
        return (server, tool) if server and tool else (None, None)
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[1], parts[2]
        return None, None
    if tool_name.startswith("mcp_"):
        suffix = tool_name[len("mcp_") :]
        for server in known_servers:
            server_token = _mcp_server_token(server)
            prefix = f"{server_token}_"
            if suffix.startswith(prefix):
                tool = suffix[len(prefix) :]
                return (server, tool) if tool else (None, None)
        return None, None
    return None, None


def _mcp_server_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
    return token.strip("_")


def _action_type(
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
    tool_name: str | None,
    tool_input: Mapping[str, object],
    command: str | None,
    prompt_text: str | None,
    home_dir: Path | str | None,
) -> tuple[str, ...]:
    paths: list[str] = []
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            paths.append(value.strip())
        elif isinstance(value, list):
            paths.extend(item.strip() for item in value if isinstance(item, str) and item.strip())
    if isinstance(tool_name, str) and tool_name.strip().lower() == "apply_patch":
        paths.extend(apply_patch_target_paths(tool_input))
    for text in (command, prompt_text):
        if text is not None:
            paths.extend(match.group("path") for match in _PROMPT_PATH_PATTERN.finditer(text))
    redacted_paths = (_redacted_target_path(path, home_dir=home_dir) for path in paths)
    return tuple(dict.fromkeys(path for path in redacted_paths if path is not None))


def apply_patch_target_paths(tool_input: Mapping[str, object]) -> tuple[str, ...]:
    paths: list[str] = []
    for key in _PATCH_INPUT_KEYS:
        patch_text = tool_input.get(key)
        if not isinstance(patch_text, str) or not patch_text.strip():
            continue
        paths.extend(match.group("path").strip() for match in _PATCH_FILE_HEADER_PATTERN.finditer(patch_text))
    return tuple(dict.fromkeys(paths))


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
