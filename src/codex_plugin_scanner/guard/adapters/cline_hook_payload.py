"""Normalize Cline hook and plugin payloads onto Guard's shared runtime shape."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..runtime.actions import GuardActionEnvelope

_EVENT_NAMES = {
    "pretooluse": "PreToolUse",
    "pretool": "PreToolUse",
    "tool_call": "PreToolUse",
    "toolcall": "PreToolUse",
    "posttooluse": "PostToolUse",
    "posttool": "PostToolUse",
    "tool_result": "PostToolUse",
    "toolresult": "PostToolUse",
    "userpromptsubmit": "UserPromptSubmit",
    "prompt_submit": "UserPromptSubmit",
    "promptsubmit": "UserPromptSubmit",
    "taskstart": "TaskStart",
    "agent_start": "TaskStart",
    "taskresume": "TaskResume",
    "agent_resume": "TaskResume",
    "taskcomplete": "TaskComplete",
    "agent_end": "TaskComplete",
    "taskcancel": "TaskCancel",
    "agent_abort": "TaskCancel",
    "taskerror": "TaskError",
    "agent_error": "TaskError",
    "sessionshutdown": "SessionShutdown",
    "session_shutdown": "SessionShutdown",
    "precompact": "PreCompact",
}

_SHELL_TOOLS = frozenset(
    {
        "run_commands",
        "run_command",
        "execute_command",
        "execute_command_line",
        "terminal",
        "bash",
        "shell",
    }
)
_READ_TOOLS = frozenset(
    {
        "read_files",
        "read_file",
        "read",
        "view_file",
        "open_file",
        "cat_file",
        "search_files",
        "list_files",
        "list_code_definition_names",
        "grep",
        "rg",
    }
)
_WRITE_TOOLS = frozenset(
    {
        "editor",
        "edit_file",
        "write_file",
        "write_to_file",
        "replace_in_file",
        "apply_patch",
        "patch",
    }
)
_NETWORK_TOOLS = frozenset(
    {
        "fetch_web_content",
        "web_fetch",
        "web_search",
        "browser",
        "browser_action",
        "open_url",
        "visit_url",
    }
)
_MCP_TOOLS = frozenset({"use_mcp_tool", "access_mcp_resource", "mcp_tool", "mcp_resource"})
_ACTION_BEARING_KEYS = frozenset(
    {
        "command",
        "commands",
        "cmd",
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "file_paths",
        "patch",
        "url",
        "urls",
        "uri",
        "href",
        "server",
        "server_name",
        "servername",
        "tool",
        "tool_name",
        "toolname",
        "package",
        "packages",
        "executable",
    }
)


class ClinePayloadError(ValueError):
    """Raised when current and compatibility Cline payloads disagree."""


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items() if isinstance(key, str)}
    return {}


def _decoded_parameter(value: object) -> object:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    if stripped[0] not in '[{"-0123456789tfn':
        return value
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return value


def _decode_parameter_map(value: object) -> dict[str, object]:
    return {key: _decoded_parameter(item) for key, item in _mapping(value).items()}


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return repr(value)


def _string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _event_name(payload: Mapping[str, object]) -> str:
    for key in ("hook_event_name", "hookEventName", "hook_name", "hookName", "event", "eventName"):
        value = _string(payload.get(key))
        if value:
            return _EVENT_NAMES.get(value.lower().replace("-", "_"), value)
    if isinstance(payload.get("tool_call"), Mapping) or isinstance(payload.get("preToolUse"), Mapping):
        return "PreToolUse"
    if isinstance(payload.get("tool_result"), Mapping) or isinstance(payload.get("postToolUse"), Mapping):
        return "PostToolUse"
    if isinstance(payload.get("userPromptSubmit"), Mapping):
        return "UserPromptSubmit"
    return "PreToolUse"


def _current_tool(payload: Mapping[str, object], event_name: str) -> tuple[str | None, object, object | None]:
    key = "tool_result" if event_name == "PostToolUse" else "tool_call"
    current = _mapping(payload.get(key))
    if not current:
        return None, {}, None
    name = _string(current.get("name"))
    tool_input = current.get("input", {})
    output = current.get("output") if event_name == "PostToolUse" else None
    return name, tool_input, output


def _legacy_tool(payload: Mapping[str, object], event_name: str) -> tuple[str | None, object, object | None]:
    key = "postToolUse" if event_name == "PostToolUse" else "preToolUse"
    legacy = _mapping(payload.get(key))
    if not legacy:
        return None, {}, None
    name = _string(legacy.get("toolName") or legacy.get("tool_name"))
    tool_input = _decode_parameter_map(legacy.get("parameters"))
    output = legacy.get("result") if event_name == "PostToolUse" else None
    return name, tool_input, output


def _input_object(tool_name: str | None, value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items() if isinstance(key, str)}
    lowered = tool_name.lower() if isinstance(tool_name, str) else ""
    if lowered in _SHELL_TOOLS and isinstance(value, (str, list)):
        return {"commands": value}
    if lowered in _READ_TOOLS and isinstance(value, (str, list)):
        return {"files": value}
    if lowered in _WRITE_TOOLS and isinstance(value, str):
        return {"patch" if lowered in {"apply_patch", "patch"} else "path": value}
    if lowered in _NETWORK_TOOLS and isinstance(value, str):
        return {"url": value}
    return {"value": value} if value not in ({}, None) else {}


def _assert_compatible(
    current_name: str | None,
    current_input: object,
    legacy_name: str | None,
    legacy_input: object,
) -> None:
    if current_name and legacy_name and current_name != legacy_name:
        raise ClinePayloadError(f"Cline hook tool names disagree: {current_name!r} != {legacy_name!r}")
    authoritative_name = current_name or legacy_name
    current_semantic = _input_object(authoritative_name, current_input)
    legacy_semantic = _input_object(authoritative_name, legacy_input)
    if current_semantic and legacy_semantic and _canonical_json(current_semantic) != _canonical_json(legacy_semantic):
        raise ClinePayloadError("Cline hook typed and compatibility tool inputs disagree")


def _commands_from_input(tool_input: Mapping[str, object]) -> list[str]:
    commands = tool_input.get("commands")
    if isinstance(commands, str) and commands.strip():
        return [commands.strip()]
    if isinstance(commands, list):
        output: list[str] = []
        for item in commands:
            if isinstance(item, str) and item.strip():
                output.append(item.strip())
            elif isinstance(item, Mapping):
                command = _string(item.get("command") or item.get("cmd"))
                if command:
                    output.append(command)
        if output:
            return output
    for key in ("command", "cmd"):
        value = _string(tool_input.get(key))
        if value:
            return [value]
    return []


def _paths_from_input(tool_input: Mapping[str, object]) -> list[str]:
    paths: list[str] = []
    path_keys = {
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "file_paths",
        "filepath",
        "filepaths",
        "target_path",
        "target_paths",
    }

    def visit(key: str, value: object) -> None:
        normalized_key = key.replace("-", "_").lower()
        if isinstance(value, str):
            if normalized_key in path_keys and value.strip():
                paths.append(value.strip())
            return
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and normalized_key in path_keys and item.strip():
                    paths.append(item.strip())
                elif isinstance(item, Mapping):
                    for child_key, child in item.items():
                        if isinstance(child_key, str):
                            visit(child_key, child)
            return
        if isinstance(value, Mapping):
            for child_key, child in value.items():
                if isinstance(child_key, str):
                    visit(child_key, child)

    for key, value in tool_input.items():
        visit(key, value)
    return list(dict.fromkeys(paths))


def _urls_from_input(tool_input: Mapping[str, object]) -> list[str]:
    urls: list[str] = []
    for key in ("url", "urls", "uri", "href"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            urls.append(value.strip())
        elif isinstance(value, list):
            urls.extend(item.strip() for item in value if isinstance(item, str) and item.strip())
    return list(dict.fromkeys(urls))


def _mcp_parts(name: str | None, tool_input: Mapping[str, object]) -> tuple[str | None, str | None]:
    server = _string(
        tool_input.get("server")
        or tool_input.get("serverName")
        or tool_input.get("server_name")
        or tool_input.get("mcpServer")
    )
    tool = _string(
        tool_input.get("tool")
        or tool_input.get("toolName")
        or tool_input.get("tool_name")
        or tool_input.get("resource")
    )
    if server and tool:
        return server, tool
    if not name:
        return None, None
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[1], parts[2]
    if "/" in name:
        first, second = name.split("/", 1)
        if first and second:
            return first, second
    return server, tool


def _normalized_tool(name: str | None, tool_input: dict[str, object]) -> tuple[str | None, dict[str, object]]:
    if not name:
        return None, tool_input
    normalized_name = name.strip()
    lowered = normalized_name.lower()
    normalized_input = dict(tool_input)
    normalized_input.setdefault("cline_tool_name", normalized_name)

    if lowered in _SHELL_TOOLS:
        commands = _commands_from_input(normalized_input)
        if len(commands) == 1:
            normalized_input["command"] = commands[0]
        elif len(commands) > 1:
            normalized_input["command"] = "cline-parallel:" + json.dumps(commands, separators=(",", ":"))
            normalized_input["cline_parallel_commands"] = commands
        return "bash", normalized_input

    if lowered in _READ_TOOLS:
        paths = _paths_from_input(normalized_input)
        if paths:
            normalized_input["paths"] = paths
        return "read_file", normalized_input

    if lowered in _WRITE_TOOLS:
        paths = _paths_from_input(normalized_input)
        if paths:
            normalized_input["paths"] = paths
        if lowered in {"apply_patch", "patch"}:
            return "apply_patch", normalized_input
        return "edit_file", normalized_input

    if lowered in _MCP_TOOLS:
        server, tool = _mcp_parts(normalized_name, normalized_input)
        if server and tool:
            return f"mcp__{server}__{tool}", normalized_input
        normalized_input["cline_action_bearing_unknown"] = True
        return normalized_name, normalized_input

    if lowered in _NETWORK_TOOLS:
        urls = _urls_from_input(normalized_input)
        if urls:
            normalized_input.setdefault("command", " ".join(urls))
        return "network_request", normalized_input

    lowered_keys = {key.lower().replace("-", "_") for key in normalized_input}
    if lowered_keys & _ACTION_BEARING_KEYS:
        normalized_input["cline_action_bearing_unknown"] = True
    return normalized_name, normalized_input


def prepare_cline_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Return a Guard-generic Cline payload without mutating the original."""

    normalized = dict(payload)
    event_name = _event_name(payload)
    normalized["hook_event_name"] = event_name

    if event_name == "UserPromptSubmit":
        prompt = _mapping(payload.get("userPromptSubmit")).get("prompt")
        if not isinstance(prompt, str):
            prompt = payload.get("prompt")
        if isinstance(prompt, str):
            normalized["prompt"] = prompt
        return normalized

    if event_name not in {"PreToolUse", "PostToolUse"}:
        return normalized

    current_name, current_raw_input, current_output = _current_tool(payload, event_name)
    legacy_name, legacy_raw_input, legacy_output = _legacy_tool(payload, event_name)
    _assert_compatible(current_name, current_raw_input, legacy_name, legacy_raw_input)

    original_name = current_name or legacy_name or _string(payload.get("tool_name") or payload.get("toolName"))
    raw_input = current_raw_input if current_name or current_raw_input not in ({}, None) else legacy_raw_input
    if raw_input in ({}, None):
        raw_input = payload.get("tool_input", payload.get("arguments", {}))
    tool_input = _input_object(original_name, raw_input)
    tool_name, tool_input = _normalized_tool(original_name, tool_input)
    if event_name == "PreToolUse" and tool_input.get("cline_action_bearing_unknown") is True:
        raise ClinePayloadError(f"Cline action-bearing tool is not mapped safely: {original_name or 'unknown'}")
    if tool_name:
        normalized["tool_name"] = tool_name
    if tool_input:
        normalized["tool_input"] = tool_input

    mcp_server, mcp_tool = _mcp_parts(original_name or tool_name, tool_input)
    if mcp_server:
        normalized["mcp_server"] = mcp_server
    if mcp_tool:
        normalized["mcp_tool"] = mcp_tool

    if event_name == "PostToolUse":
        output = current_output if current_output is not None else legacy_output
        if output is not None:
            normalized["tool_response"] = output
            normalized["output"] = output

    return normalized


def normalize_cline_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize Cline onto Guard's canonical typed action envelope."""

    from ..runtime import actions as runtime_actions

    prepared = prepare_cline_hook_payload(payload)
    envelope = runtime_actions._normalize_action_payload(  # pyright: ignore[reportPrivateUsage]
        prepared,
        harness="cline",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )
    original_tool = _string(_mapping(prepared.get("tool_input")).get("cline_tool_name"))
    if original_tool and original_tool.lower() in _NETWORK_TOOLS:
        from dataclasses import replace

        return replace(envelope, action_type="network_request")
    return envelope


def register_cline_action_normalizer() -> None:
    """Register Cline aliases with the shared action boundary exactly once."""

    from ..runtime import actions as runtime_actions

    for alias in ("cline", "cline-cli", "cline-vscode"):
        runtime_actions._ACTION_PAYLOAD_NORMALIZERS[alias] = normalize_cline_payload  # pyright: ignore[reportPrivateUsage]


__all__ = [
    "ClinePayloadError",
    "normalize_cline_payload",
    "prepare_cline_hook_payload",
    "register_cline_action_normalizer",
]
