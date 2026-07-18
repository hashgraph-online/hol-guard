"""Typed runtime action envelopes for Guard hook payloads."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path, PureWindowsPath
from typing import Literal, TypeGuard

from ..action_lattice import is_action_bearing_key
from ..redaction import redact_text
from .secret_sensitivity import redacted_secret_path_context
from .shell_command_wrappers import normalize_transparent_shell_command

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

_VALID_ACTION_TYPES: frozenset[GuardActionType] = frozenset(
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
_FILE_WRITE_TOOL_NAMES = frozenset({"write", "edit", "multiedit", "write_file", "edit_file", "apply_patch"})
_PATH_KEYS = (
    "path",
    "paths",
    "file_path",
    "file_paths",
    "filePath",
    "filePaths",
    "filepath",
    "file",
    "files",
    "filename",
    "filenames",
    "target_path",
    "target_paths",
    "targetPath",
    "targetPaths",
)
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
_PATCH_INPUT_KEYS = ("patch", "input")
_PATCH_FILE_HEADER_PATTERN = re.compile(r"^\*\*\* (?:Add|Delete|Update) File: (?P<path>.+)$", re.MULTILINE)
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
    "prompt": "UserPromptSubmit",
    "userpromptsubmit": "UserPromptSubmit",
    "userpromptsubmitted": "UserPromptSubmit",
    "pretool": "PreToolUse",
    "pretooluse": "PreToolUse",
    "posttool": "PostToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
}
_PROMPT_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?P<path>(?:"
    r"(?:~|\.{1,2})?/?(?:[A-Za-z0-9_.-]+/)*(?:\.npmrc|\.env(?:\.[A-Za-z0-9_-]+)?|id_rsa|id_ed25519)"
    r"|(?:~|\.{1,2})?/?(?:[A-Za-z0-9_.-]+/)+credentials"
    r"))"
    r"(?![A-Za-z0-9_.-])"
)
_NETWORK_HOST_PATTERN = re.compile(r"(?:https?|wss?|grpcs?)://(?P<host>[A-Za-z0-9.-]+)(?::\d+)?(?:[/?#]|$)")
_GENERIC_POSIX_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![:A-Za-z0-9_./-])(?P<path>/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+)(?![A-Za-z0-9_.-])"
)
_GENERIC_WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./\\:-])(?P<path>[A-Za-z]:\\(?:[^\\\s'\"<>|]+\\)+[^\\\s'\"<>|]+)"
)
_GENERIC_WINDOWS_UNC_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./\\:-])(?P<path>\\\\[^\\\s'\"<>|]+\\[^\\\s'\"<>|]+(?:\\[^\\\s'\"<>|]+)+)"
)
_PROMPT_EXCERPT_LIMIT = 240


def _package_intent_parser_module():
    return importlib.import_module(".package_intent_parser", __package__)


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
    prompt_text: str | None
    target_paths: tuple[str, ...]
    network_hosts: tuple[str, ...]
    mcp_server: str | None
    mcp_tool: str | None
    package_manager: str | None
    package_name: str | None
    package_intent_kind: str | None = None
    package_targets: tuple[str, ...] = ()
    pre_execution_result: str | None = None
    script_name: str | None = None
    raw_payload_redacted: dict[str, object] = field(default_factory=dict)

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
            "prompt_text": self.prompt_text,
            "target_paths": list(self.target_paths),
            "network_hosts": list(self.network_hosts),
            "mcp_server": self.mcp_server,
            "mcp_tool": self.mcp_tool,
            "package_manager": self.package_manager,
            "package_name": self.package_name,
            "package_intent_kind": self.package_intent_kind,
            "package_targets": list(self.package_targets),
            "pre_execution_result": self.pre_execution_result,
            "script_name": self.script_name,
            "raw_payload_redacted": dict(self.raw_payload_redacted),
        }

    def with_pre_execution_result(self, value: str | None) -> GuardActionEnvelope:
        """Return a copy of the envelope annotated with its final pre-exec decision."""

        return replace(self, pre_execution_result=value)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardActionEnvelope:
        """Build an envelope from a persisted payload."""

        for key in payload:
            if not isinstance(key, str):
                raise ValueError("Guard action envelope keys must be strings")
            if is_action_bearing_key(key) and key not in {
                "action_id",
                "action_type",
                "pre_execution_result",
                "actionId",
                "actionType",
                "preExecutionResult",
            }:
                raise ValueError(f"Guard action envelope contains unknown action-bearing field: {key}")
        action_id = _matching_aliased_value(payload, "action_id", "actionId")
        action_type_value = _matching_aliased_value(payload, "action_type", "actionType")
        pre_execution_result = _matching_aliased_value(
            payload,
            "pre_execution_result",
            "preExecutionResult",
        )
        schema_version = _required_int(payload, "schema_version")
        if schema_version != _SCHEMA_VERSION:
            raise ValueError(f"Guard action envelope schema_version {schema_version} is not supported.")
        action_type = _required_action_type(action_type_value)
        return cls(
            schema_version=schema_version,
            action_id=_string_value(action_id) or "",
            harness=_required_string(payload, "harness"),
            event_name=_required_string(payload, "event_name"),
            action_type=action_type,
            workspace=_string_value(payload.get("workspace")),
            workspace_hash=_string_value(payload.get("workspace_hash")),
            tool_name=_string_value(payload.get("tool_name")),
            command=_string_value(payload.get("command")),
            prompt_excerpt=_string_value(payload.get("prompt_excerpt")),
            prompt_text=_string_value(payload.get("prompt_text")),
            target_paths=_string_tuple(payload.get("target_paths")),
            network_hosts=_string_tuple(payload.get("network_hosts")),
            mcp_server=_string_value(payload.get("mcp_server")),
            mcp_tool=_string_value(payload.get("mcp_tool")),
            package_manager=_string_value(payload.get("package_manager")),
            package_name=_string_value(payload.get("package_name")),
            package_intent_kind=_string_value(payload.get("package_intent_kind")),
            package_targets=_string_tuple(payload.get("package_targets")),
            pre_execution_result=_string_value(pre_execution_result),
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
        "package_manager": None,
        "package_name": None,
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

    return _normalize_action_payload(
        payload,
        harness="codex",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_claude_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Claude Code hook payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="claude-code",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_opencode_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize an OpenCode runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="opencode",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_copilot_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Copilot runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="copilot",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_gemini_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Gemini runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="gemini",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_hermes_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Hermes runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="hermes",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_openclaw_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize an OpenClaw runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="openclaw",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_cursor_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Cursor IDE hook payload into a typed action envelope."""

    from ..adapters.cursor_hooks import prepare_cursor_hook_payload

    return _normalize_action_payload(
        prepare_cursor_hook_payload(payload),
        harness="cursor",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_grok_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Grok Build CLI hook payload into a typed action envelope."""

    from ..adapters.grok_hooks import prepare_grok_hook_payload

    return _normalize_action_payload(
        prepare_grok_hook_payload(payload),
        harness="grok",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_zcode_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a z.ai ZCode hook payload into a typed action envelope.

    ZCode speaks the Claude Code wire protocol, so payloads normalize onto the
    shared Guard shape through the ZCode hook helpers.
    """

    from ..adapters.zcode_hooks import prepare_zcode_hook_payload

    return _normalize_action_payload(
        prepare_zcode_hook_payload(payload),
        harness="zcode",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_pi_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Pi extension event payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="pi",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_harness_payload(
    harness: str,
    event_name: str,
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize any supported Guard harness payload into a typed action envelope."""

    normalized_harness = harness.strip().lower()
    normalizers = {
        "codex": normalize_codex_hook_payload,
        "claude": normalize_claude_hook_payload,
        "claude-code": normalize_claude_hook_payload,
        "opencode": normalize_opencode_payload,
        "copilot": normalize_copilot_payload,
        "gemini": normalize_gemini_payload,
        "hermes": normalize_hermes_payload,
        "openclaw": normalize_openclaw_payload,
        "cursor": normalize_cursor_hook_payload,
        "grok": normalize_grok_hook_payload,
        "pi": normalize_pi_payload,
        "zcode": normalize_zcode_hook_payload,
        "zai": normalize_zcode_hook_payload,
    }
    normalizer = normalizers.get(normalized_harness)
    if normalizer is None:
        raise ValueError(f"Unsupported Guard harness for action normalization: {harness}")
    normalized_payload = _payload_with_default_event(payload, event_name)
    return normalizer(normalized_payload, workspace=workspace, home_dir=home_dir)


def _normalize_action_payload(
    payload: Mapping[str, object],
    *,
    harness: str,
    default_event_name: str | None,
    workspace: Path | str | None,
    home_dir: Path | str | None,
) -> GuardActionEnvelope:
    normalized_payload = dict(payload)
    if default_event_name is not None:
        normalized_payload = _payload_with_default_event(normalized_payload, default_event_name)
    event_name = _hook_event_name(normalized_payload)
    explicit_tool_name = _tool_name_from_payload(normalized_payload)
    tool_call_name, tool_call_input = _tool_call_from_payload(
        normalized_payload.get("toolCalls"),
        expected_tool_name=explicit_tool_name,
    )
    tool_name = explicit_tool_name or tool_call_name
    tool_input = _tool_input_from_payload(normalized_payload)
    if not tool_input and tool_call_input is not None:
        tool_input = tool_call_input
    raw_command = command_text_from_tool_payload(tool_name, tool_input)
    normalized_command, wrapper_chain = _normalized_shell_command(
        tool_name,
        raw_command,
        cwd=Path(workspace) if workspace is not None else None,
        home_dir=Path(home_dir) if home_dir is not None else None,
    )
    if wrapper_chain and isinstance(tool_input, Mapping):
        normalized_payload["tool_input"] = {
            **dict(tool_input),
            "guard_inner_command": normalized_command,
            "guard_shell_wrappers": list(wrapper_chain),
        }
    command = _command_detail(normalized_command, home_dir=home_dir)
    prompt_text = _prompt_text(_prompt_value(normalized_payload))
    prompt_excerpt = _prompt_excerpt(prompt_text)
    mcp_server, mcp_tool = _mcp_details(normalized_payload, tool_name)
    action_type = _action_type(
        event_name=event_name,
        tool_name=tool_name,
        command=normalized_command,
        prompt_excerpt=prompt_excerpt,
        mcp_server=mcp_server,
    )
    target_paths = _target_paths(
        tool_name=tool_name,
        tool_input=tool_input,
        command=normalized_command,
        prompt_text=prompt_text,
        home_dir=home_dir,
    )
    network_hosts = _network_hosts(raw_command, prompt_text)
    workspace_label = redacted_workspace_label(workspace, home_dir=home_dir)
    workspace_hash = _workspace_hash(workspace)
    workspace_path = Path(workspace) if workspace is not None else None
    package_intent = (
        _package_intent_parser_module().parse_package_intent(normalized_command, workspace=workspace_path)
        if normalized_command
        else None
    )
    package_targets = (
        tuple(target.raw_spec for target in package_intent.targets if target.raw_spec)
        if package_intent is not None
        else ()
    )
    primary_package_name = None
    if package_intent is not None:
        for target in package_intent.targets:
            if target.package_name:
                primary_package_name = target.package_name
                break
    return GuardActionEnvelope(
        schema_version=_SCHEMA_VERSION,
        action_id="",
        harness=harness,
        event_name=event_name,
        action_type=action_type,
        workspace=workspace_label,
        workspace_hash=workspace_hash,
        tool_name=tool_name,
        command=command,
        prompt_excerpt=prompt_excerpt,
        prompt_text=prompt_text,
        target_paths=target_paths,
        network_hosts=network_hosts,
        mcp_server=mcp_server,
        mcp_tool=mcp_tool,
        package_manager=package_intent.package_manager if package_intent is not None else None,
        package_name=primary_package_name,
        package_intent_kind=package_intent.intent_kind if package_intent is not None else None,
        package_targets=package_targets,
        pre_execution_result=None,
        script_name=None,
        raw_payload_redacted=_redacted_payload(normalized_payload, home_dir=home_dir),
    )


def _is_guard_action_type(value: object) -> TypeGuard[GuardActionType]:
    return isinstance(value, str) and value in _VALID_ACTION_TYPES


def _required_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise ValueError(f"Guard action envelope missing required integer {key}.")
    return value


def _matching_aliased_value(payload: Mapping[str, object], snake_key: str, camel_key: str) -> object:
    if snake_key in payload and camel_key in payload and payload[snake_key] != payload[camel_key]:
        raise ValueError(f"Guard action envelope {camel_key} must match {snake_key}.")
    return payload.get(snake_key, payload.get(camel_key))


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Guard action envelope missing required string {key}.")
    return value


def _required_action_type(value: object) -> GuardActionType:
    if not _is_guard_action_type(value):
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


def _command_detail(command: str | None, *, home_dir: Path | str | None) -> str | None:
    if command is None:
        return None
    return _redact_path_mentions(redact_text(command).text, home_dir=home_dir)


def _prompt_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    redacted = redact_text(value.strip()).text
    collapsed = " ".join(redacted.split())
    if not collapsed:
        return None
    return collapsed


def _prompt_excerpt(prompt_text: str | None) -> str | None:
    if prompt_text is None:
        return None
    return prompt_text[:_PROMPT_EXCERPT_LIMIT]


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
        secret_context = redacted_secret_path_context(stripped)
        if secret_context is not None:
            return secret_context
        target_name = Path(stripped).name or "path"
        return f".../{target_name}"
    windows_path = PureWindowsPath(stripped)
    if windows_path.is_absolute():
        secret_context = redacted_secret_path_context(stripped)
        if secret_context is not None:
            return secret_context
        target_name = windows_path.name or "path"
        return f".../{target_name}"
    if _is_absolute_target_path(stripped):
        redacted_path = redacted_workspace_label(stripped, home_dir=home_dir)
        if redacted_path is None:
            return None
        if redacted_path.startswith(".../"):
            secret_context = redacted_secret_path_context(stripped)
            if secret_context is not None:
                return secret_context
        return redacted_path
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

    redacted = _GENERIC_WINDOWS_UNC_PATH_PATTERN.sub(replace_path, text)
    redacted = _GENERIC_WINDOWS_ABSOLUTE_PATH_PATTERN.sub(replace_path, redacted)
    redacted = _GENERIC_POSIX_ABSOLUTE_PATH_PATTERN.sub(replace_path, redacted)
    return _PROMPT_PATH_PATTERN.sub(replace_path, redacted)


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
    "normalize_claude_hook_payload",
    "normalize_codex_hook_payload",
    "normalize_copilot_payload",
    "normalize_gemini_payload",
    "normalize_harness_payload",
    "normalize_opencode_payload",
    "redacted_workspace_label",
    "stable_action_hash",
]
