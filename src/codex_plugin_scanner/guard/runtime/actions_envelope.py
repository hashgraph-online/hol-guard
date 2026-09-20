"""Typed action-envelope serialization and stable action identity."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Literal, TypeGuard

from ..action_lattice import is_action_bearing_key

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
    command_category: str | None = None
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
            "command_category": self.command_category,
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
                "command_category",
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
            command_category=_string_value(payload.get("command_category")),
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


def _normalized_command(command: str | None) -> str | None:
    if command is None:
        return None
    return command.strip()
