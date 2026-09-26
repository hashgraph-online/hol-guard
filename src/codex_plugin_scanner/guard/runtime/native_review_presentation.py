"""Pure projection of Rust action kinds and redacted request inputs for review."""

from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

from ..redaction import redact_review_payload

_NATIVE_ACTION_TYPES = {
    "command": "shell_command",
    "file_read": "file_read",
    "file_write": "file_write",
    "mcp_tool": "mcp_tool",
    "package": "package_script",
    "network": "network_request",
    "config": "config_change",
    "process_service": "config_change",
    "unknown": "config_change",
    "prompt": "prompt",
    "harness": "harness_start",
    "browser": "browser_action",
}
_INPUT_KEYS = ("tool_input", "toolInput", "arguments", "input", "params")
_PATH_KEYS = ("path", "file_path", "filePath", "paths", "file_paths", "filePaths", "target", "target_path")


def normalize_native_review_payload(
    harness: str,
    payload: Mapping[str, object],
    *,
    request_id: str,
    tool_name: str,
    command: str | None,
    launch_target: str,
    workspace: Path | None,
    native_action: object,
) -> dict[str, object]:
    """Never classify paths, normalize commands, read files, or derive approval identity."""
    normalized_harness = harness.strip().lower()
    if not normalized_harness:
        raise ValueError("Native review harness must not be empty")
    if not isinstance(native_action, Mapping):
        raise ValueError("Native action metadata must be a mapping")
    native_kind = native_action.get("action_type")
    if not isinstance(native_kind, str) or native_kind not in _NATIVE_ACTION_TYPES:
        raise ValueError("Native action kind is unsupported")
    action_type = _NATIVE_ACTION_TYPES[native_kind]
    inputs: Mapping[str, object] = {}
    for key in _INPUT_KEYS:
        candidate = payload.get(key)
        if isinstance(candidate, Mapping):
            inputs = candidate
            break
    target_paths: list[str] = []
    if action_type in {"file_read", "file_write"}:
        # Only project declared targets after Rust has supplied their action kind.
        for key in _PATH_KEYS:
            value = inputs.get(key)
            if isinstance(value, str) and value:
                target_paths.append(value)
            elif isinstance(value, list):
                target_paths.extend(item for item in value if isinstance(item, str) and item)
    host = urlparse(launch_target).hostname if action_type == "network_request" and "://" in launch_target else None
    raw_payload = dict(payload)
    raw_payload.setdefault("hook_event_name", "PreToolUse")
    return redact_review_payload(
        {
            "schema_version": 1,
            "action_id": request_id,
            "harness": normalized_harness,
            "event_name": "PreToolUse",
            "action_type": action_type,
            "workspace": str(workspace) if workspace is not None else None,
            "workspace_hash": None,
            "tool_name": tool_name,
            "command": command,
            "prompt_excerpt": None,
            "prompt_text": None,
            "target_paths": list(dict.fromkeys(target_paths)),
            "network_hosts": [host] if host else [],
            "mcp_server": None,
            "mcp_tool": None,
            "package_manager": None,
            "package_name": None,
            "command_category": None,
            "package_intent_kind": None,
            "package_targets": [],
            "script_name": None,
            "pre_execution_result": "review",
            "raw_payload_redacted": raw_payload,
        }
    )
