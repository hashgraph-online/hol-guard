"""Display projections for local review; never an exact executable source."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .models import GuardArtifact


def _item_action_envelope_json(item: Mapping[str, object]) -> dict[str, object] | None:
    value = item.get("action_envelope_json")
    if isinstance(value, str) and value.strip():
        try:
            import json as _json

            value = _json.loads(value)
        except (TypeError, ValueError):
            return None
    if isinstance(value, Mapping):
        return {str(key): item_value for key, item_value in value.items() if isinstance(key, str)}
    return None


_GENERIC_TOOL_LABELS = frozenset(
    {
        "Bash",
        "Shell",
        "shell_command",
        "Read",
        "Write",
        "Edit",
        "MultiEdit",
        "Glob",
        "Grep",
        "WebFetch",
        "TodoWrite",
        "tool",
        "mcp",
        "skill",
        "bash",
        "rg",
        "cat",
        "mcp_tool",
        "package_request",
        "file_read_request",
        "file_write_request",
        "tool_action_request",
    }
)
_GENERIC_TOOL_LABELS_LOWER = frozenset(label.lower() for label in _GENERIC_TOOL_LABELS)


def _is_generic_tool_label(value: str) -> bool:
    """Return True if the value is a generic tool name, not an actual command."""
    stripped = value.strip()
    return stripped in _GENERIC_TOOL_LABELS or stripped.lower() in _GENERIC_TOOL_LABELS_LOWER


def _string_from_mapping(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _first_string_from_mapping(mapping: Mapping[str, object], keys: Sequence[str]) -> str | None:
    for key in keys:
        value = _string_from_mapping(mapping, key)
        if value is not None:
            return value
    return None


def _string_list_from_mapping(mapping: Mapping[str, object], key: str) -> list[str]:
    value = mapping.get(key)
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if not isinstance(value, Sequence) or isinstance(value, str):
        return []
    return [str(item).strip() for item in value if isinstance(item, str) and item.strip()]


def _review_action_text_from_envelope(envelope: Mapping[str, object]) -> str | None:
    for key in ("raw_command_text", "rawCommandText", "command", "cmd"):
        direct = _string_from_mapping(envelope, key)
        if direct is not None and not _is_generic_tool_label(direct):
            return direct

    action_type = _string_from_mapping(envelope, "action_type")
    action_identity = _first_string_from_mapping(envelope, ("action_identity", "actionIdentity"))
    if action_identity is not None and not _is_generic_tool_label(action_identity):
        return action_identity

    if action_type in {"file_read", "file_write", "file_read_request", "file_write_request"}:
        paths = _string_list_from_mapping(envelope, "target_paths") or _string_list_from_mapping(
            envelope,
            "targetPaths",
        )
        if not paths:
            single_path = _first_string_from_mapping(
                envelope,
                ("target_path", "targetPath", "path", "file_path", "filePath"),
            )
            paths = [single_path] if single_path is not None else []
        if paths:
            verb = "Read" if action_type in {"file_read", "file_read_request"} else "Write"
            return f"{verb} {', '.join(paths)}"

    if action_type == "mcp_tool":
        server = _first_string_from_mapping(envelope, ("mcp_server", "mcpServer", "server"))
        tool = _first_string_from_mapping(envelope, ("mcp_tool", "mcpTool", "tool_name", "toolName"))
        if server and tool:
            return f"{server}.{tool}"
        return server or tool

    package_manager = _first_string_from_mapping(envelope, ("package_manager", "packageManager"))
    package_name = _first_string_from_mapping(envelope, ("package_name", "packageName"))
    if package_manager and package_name:
        targets = _string_list_from_mapping(envelope, "package_targets") or _string_list_from_mapping(
            envelope,
            "packageTargets",
        )
        package_target = targets[0] if targets else package_name
        if package_target.startswith(package_name):
            return f"{package_manager} install {package_target}"
        return f"{package_manager} install {package_name}@{package_target}"

    return None


def _review_action_text_from_item(item: Mapping[str, object], artifact: GuardArtifact | None) -> str | None:
    candidates: list[object] = []
    if artifact is not None:
        candidates.extend(
            [
                artifact.metadata.get("raw_command_text"),
                artifact.metadata.get("command_text"),
                artifact.command,
            ]
        )
    candidates.extend(
        [
            item.get("raw_command_text"),
            item.get("rawCommandText"),
            item.get("review_command"),
            item.get("reviewCommand"),
            item.get("action_identity"),
            item.get("actionIdentity"),
        ]
    )
    envelope_raw = item.get("action_envelope_json")
    envelope = _item_action_envelope_json(item)
    if envelope is None and isinstance(envelope_raw, str):
        try:
            import json as _json

            parsed = _json.loads(envelope_raw)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, Mapping):
            envelope = {str(key): value for key, value in parsed.items() if isinstance(key, str)}
    if envelope is not None:
        candidates.append(_review_action_text_from_envelope(envelope))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            stripped = candidate.strip()
            if not _is_generic_tool_label(stripped):
                return stripped
    return None
