"""Stable action identity normalization for Guard policy deduplication.

Provides normalizers for command, prompt, and MCP tool call identities.
The output of each normalizer is a stable string suitable for comparison
or hashing across repeated calls with transient variation stripped out.
"""

from __future__ import annotations

import hashlib
import json
import re

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[mABCDEFGHJKSTfhinsu]")

_REQUEST_ID_PATTERN = re.compile(
    r"\b(?:req|request|approval|id)[-_][a-zA-Z0-9_-]{4,64}\b",
    re.IGNORECASE,
)

_TIMESTAMP_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?\b")

_PORT_FLAG_PATTERN = re.compile(
    r"(?:--port|-p)\s+\d{2,5}\b",
    re.IGNORECASE,
)

_MARKDOWN_BOLD_ITALIC = re.compile(r"\*{1,3}|(?<!\w)_{1,3}(?=\w)|(?<=\w)_{1,3}(?!\w)")

_BACKTICK_INLINE_CODE = re.compile(r"`([^`]+)`")

_GENERIC_REQUEST_ID_IN_ARGS = re.compile(r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b")


def normalize_command_identity(command: str) -> str:
    """Return a stable identity string for a shell command.

    Strips ANSI codes, daemon ports, timestamps, approval request IDs,
    UUIDs, and excess whitespace while preserving the command name,
    meaningful arguments, target paths, and network hosts.
    """
    normalized = _ANSI_ESCAPE.sub("", command)
    normalized = _REQUEST_ID_PATTERN.sub("<request-id>", normalized)
    normalized = _GENERIC_REQUEST_ID_IN_ARGS.sub("<uuid>", normalized)
    normalized = _TIMESTAMP_PATTERN.sub("<timestamp>", normalized)
    normalized = _PORT_FLAG_PATTERN.sub("<port-flag>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def normalize_prompt_identity(prompt: str) -> str:
    """Return a stable identity string for a prompt text.

    Strips markdown bold/italic formatting and normalises whitespace,
    while preserving the requested sensitive targets (file paths, keys,
    tokens, named secrets).
    """
    normalized = _MARKDOWN_BOLD_ITALIC.sub("", prompt)
    normalized = _BACKTICK_INLINE_CODE.sub(r"\1", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    normalized = normalized.lower()
    return normalized


def normalize_mcp_identity(call: dict[str, object]) -> str:
    """Return a stable identity hash for an MCP tool call.

    The identity is derived from:
    - server_id
    - tool_name
    - arguments (sorted keys, stable JSON)
    - schema_hash (when present)

    Returns a hex digest suitable for equality comparison.
    """
    server_id = str(call.get("server_id", ""))
    tool_name = str(call.get("tool_name", ""))
    arguments = call.get("arguments", {})
    schema_hash = str(call.get("schema_hash", ""))

    stable_args = json.dumps(
        {k: v for k, v in sorted(arguments.items())} if isinstance(arguments, dict) else arguments,
        sort_keys=True,
        ensure_ascii=True,
    )
    identity_source = f"{server_id}:{tool_name}:{stable_args}:{schema_hash}"
    return hashlib.sha256(identity_source.encode("utf-8")).hexdigest()


def normalize_browser_mcp_identity(call: dict[str, object]) -> str:
    """Return a stable identity hash for a browser MCP tool call.

    Uses browser-aware fields: server identity, tool identity, intent,
    operation, origin, path prefix, profile mode, sensitive flags, and
    schema hash. Volatile fields (timeout, pageId, etc.) are dropped.

    Returns a hex digest suitable for equality comparison.
    """
    server_id = str(call.get("server_id", call.get("server_identity_hash", "")))
    tool_name = str(call.get("tool_name", call.get("operation", "")))
    intent = str(call.get("intent", ""))
    operation = str(call.get("operation", tool_name))
    target_origin = str(call.get("target_origin", ""))
    target_path_prefix = str(call.get("target_path_prefix", ""))
    profile_mode = str(call.get("profile_mode", ""))
    schema_hash = str(call.get("schema_hash", call.get("mcp_schema_hash", "")))
    sensitive_flags = call.get("sensitive_surface_flags") or ()
    if isinstance(sensitive_flags, (list, tuple)):
        sensitive_flags_str = ",".join(sorted(str(f) for f in sensitive_flags))
    else:
        sensitive_flags_str = str(sensitive_flags)

    identity_source = (
        f"{server_id}:{tool_name}:{intent}:{operation}:"
        + f"{target_origin}:{target_path_prefix}:{profile_mode}:"
        + f"{schema_hash}:{sensitive_flags_str}"
    )
    return hashlib.sha256(identity_source.encode("utf-8")).hexdigest()
