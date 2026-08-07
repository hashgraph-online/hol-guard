"""Typed MCP tool registry — single source of truth for tool definitions.

Consumed by ``list_tools``, direct ``call_tool``, and FastMCP stdio
registration.  A new tool cannot appear in one surface and disappear from
another.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_LOOPBACK_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def parse_loopback_origin(approval_url_base: object) -> str | None:
    """Validate a trusted loopback daemon origin from the approval center locator.

    Accepts only ``http``/``https`` schemes pointing at a loopback host
    (``127.0.0.1``, ``localhost``, ``::1``).  Returns the canonical
    ``scheme://netloc`` form (preserving port and IPv6 brackets), or ``None``
    if the value is not a string, malformed, or not loopback.  Pure: never
    reads the filesystem and never accepts a caller-supplied origin.
    """
    if not isinstance(approval_url_base, str) or not approval_url_base:
        return None
    try:
        parsed = urlparse(approval_url_base)
        hostname = parsed.hostname or ""
    except ValueError:
        return None
    if parsed.scheme not in _LOOPBACK_SCHEMES:
        return None
    if hostname not in _LOOPBACK_HOSTS:
        return None
    netloc = parsed.netloc
    if not netloc:
        return None
    return f"{parsed.scheme}://{netloc}"


AnnotationHint = Literal[
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
]


@dataclass(frozen=True, slots=True)
class ToolAnnotations:
    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool

    def to_dict(self) -> dict[str, bool]:
        return {
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        }


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, object]
    annotations: ToolAnnotations
    handler: Callable[..., Any]


_READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only=True,
    destructive=False,
    idempotent=True,
    open_world=False,
)

_VALIDATE_POLICY_ANNOTATIONS = ToolAnnotations(
    read_only=True,
    destructive=False,
    idempotent=True,
    open_world=False,
)

_CREATE_POLICY_ANNOTATIONS = ToolAnnotations(
    read_only=False,
    destructive=True,
    idempotent=True,
    open_world=False,
)

_GET_POLICY_CREATION_ANNOTATIONS = ToolAnnotations(
    read_only=True,
    destructive=False,
    idempotent=True,
    open_world=False,
)

_SEARCH_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Free-text search query."},
    },
    "required": ["query"],
}

_FETCH_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "id": {"type": "string", "description": "Opaque document ID from search results."},
    },
    "required": ["id"],
    "additionalProperties": False,
}

_GET_STATUS_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

_VALIDATE_POLICY_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "policyYaml": {"type": "string", "description": "Canonical GuardPolicy YAML to validate."},
        "mode": {
            "type": "string",
            "enum": ["merge", "replace"],
            "description": "Import mode (default: merge).",
            "default": "merge",
        },
    },
    "required": ["policyYaml"],
    "additionalProperties": False,
}

_CREATE_POLICY_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "policyYaml": {"type": "string", "description": "Canonical GuardPolicy YAML to create."},
        "mode": {
            "type": "string",
            "enum": ["merge", "replace"],
            "description": "Import mode.",
        },
        "candidateDigest": {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
            "description": "64 lowercase hex characters from validate_policy.",
        },
        "expectedCurrentDigest": {
            "type": ["string", "null"],
            "pattern": "^[0-9a-f]{64}$",
            "description": "Current policy digest from validate_policy, or null if no policy exists.",
        },
        "idempotencyKey": {
            "type": "string",
            "pattern": "^[A-Za-z0-9._~-]{8,128}$",
            "description": "8-128 URL-safe characters for replay-safe idempotency.",
        },
    },
    "required": ["policyYaml", "mode", "candidateDigest", "expectedCurrentDigest", "idempotencyKey"],
    "additionalProperties": False,
}

_GET_POLICY_CREATION_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "requestId": {
            "type": "string",
            "description": "Opaque MCP policy request ID from create_policy.",
        },
    },
    "required": ["requestId"],
    "additionalProperties": False,
}


def build_tool_registry() -> list[ToolDefinition]:
    """Build the complete typed tool registry.

    Returns all six tools with their schemas, annotations, and handlers.
    The original three tools preserve their existing behavior byte-for-byte.
    """
    from .policy_tools import (
        execute_create_policy,
        execute_get_policy_creation,
        execute_validate_policy,
    )
    from .tools import execute_fetch, execute_get_guard_status, execute_search

    return [
        ToolDefinition(
            name="search",
            description="Search the Guard knowledge base for relevant documentation and guidance.",
            input_schema=_SEARCH_SCHEMA,
            annotations=_READ_ONLY_ANNOTATIONS,
            handler=execute_search,
        ),
        ToolDefinition(
            name="fetch",
            description="Fetch a specific document by its opaque ID from search results.",
            input_schema=_FETCH_SCHEMA,
            annotations=_READ_ONLY_ANNOTATIONS,
            handler=execute_fetch,
        ),
        ToolDefinition(
            name="get_guard_status",
            description="Get the current Guard runtime status, including policy authoring availability.",
            input_schema=_GET_STATUS_SCHEMA,
            annotations=_READ_ONLY_ANNOTATIONS,
            handler=execute_get_guard_status,
        ),
        ToolDefinition(
            name="validate_policy",
            description=(
                "Validate a canonical GuardPolicy YAML document without writing any state. "
                "Returns candidate/current digests, semantic diff, and write plan. "
                "Read-only, non-destructive, idempotent, closed-world."
            ),
            input_schema=_VALIDATE_POLICY_SCHEMA,
            annotations=_VALIDATE_POLICY_ANNOTATIONS,
            handler=execute_validate_policy,
        ),
        ToolDefinition(
            name="create_policy",
            description=(
                "Stage a digest-bound policy creation request and initiate secure out-of-band "
                "human approval. Does not activate policy while pending. Changes active local "
                "enforcement only after human approval through the Guard dashboard. "
                "Non-read-only, destructive, idempotent, closed-world."
            ),
            input_schema=_CREATE_POLICY_SCHEMA,
            annotations=_CREATE_POLICY_ANNOTATIONS,
            handler=execute_create_policy,
        ),
        ToolDefinition(
            name="get_policy_creation",
            description=(
                "Read the status of one policy creation request by opaque request ID. "
                "Returns pending, applied, declined, expired, or failed. "
                "Read-only, non-destructive, idempotent, closed-world."
            ),
            input_schema=_GET_POLICY_CREATION_SCHEMA,
            annotations=_GET_POLICY_CREATION_ANNOTATIONS,
            handler=execute_get_policy_creation,
        ),
    ]


def list_tool_names() -> list[str]:
    return [tool.name for tool in build_tool_registry()]


def get_tool_definition(name: str) -> ToolDefinition | None:
    for tool in build_tool_registry():
        if tool.name == name:
            return tool
    return None


__all__ = [
    "ToolAnnotations",
    "ToolDefinition",
    "build_tool_registry",
    "get_tool_definition",
    "list_tool_names",
    "parse_loopback_origin",
]
