"""Native claim for an optional trusted MCP task mutation budget."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request

FEATURE = "mcp-task-write-budget-v1"
_REQUEST_SCHEMA = "guard-mcp-write-budget-claim-request.v1"
_RESULT_SCHEMA = "guard-mcp-write-budget-claim-result.v1"
_DECISIONS = frozenset({"inactive", "allow", "block"})
_REASONS = frozenset(
    {
        "no_policy",
        "read_only",
        "claimed",
        "invalid_request",
        "write_budget_exhausted",
        "budget_state_invalid",
        "policy_invalid",
        "guard_home_invalid",
        "invalid_arguments",
        "record_id_reserved",
        "required_source_references_missing",
        "tool_not_authorized",
        "tool_write_limit_exhausted",
    }
)


class NativeMcpWriteBudgetError(ValueError):
    """No bound native answer; the MCP call must not reach its server."""


def shallow_tool_argument_problem(tool_definition: dict[str, Any], arguments: object) -> str | None:
    """Catch definite top-level schema errors before a fail-closed write claim."""
    schema = tool_definition.get("inputSchema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return None
    properties = schema.get("properties")
    required = schema.get("required", [])
    if (
        not isinstance(properties, dict)
        or len(properties) > 128
        or not isinstance(required, list)
        or len(required) > 128
        or any(not isinstance(name, str) for name in required)
    ):
        return None
    if not isinstance(arguments, dict):
        return "tool arguments must be an object"
    safe = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
    missing = sorted(name for name in required if name not in arguments and safe.fullmatch(name))
    if missing:
        return f"required tool argument missing: {missing[0]}"
    if schema.get("additionalProperties") is False:
        extra = sorted(
            name for name in arguments if name not in properties and isinstance(name, str) and safe.fullmatch(name)
        )
        if extra:
            return f"unexpected tool argument: {extra[0]}"
    return None


def _budget_argument_projection(tool_name: str, arguments: object) -> object:
    """Bound the resident request to fields used by its task policy."""
    if not isinstance(arguments, dict):
        return None
    projected: dict[str, object] = {}
    record_id = arguments.get("record_id")
    if isinstance(record_id, str) and len(record_id) <= 256:
        projected["record_id"] = record_id
    data = arguments.get("data")
    if not isinstance(data, dict):
        return projected
    artifact = data
    if tool_name.endswith(".update"):
        notes = data.get("notes", data.get("internal_notes"))
        if isinstance(notes, list) and notes and isinstance(notes[-1], dict):
            artifact = notes[-1]
    ids, versions = artifact.get("source_ids"), artifact.get("source_versions")
    if (
        isinstance(ids, list)
        and len(ids) <= 128
        and all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", value) for value in ids)
        and isinstance(versions, dict)
        and len(versions) <= 128
        and all(
            isinstance(key, str)
            and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", key)
            and type(value) is int
            and 1 <= value <= 2**63 - 1
            for key, value in versions.items()
        )
    ):
        projected["data"] = {"source_ids": ids, "source_versions": versions}
    return projected


def claim_mcp_write_budget(*, guard_home: Path, tool_name: str, arguments: object) -> tuple[str, str, tuple[str, ...]]:
    if os.name != "posix":
        return "inactive", "no_policy", ()
    request_id = f"mcp-write-budget-{uuid4().hex}"
    if not ensure_resident_prerequisite(guard_home):
        raise NativeMcpWriteBudgetError("resident prerequisite unavailable")
    reply = _resident_request(
        operation="mcp_write_budget_claim",
        request={
            "schema": _REQUEST_SCHEMA,
            "request_id": request_id,
            "guard_home": str(guard_home),
            "tool_name": tool_name,
            "arguments": _budget_argument_projection(tool_name, arguments),
        },
        guard_home=guard_home,
        timeout_seconds=5,
        required_feature=FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    missing_source_ids = reply.get("missing_source_ids") if reply is not None else None
    decision = reply.get("decision") if reply is not None else None
    reason = reply.get("reason") if reply is not None else None
    if (
        reply is None
        or set(reply) != {"schema", "request_id", "status", "decision", "reason", "remaining", "missing_source_ids"}
        or reply.get("request_id") != request_id
        or reply.get("status") != "ok"
        or not isinstance(decision, str)
        or decision not in _DECISIONS
        or not isinstance(reason, str)
        or reason not in _REASONS
        or not (reply.get("remaining") is None or type(reply.get("remaining")) is int)
        or not isinstance(missing_source_ids, list)
        or len(missing_source_ids) > 128
        or any(
            not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", value)
            for value in missing_source_ids
        )
    ):
        raise NativeMcpWriteBudgetError("native mutation-budget answer invalid")
    assert isinstance(decision, str) and isinstance(reason, str) and isinstance(missing_source_ids, list)
    if (decision == "inactive") != (reason == "no_policy"):
        raise NativeMcpWriteBudgetError("native mutation-budget answer inconsistent")
    missing = tuple(cast(str, value) for value in missing_source_ids)
    if bool(missing) != (reason == "required_source_references_missing"):
        raise NativeMcpWriteBudgetError("native mutation-budget provenance answer inconsistent")
    return decision, reason, missing
