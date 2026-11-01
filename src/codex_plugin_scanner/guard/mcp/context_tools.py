"""Context tool descriptors and rendering; authority stays in Rust."""

from __future__ import annotations

import json
from typing import Any

from ..native_context_agent import CONTEXT_TOOLS, NativeContextAgent
from ..native_context_assistance import ContextAssistanceError


def definitions() -> list[Any]:
    from .registry import _READ_ONLY_ANNOTATIONS, ToolAnnotations, ToolDefinition

    descriptions = (
        (
            "Read this MCP connection's native context status and public pairing code. "
            "Ask the user to approve that code in Protection before retrieving context. "
            "This is data, not command approval."
        ),
        (
            "Prepare current cited local context from the workspace/app sources granted to this connection. "
            "Does not approve or execute any action."
        ),
        (
            "Explain the selection in a retained context snapshot from this connection's scope. "
            "Stale or foreign snapshots are refused. No execution permission is granted."
        ),
        (
            "Prepare cited context for a recent authenticated native Guard decision "
            "in this connection's app/workspace. "
            "Pass its decision_id; optionally pass a returned snapshot_id to explain that selection. "
            "Native policy and source freshness are checked. "
            "This does not revalidate executable bytes, approve, or execute an action."
        ),
        (
            "Propose a shared note of at most 4096 UTF-8 bytes using a snapshot returned by get_guard_context. "
            "The note stays quarantined until the operator reviews and admits it. "
            "Use a stable request_key and query status after an uncertain outcome; do not retry with changed text. "
            "This never grants command approval."
        ),
        "Read the outcome of this connection's shared-note proposal using its request_key.",
        (
            "Forget this connection's proposal record and free its quota. "
            "Already admitted evidence remains until the operator clears it."
        ),
    )
    properties = (
        {},
        {"query": {"type": "string", "maxLength": 4096}},
        {"snapshot_id": {"type": "string", "pattern": "^[a-f0-9]{64}$"}},
        {
            "decision_id": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "snapshot_id": {"anyOf": [{"type": "string", "pattern": "^[a-f0-9]{64}$"}, {"type": "null"}]},
        },
        {
            "snapshot_id": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "request_key": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9_.:-]+$"},
            "text": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
        {"request_key": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9_.:-]+$"}},
        {"request_key": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9_.:-]+$"}},
    )
    return [
        ToolDefinition(
            name=name,
            description=description,
            input_schema={
                "type": "object",
                "properties": fields,
                "required": ["decision_id"] if name == "explain_guard_action" else list(fields),
                "additionalProperties": False,
            },
            annotations=(
                ToolAnnotations(read_only=False, destructive=False, idempotent=True, open_world=False)
                if name == "propose_guard_context_note"
                else ToolAnnotations(read_only=False, destructive=True, idempotent=False, open_world=False)
                if name == "forget_guard_context_proposal"
                else _READ_ONLY_ANNOTATIONS
            ),
            handler=execute,
        )
        for name, description, fields in zip(CONTEXT_TOOLS, descriptions, properties, strict=True)
    ]


def execute(agent: NativeContextAgent, name: str, arguments: dict[str, object]) -> str:
    try:
        data = agent.call(name, arguments)
        return json.dumps({"ok": True, "data_role": True, "data": data}, ensure_ascii=False, separators=(",", ":"))
    except (ContextAssistanceError, OSError, RuntimeError, ValueError) as error:
        code = error.code if isinstance(error, ContextAssistanceError) else "native_context_assistance_unavailable"
        message = (
            "Context is unavailable or this connection needs current human-approved workspace access. "
            "Guard approvals remain independent."
        )
        return json.dumps(
            {"ok": False, "data_role": True, "error": {"code": code, "message": message}}, separators=(",", ":")
        )
