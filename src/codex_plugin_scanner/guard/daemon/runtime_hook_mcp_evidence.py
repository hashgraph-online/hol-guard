"""Private schema-only Composio discovery journal record."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from datetime import datetime

from ..runtime.composio_discovery import ComposioActionSchema, composio_discovered_actions
from ..runtime.composio_workflows import ComposioWorkflowProposal, composio_workflow_proposals
from ..runtime.observed_mcp_tools import observed_mcp_tool

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class _McpDiscoveryRecord:
    record_id: str
    harness: str
    tool_name: str
    occurred_at: str
    actions: tuple[ComposioActionSchema, ...]
    proposals: tuple[ComposioWorkflowProposal, ...] = ()
    payload_bytes: int = 0
    attempts: int = 0

    def serialized(self) -> bytes:
        return (
            json.dumps(
                {
                    "schema": "hol-guard-mcp-provider-evidence.v1",
                    "record_id": self.record_id,
                    "harness": self.harness,
                    "tool_name": self.tool_name,
                    "occurred_at": self.occurred_at,
                    "tool_schemas": {
                        action.tool_slug: {
                            "toolkit": action.toolkit,
                            "tool_slug": action.tool_slug,
                            "description": action.description,
                            "input_schema": action.input_schema,
                            "hasFullSchema": action.full_schema,
                        }
                        for action in self.actions
                    },
                    "workflow_proposals": [
                        {
                            "primary": item.primary,
                            "supporting": item.supporting,
                            "guidance_present": item.guidance_present,
                        }
                        for item in self.proposals
                    ],
                },
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    @classmethod
    def from_json(cls, value: object) -> _McpDiscoveryRecord | None:
        if not isinstance(value, dict) or value.get("schema") != "hol-guard-mcp-provider-evidence.v1":
            return None
        if set(value) not in (
            {"schema", "record_id", "harness", "tool_name", "occurred_at", "tool_schemas"},
            {"schema", "record_id", "harness", "tool_name", "occurred_at", "tool_schemas", "workflow_proposals"},
        ):
            return None
        record_id, harness, tool_name, occurred_at = (
            value.get("record_id"),
            value.get("harness"),
            value.get("tool_name"),
            value.get("occurred_at"),
        )
        if (
            not isinstance(record_id, str)
            or not _SAFE_IDENTIFIER.fullmatch(record_id)
            or not isinstance(harness, str)
            or not isinstance(tool_name, str)
            or not isinstance(occurred_at, str)
            or len(occurred_at) > 64
        ):
            return None
        source = observed_mcp_tool(harness, tool_name)
        if source is None or source.harness != harness:
            return None
        try:
            if datetime.fromisoformat(occurred_at).tzinfo is None:
                return None
        except ValueError:
            return None
        actions = composio_discovered_actions(
            tool_name,
            {
                "successful": True,
                "error": None,
                "data": {"tool_schemas": value.get("tool_schemas")},
            },
        )
        if actions is None:
            return None
        raw_proposals = value.get("workflow_proposals", [])
        if (
            not isinstance(raw_proposals, list)
            or len(raw_proposals) > 50
            or not all(
                isinstance(item, dict)
                and set(item) == {"primary", "supporting", "guidance_present"}
                and type(item["guidance_present"]) is bool
                for item in raw_proposals
            )
        ):
            return None
        proposals = composio_workflow_proposals(
            tool_name,
            {
                "successful": True,
                "error": None,
                "data": {
                    "results": [
                        {
                            "primary_tool_slugs": item.get("primary"),
                            "related_tool_slugs": item.get("supporting"),
                            "recommended_plan_steps": (["present"] if item.get("guidance_present") else []),
                        }
                        for item in raw_proposals
                    ]
                },
            },
        )
        if proposals is None or len(proposals) != len(raw_proposals):
            return None
        record = cls(record_id, harness, tool_name, occurred_at, actions, proposals)
        return replace(record, payload_bytes=len(record.serialized()))
