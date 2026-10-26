"""Suggested action dependencies from Composio search, never an MCP Skills declaration."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .composio_contract import composio_tool_role
from .composio_discovery import _response_object

_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class ComposioWorkflowProposal:
    primary: tuple[str, ...]
    supporting: tuple[str, ...]
    guidance_present: bool


def composio_workflow_proposals(tool_name: str, response: object) -> tuple[ComposioWorkflowProposal, ...] | None:
    if composio_tool_role(tool_name) != "discovery":
        return None
    value = _response_object(response)
    data = value.get("data") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("successful") is not True
        or value.get("error") is not None
        or not isinstance(data, dict)
        or data.get("error") is not None
        or ("success" in data and data["success"] is not True)
    ):
        return None
    results = data.get("results", [])
    if not isinstance(results, list) or len(results) > 50:
        return None
    proposals: list[ComposioWorkflowProposal] = []
    for result in results:
        if not isinstance(result, dict):
            return None
        primary = _slugs(result.get("primary_tool_slugs", []))
        supporting = _slugs(result.get("related_tool_slugs", []))
        if primary is None or supporting is None or len(set(primary + supporting)) > 50:
            return None
        steps = result.get("recommended_plan_steps")
        if steps is not None and (
            not isinstance(steps, list)
            or len(steps) > 50
            or any(not isinstance(step, str) or len(step) > 4096 for step in steps)
        ):
            return None
        # Do not retain use cases, plan text/snippets, account status, arguments or session IDs.
        if primary or supporting:
            proposal = ComposioWorkflowProposal(
                primary,
                tuple(slug for slug in supporting if slug not in primary),
                bool(steps),
            )
            if proposal not in proposals:
                proposals.append(proposal)
    return tuple(proposals)


def _slugs(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or len(value) > 50:
        return None
    if any(not isinstance(slug, str) or not _SLUG.fullmatch(slug) for slug in value):
        return None
    return tuple(dict.fromkeys(value))
