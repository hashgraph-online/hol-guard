"""Suggested action dependencies from Composio search, never an MCP Skills declaration.

The native runtime reads them from the discovery response; this is the record
it hands back.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ComposioWorkflowProposal:
    primary: tuple[str, ...]
    supporting: tuple[str, ...]
    guidance_present: bool
