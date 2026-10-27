"""Bounded metadata from the inspected Composio discovery response profile.

This is provider-result evidence, not an authenticated host inventory event.
Neither session IDs nor connection-status labels establish account authority.
The native runtime parses the discovery response; this is the record it
hands back.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ComposioActionSchema:
    toolkit: str
    tool_slug: str
    description: str
    input_schema: dict[str, object]
    full_schema: bool
