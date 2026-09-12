"""Canonical agent identities accepted by Guard inventory snapshots."""

from __future__ import annotations

from typing import Literal

AgentInventoryType = Literal[
    "hermes",
    "openclaw",
    "codex",
    "claude-code",
    "cursor",
    "antigravity",
    "gemini",
    "opencode",
    "kimi",
    "grok",
    "pi",
    "omp",
    "zcode",
    "paseo",
]
_AGENT_INVENTORY_TYPES: tuple[AgentInventoryType, ...] = (
    "hermes",
    "openclaw",
    "codex",
    "claude-code",
    "cursor",
    "antigravity",
    "gemini",
    "opencode",
    "kimi",
    "grok",
    "pi",
    "omp",
    "zcode",
    "paseo",
)


def agent_type(value: str) -> AgentInventoryType:
    """Normalize a harness identity to the inventory contract's supported agent types."""
    for agent_type in _AGENT_INVENTORY_TYPES:
        if value == agent_type:
            return agent_type
    return "codex"
