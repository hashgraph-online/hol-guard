"""Adapter registry and selection helpers."""

from __future__ import annotations

from .base import EcosystemAdapter
from .claude import ClaudeAdapter
from .codex import CodexAdapter
from .gemini import GeminiAdapter
from .opencode import OpenCodeAdapter
from .types import Ecosystem


def get_default_adapters() -> tuple[EcosystemAdapter, ...]:
    """Return the built-in ecosystem adapters."""

    return (
        CodexAdapter(),
        ClaudeAdapter(),
        GeminiAdapter(),
        OpenCodeAdapter(),
    )


def resolve_ecosystem(value: str | None) -> Ecosystem | None:
    """Resolve a CLI ecosystem value."""

    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("", "auto"):
        return None
    try:
        return Ecosystem(lowered)
    except ValueError:
        return None


def list_supported_ecosystems() -> tuple[str, ...]:
    """List supported ecosystem ids."""

    return tuple(adapter.ecosystem_id.value for adapter in get_default_adapters())
