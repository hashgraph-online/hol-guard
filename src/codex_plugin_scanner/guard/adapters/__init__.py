"""Harness adapter registry."""

from __future__ import annotations

from .base import HarnessAdapter, HarnessContext
from .claude_code import ClaudeCodeHarnessAdapter
from .codex import CodexHarnessAdapter
from .cursor import CursorHarnessAdapter
from .gemini import GeminiHarnessAdapter
from .opencode import OpenCodeHarnessAdapter

ADAPTERS: tuple[HarnessAdapter, ...] = (
    CodexHarnessAdapter(),
    ClaudeCodeHarnessAdapter(),
    CursorHarnessAdapter(),
    GeminiHarnessAdapter(),
    OpenCodeHarnessAdapter(),
)


def get_adapter(harness: str) -> HarnessAdapter:
    """Resolve a harness adapter by name."""

    for adapter in ADAPTERS:
        if adapter.harness == harness:
            return adapter
    raise ValueError(f"Unsupported harness: {harness}")


def list_adapters() -> tuple[HarnessAdapter, ...]:
    """Return the known harness adapters."""

    return ADAPTERS


__all__ = ["HarnessContext", "get_adapter", "list_adapters"]
