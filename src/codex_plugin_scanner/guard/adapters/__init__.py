"""Harness adapter registry."""

from __future__ import annotations

from .antigravity import AntigravityHarnessAdapter
from .base import HarnessAdapter, HarnessContext
from .claude_code import ClaudeCodeHarnessAdapter
from .codex import CodexHarnessAdapter
from .copilot import CopilotHarnessAdapter
from .cursor import CursorHarnessAdapter
from .gemini import GeminiHarnessAdapter
from .hermes import HermesHarnessAdapter
from .opencode import OpenCodeHarnessAdapter

ADAPTERS: tuple[HarnessAdapter, ...] = (
    CodexHarnessAdapter(),
    ClaudeCodeHarnessAdapter(),
    CopilotHarnessAdapter(),
    CursorHarnessAdapter(),
    AntigravityHarnessAdapter(),
    GeminiHarnessAdapter(),
    HermesHarnessAdapter(),
    OpenCodeHarnessAdapter(),
)


def get_adapter(harness: str) -> HarnessAdapter:
    """Resolve a harness adapter by name."""

    for adapter in ADAPTERS:
        if adapter.harness == harness:
            return adapter
        if harness in getattr(adapter, "aliases", ()):
            return adapter
    raise ValueError(f"Unsupported harness: {harness}")


def list_adapters() -> tuple[HarnessAdapter, ...]:
    """Return the known harness adapters."""

    return ADAPTERS


__all__ = ["HarnessContext", "get_adapter", "list_adapters"]
