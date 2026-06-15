"""Harness adapter registry."""

from __future__ import annotations

from functools import lru_cache
from importlib import import_module

from .base import HarnessAdapter, HarnessContext

_ADAPTER_SPECS: tuple[tuple[str, str], ...] = (
    (".codex", "CodexHarnessAdapter"),
    (".claude_code", "ClaudeCodeHarnessAdapter"),
    (".copilot", "CopilotHarnessAdapter"),
    (".cursor", "CursorHarnessAdapter"),
    (".antigravity", "AntigravityHarnessAdapter"),
    (".gemini", "GeminiHarnessAdapter"),
    (".grok", "GrokHarnessAdapter"),
    (".hermes", "HermesHarnessAdapter"),
    (".kimi", "KimiHarnessAdapter"),
    (".openclaw", "OpenClawHarnessAdapter"),
    (".opencode", "OpenCodeHarnessAdapter"),
)


@lru_cache(maxsize=1)
def _adapters() -> tuple[HarnessAdapter, ...]:
    adapters: list[HarnessAdapter] = []
    for module_name, class_name in _ADAPTER_SPECS:
        adapter_class = getattr(import_module(module_name, __package__), class_name)
        adapters.append(adapter_class())
    return tuple(adapters)


def get_adapter(harness: str) -> HarnessAdapter:
    """Resolve a harness adapter by name."""

    for adapter in _adapters():
        if adapter.harness == harness:
            return adapter
        if harness in getattr(adapter, "aliases", ()):
            return adapter
    raise ValueError(f"Unsupported harness: {harness}")


def list_adapters() -> tuple[HarnessAdapter, ...]:
    """Return the known harness adapters."""

    return _adapters()


__all__ = ["HarnessContext", "get_adapter", "list_adapters"]
