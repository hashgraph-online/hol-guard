"""Harness adapter registry."""

from __future__ import annotations

from functools import lru_cache
from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .base import HarnessAdapter, HarnessContext

# ``(module, class)`` for a Python adapter; ``(".native_harness", harness)``
# for one the native ``harness_adapter`` kind answers.
_ADAPTER_SPECS: tuple[tuple[str, str], ...] = (
    (".codex", "CodexHarnessAdapter"),
    (".claude_code", "ClaudeCodeHarnessAdapter"),
    (".copilot", "CopilotHarnessAdapter"),
    (".cursor", "CursorHarnessAdapter"),
    (".cline_runtime", "ClineHarnessAdapter"),
    (".native_harness", "devin"),
    (".native_harness", "antigravity"),
    (".native_harness", "gemini"),
    (".native_harness", "grok"),
    (".hermes", "HermesHarnessAdapter"),
    (".native_harness", "kimi"),
    (".native_harness", "omp"),
    (".native_harness", "pi"),
    (".native_harness", "openclaw"),
    (".opencode_runtime", "OpenCodeHarnessAdapter"),
    (".native_harness", "zcode"),
    (".native_harness", "paseo"),
    (".native_harness", "muse"),
)


@lru_cache(maxsize=1)
def _adapters() -> tuple[HarnessAdapter, ...]:
    from .native_harness import NATIVE_HARNESSES, NativeHarnessAdapter

    native = {harness: (harness, aliases, launcher) for harness, aliases, launcher in NATIVE_HARNESSES}
    adapters: list[HarnessAdapter] = []
    for module_name, name in _ADAPTER_SPECS:
        if module_name == ".native_harness":
            adapters.append(NativeHarnessAdapter(*native[name]))
            continue
        adapter_class = getattr(import_module(module_name, __package__), name)
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


def __getattr__(name: str) -> Any:
    if name in {"HarnessAdapter", "HarnessContext"}:
        value = getattr(import_module(".base", __name__), name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["HarnessContext", "get_adapter", "list_adapters"]
