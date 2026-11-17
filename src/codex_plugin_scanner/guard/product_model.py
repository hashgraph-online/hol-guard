"""Harness names the top-level CLI dispatches to HOL Guard."""

from __future__ import annotations

from codex_plugin_scanner.guard.harness.contract_registry import harness_names


def __getattr__(name: str) -> object:
    # The names come from the native runtime on first use, never at import.
    if name == "SUPPORTED_HARNESS_VALUES":
        return harness_names()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
