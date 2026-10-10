"""Shared harness-env pinning for guard-cli attribution tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

from codex_plugin_scanner.guard.adapters.zcode_config import ZCODE_ENV_HINTS
from codex_plugin_scanner.guard.runtime.harness_attribution import (
    _CLAUDE_CODE_ENV_MARKERS,
    _CODEX_ENV_MARKERS,
    _CURSOR_ENV_MARKERS,
    _DEVIN_ENV_MARKERS,
    _GROK_ENV_MARKERS,
    _OPENCODE_ENV_MARKERS,
    ORIGIN_HARNESS_ENV,
)

HARNESS_ENV_MARKERS = (
    *ZCODE_ENV_HINTS,
    "__CFBundleIdentifier",
    *_CLAUDE_CODE_ENV_MARKERS,
    *_CODEX_ENV_MARKERS,
    *_CURSOR_ENV_MARKERS,
    *_DEVIN_ENV_MARKERS,
    *_GROK_ENV_MARKERS,
    *_OPENCODE_ENV_MARKERS,
    ORIGIN_HARNESS_ENV,
)


def strip_harness_env_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin a plain terminal environment so guard-cli attribution is hermetic."""

    for marker in HARNESS_ENV_MARKERS:
        monkeypatch.delenv(marker, raising=False)
    monkeypatch.setenv("__CFBundleIdentifier", "com.apple.Terminal")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.package_protect_projection.resolve_parent_process_harness",
        lambda: None,
    )
