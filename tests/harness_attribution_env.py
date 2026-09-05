"""Shared harness-env pinning for guard-cli attribution tests."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.adapters.zcode_config import ZCODE_ENV_HINTS
from codex_plugin_scanner.guard.runtime.harness_attribution import (
    _CLAUDE_CODE_ENV_MARKERS,
    _CODEX_ENV_MARKERS,
    _CURSOR_ENV_MARKERS,
)

HARNESS_ENV_MARKERS = (
    *ZCODE_ENV_HINTS,
    "__CFBundleIdentifier",
    *_CLAUDE_CODE_ENV_MARKERS,
    *_CODEX_ENV_MARKERS,
    *_CURSOR_ENV_MARKERS,
)


def strip_harness_env_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin a plain terminal environment so guard-cli attribution is hermetic."""

    for marker in HARNESS_ENV_MARKERS:
        monkeypatch.delenv(marker, raising=False)
    monkeypatch.setenv("__CFBundleIdentifier", "com.apple.Terminal")
