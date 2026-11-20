"""Shared harness-env pinning for guard-cli attribution tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

ORIGIN_HARNESS_ENV = "HOL_GUARD_ORIGIN_HARNESS"

HARNESS_ENV_MARKERS = (
    "ZAI_OAUTH_CLIENT_ID",
    "ZAI_OAUTH_ORIGIN",
    "ZCODE_APP_VERSION",
    "ZCODE_BASE_URL",
    "ZCODE_ENV",
    "ZCODE_PROCESS_LABEL",
    "ZCODE_RG_BINARY",
    "ZCODE_RUNTIME_ENV",
    "__CFBundleIdentifier",
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CODEX_SANDBOX",
    "CODEX_THREAD_ID",
    "CURSOR_PROJECT_DIR",
    "CURSOR_SESSION_ID",
    "CURSOR_TRACE_ID",
    "CURSOR_TRANSCRIPT_PATH",
    "CURSOR_VERSION",
    "DEVIN_PROJECT_DIR",
    "GROK_AGENT",
    "GROK_SESSION_ID",
    "MUSE_SESSION_ID",
    "MUSE_THREAD_ID",
    "OPENCODE_CONFIG_CONTENT",
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
