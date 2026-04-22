"""Copilot harness adapter."""

from __future__ import annotations

from .codex import CodexHarnessAdapter


class CopilotHarnessAdapter(CodexHarnessAdapter):
    """Reuse the Codex local config model for Copilot CLI sessions."""

    harness = "copilot"
    executable = "copilot"
    approval_summary = "Guard routes Copilot launch approval through the local approval center."
    fallback_hint = "Use the local Guard inbox when Copilot cannot resolve the review inline."
