"""Tests for configurable receipt redaction levels."""

from __future__ import annotations

from codex_plugin_scanner.guard.config import (
    VALID_RECEIPT_REDACTION_LEVELS,
    _coerce_loaded_receipt_redaction_level,
)
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope


def _make_envelope(
    *,
    command: str | None = "rm -rf /important-dir",
    target_paths: tuple[str, ...] = ("/important-dir",),
    network_hosts: tuple[str, ...] = ("example.com",),
    package_name: str | None = "evil-package",
) -> GuardActionEnvelope:
    """Build a minimal envelope for testing."""
    return GuardActionEnvelope(
        schema_version=1,
        action_id="test-action-001",
        harness="test-harness",
        event_name="tool_call",
        action_type="command-write",
        workspace="/test",
        workspace_hash="abc123",
        tool_name="bash",
        command=command,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=target_paths,
        network_hosts=network_hosts,
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=package_name,
        package_intent_kind=None,
        package_targets=(),
        pre_execution_result=None,
        script_name=None,
    )


class TestRedactionLevelConfig:
    def test_valid_levels(self):
        assert frozenset({"full", "partial", "none"}) == VALID_RECEIPT_REDACTION_LEVELS

    def test_coerce_loaded_default(self):
        assert _coerce_loaded_receipt_redaction_level(None) == "full"
        assert _coerce_loaded_receipt_redaction_level("invalid") == "full"

    def test_coerce_loaded_valid(self):
        assert _coerce_loaded_receipt_redaction_level("full") == "full"
        assert _coerce_loaded_receipt_redaction_level("partial") == "partial"
        assert _coerce_loaded_receipt_redaction_level("none") == "none"
