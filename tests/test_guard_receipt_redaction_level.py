"""Tests for configurable receipt redaction levels."""

from __future__ import annotations

from codex_plugin_scanner.guard.config import (
    VALID_RECEIPT_REDACTION_LEVELS,
    _coerce_editable_setting,
    _coerce_loaded_receipt_redaction_level,
)
from codex_plugin_scanner.guard.receipts.manager import _redacted_envelope_dict
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
        assert VALID_RECEIPT_REDACTION_LEVELS == frozenset({"full", "partial", "none"})

    def test_coerce_loaded_default(self):
        assert _coerce_loaded_receipt_redaction_level(None) == "full"
        assert _coerce_loaded_receipt_redaction_level("invalid") == "full"

    def test_coerce_loaded_valid(self):
        assert _coerce_loaded_receipt_redaction_level("full") == "full"
        assert _coerce_loaded_receipt_redaction_level("partial") == "partial"
        assert _coerce_loaded_receipt_redaction_level("none") == "none"

    def test_coerce_editable_valid(self):
        assert _coerce_editable_setting("receipt_redaction_level", "full") == "full"
        assert _coerce_editable_setting("receipt_redaction_level", "partial") == "partial"
        assert _coerce_editable_setting("receipt_redaction_level", "none") == "none"

    def test_coerce_editable_invalid(self):
        try:
            _coerce_editable_setting("receipt_redaction_level", "invalid")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "receipt redaction level" in str(e).lower()


class TestRedactedEnvelopeDictFull:
    def test_full_level_excludes_command(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="full")
        assert "command" not in result
        assert result["command_length"] == len("rm -rf /important-dir")

    def test_full_level_excludes_target_paths(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="full")
        assert "target_paths" not in result
        assert result["target_paths_count"] == 1

    def test_full_level_excludes_network_hosts(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="full")
        assert "network_hosts" not in result
        assert result["network_hosts_count"] == 1

    def test_full_level_excludes_package_name(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="full")
        assert "package_name" not in result
        assert result["has_package_name"] is True

    def test_full_level_default(self):
        """Default redaction level is 'full'."""
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope)
        assert "command" not in result


class TestRedactedEnvelopeDictPartial:
    def test_partial_level_includes_command(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="partial")
        assert result.get("command") == "rm -rf /important-dir"

    def test_partial_level_excludes_target_paths(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="partial")
        assert "target_paths" not in result

    def test_partial_level_excludes_network_hosts(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="partial")
        assert "network_hosts" not in result

    def test_partial_level_excludes_package_name(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="partial")
        assert "package_name" not in result

    def test_partial_level_includes_metadata(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="partial")
        assert result["command_length"] == len("rm -rf /important-dir")
        assert result["tool_name"] == "bash"
        assert result["has_package_name"] is True


class TestRedactedEnvelopeDictNone:
    def test_none_level_includes_command(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert result.get("command") == "rm -rf /important-dir"

    def test_none_level_includes_target_paths(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert result.get("target_paths") == ["/important-dir"]

    def test_none_level_includes_network_hosts(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert result.get("network_hosts") == ["example.com"]

    def test_none_level_includes_package_name(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert result.get("package_name") == "evil-package"

    def test_none_level_includes_metadata(self):
        envelope = _make_envelope()
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert result["command_length"] == len("rm -rf /important-dir")
        assert result["tool_name"] == "bash"


class TestRedactedEnvelopeDictEdgeCases:
    def test_none_command_with_partial(self):
        envelope = _make_envelope(command=None)
        result = _redacted_envelope_dict(envelope, redaction_level="partial")
        assert "command" not in result
        assert result["command_length"] == 0

    def test_empty_package_name_with_none(self):
        envelope = _make_envelope(package_name="")
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert "package_name" not in result
        assert result["has_package_name"] is False

    def test_empty_target_paths_with_none(self):
        envelope = _make_envelope(target_paths=())
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert "target_paths" not in result
        assert result["target_paths_count"] == 0

    def test_empty_network_hosts_with_none(self):
        envelope = _make_envelope(network_hosts=())
        result = _redacted_envelope_dict(envelope, redaction_level="none")
        assert "network_hosts" not in result
        assert result["network_hosts_count"] == 0
