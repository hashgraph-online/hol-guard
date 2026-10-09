"""Transport contract for the native MCP runtime-evidence owner."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_mcp_runtime_evidence as module
from codex_plugin_scanner.guard.native_mcp_runtime_evidence import (
    NativeMcpRuntimeEvidenceError,
    argument_entries,
    native_command_text,
    native_runtime_action_record,
)


def test_argument_entries_projects_ordered_string_values() -> None:
    assert argument_entries({"a": "x", 1: 2}, mapping_type=dict) == [["a", "x"], ["1", None]]
    assert argument_entries(["a"], mapping_type=dict) is None


def test_unavailable_native_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Status:
        mode = "off"
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    with pytest.raises(NativeMcpRuntimeEvidenceError, match="unavailable"):
        native_command_text("tool", [["command", "ls"]])


def test_mismatched_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Features:
        features = frozenset({module._FEATURE, module._RESIDENT_PROTOCOL_FEATURE})

    class Identity:
        path = "/bin/true"
        sha256 = "0" * 64

    class Status:
        mode = "force"
        available = True
        compatible = True
        identity = Identity()
        capabilities = Features()

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(module, "native_record_resident_failure", lambda *a, **k: None)
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        lambda **_: (
            b'{"schema":"guard-mcp-runtime-evidence-result.v1","request_id":"x","request_sha256":"y",'
            b'"status":"ok","code":"ok","payload":{"command_text":"ls"}}'
        ),
    )
    with pytest.raises(NativeMcpRuntimeEvidenceError):
        native_command_text("tool", [["command", "ls"]])


def test_native_round_trip_end_to_end() -> None:
    assert native_command_text("fs", [["path", " /tmp/a "]]) == "fs /tmp/a"
    record = native_runtime_action_record(
        tool_description="d",
        arguments=[["file_path", "/home/u/secret.txt"]],
        risk_categories=["credential"],
        envelope=None,
    )
    assert record is not None
    assert record["filesTouched"] == ["[redacted]/secret.txt"]
    assert record["claimedCapabilities"] == ["tool_description"]
