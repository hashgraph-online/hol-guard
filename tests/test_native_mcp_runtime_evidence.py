"""Transport contract for the native MCP runtime-evidence owner."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_mcp_runtime_evidence as module
from codex_plugin_scanner.guard.native_mcp_runtime_evidence import (
    argument_entries,
    native_receipt_evidence,
)


def test_argument_entries_projects_only_consumed_keys_in_order() -> None:
    assert argument_entries({"a": "x", "path": "p", "cmd": 2, 1: 2}, mapping_type=dict) == [
        ["path", "p"],
        ["cmd", None],
    ]
    assert argument_entries(["a"], mapping_type=dict) is None


def test_large_unconsumed_argument_is_not_shipped(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = argument_entries({"content": "x" * (512 * 1024), "command": "ls"}, mapping_type=dict)
    assert entries == [["command", "ls"]]


def test_python_key_sets_mirror_the_rust_contract() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "rust/crates/guard-contracts/src/mcp_runtime_evidence.rs"
    ).read_text(encoding="utf-8")

    def rust_keys(name: str) -> tuple[str, ...]:
        match = re.search(rf"pub const {name}: &\[&str\] = &\[(.*?)\];", source, re.S)
        assert match is not None, name
        return tuple(re.findall(r'"([^"]+)"', match.group(1)))

    assert rust_keys("MCP_RUNTIME_EVIDENCE_COMMAND_ARGUMENT_KEYS") == module._COMMAND_ARGUMENT_KEYS
    assert rust_keys("MCP_RUNTIME_EVIDENCE_PATH_ARGUMENT_KEYS") == module._PATH_ARGUMENT_KEYS
    assert rust_keys("MCP_RUNTIME_EVIDENCE_PATH_TOKENS") == module._PATH_TOKENS


def _force_available(monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_receipt_evidence_single_round_trip_end_to_end(tmp_path: Path) -> None:
    text, record = native_receipt_evidence(
        artifact_name="fs",
        tool_description="d",
        arguments=[["path", "/tmp/a"]],
        risk_categories=["credential"],
        guard_home=tmp_path,
    )
    assert text == "fs /tmp/a"
    assert record is not None
    assert record["claimedCapabilities"] == ["tool_description"]
