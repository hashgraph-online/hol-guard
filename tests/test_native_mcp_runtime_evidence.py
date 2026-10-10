"""Transport contract for the native MCP runtime-evidence owner."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_mcp_runtime_evidence as module
from codex_plugin_scanner.guard.native_mcp_runtime_evidence import (
    NativeMcpRuntimeEvidenceError,
    argument_entries,
    native_command_text,
    native_receipt_evidence,
    native_runtime_action_record,
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


def test_oversized_consumed_value_raises_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    with pytest.raises(NativeMcpRuntimeEvidenceError, match="request_too_large"):
        native_command_text("tool", [["command", "x" * (512 * 1024)]])


def test_non_ascii_canonical_expansion_is_rejected_client_side(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    # ~100 KiB of UTF-8 that escapes to >256 KiB in the ASCII canonical form.
    with pytest.raises(NativeMcpRuntimeEvidenceError, match="request_too_large"):
        native_command_text("tool", [["command", "\U0001f600" * 30_000]])


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


def test_request_uses_explicit_guard_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _force_available(monkeypatch)
    seen: list[Path] = []

    def client(**kwargs: object) -> None:
        seen.append(kwargs["guard_home"])  # type: ignore[arg-type]

    monkeypatch.setattr(module, "native_resident_client_request", client)
    with pytest.raises(NativeMcpRuntimeEvidenceError):
        native_command_text("tool", [["command", "ls"]], guard_home=tmp_path / "custom")
    assert seen == [tmp_path / "custom"]


def test_client_exceptions_become_typed_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    for error in (RuntimeError("thread"), OSError("pipe"), TimeoutError("slow")):

        def client(error: Exception = error, **_kwargs: object) -> bytes:
            raise error

        monkeypatch.setattr(module, "native_resident_client_request", client)
        with pytest.raises(NativeMcpRuntimeEvidenceError, match="resident_unavailable"):
            native_command_text("tool", [["command", "ls"]])


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
