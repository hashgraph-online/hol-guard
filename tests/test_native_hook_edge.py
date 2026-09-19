from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_command_model
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge, review_raw_hook_native
from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
)
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)


def _edge_result() -> dict[str, object]:
    edge: dict[str, object] = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "result": {
            "schema": "guard-pre-tool-result.v1",
            "version": 1,
            "authority": "rust",
            "action": {
                "schema": "guard-pre-tool-action.v1",
                "version": 1,
                "harness": "claude-code",
                "event": "PreToolUse",
                "action_type": "command",
                "operation": "execute",
                "bounded": True,
                "sensitive_target": False,
            },
            "decision": "allow",
            "policy_action": "allow",
            "minimum_action": "allow",
            "reason_code": "native_exact_safe_command",
            "reason": "bounded command allowed by Rust",
            "explicitly_benign": True,
        },
    }
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "request-1",
        "request_digest": "a" * 64,
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "allow",
        "model_output_action": "not_applicable",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_exact_safe_command",
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 100,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    edge["receipt"] = receipt
    return edge


def test_edge_decoder_accepts_omitted_optional_request_id() -> None:
    assert _decode_edge(_edge_result()) == _edge_result()
    with_extra = _edge_result()
    with_extra["semantic_override"] = "allow"
    assert _decode_edge(with_extra) is None


def test_edge_decoder_requires_receipt_bound_to_result() -> None:
    missing_receipt = _edge_result()
    del missing_receipt["receipt"]
    assert _decode_edge(missing_receipt) is None

    mutated_result = _edge_result()
    result = mutated_result["result"]
    assert isinstance(result, dict)
    result["reason_code"] = "native_other_reason"
    assert _decode_edge(mutated_result) is None


def test_command_model_budget_is_bound_at_resident_envelope_top_level(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"runtime")
    identity = NativeRuntimeIdentity(
        path=runtime,
        size=runtime.stat().st_size,
        mtime_ns=runtime.stat().st_mtime_ns,
        sha256="a" * 64,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="test",
        rule_digest="b" * 64,
        build_sha="c" * 40,
        target="test",
        features=(
            "pre-tool-command-model-shadow-v1",
            "resident-command-model-shadow-v1",
            "resident-protocol-v2",
        ),
    )
    monkeypatch.setattr(
        native_command_model,
        "native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="shadow",
            available=True,
            compatible=True,
            reason="ready",
            identity=identity,
            capabilities=capabilities,
        ),
    )
    captured: dict[str, object] = {}

    def fake_client(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return b"{}"

    monkeypatch.setattr(native_command_model, "native_resident_client_request", fake_client)
    monkeypatch.setattr(
        native_command_model,
        "_decode_command_model",
        lambda *_args, **_kwargs: {"confidence": "exact"},
    )

    result = native_command_model.review_command_model_native(
        "git status",
        guard_home=tmp_path / "guard-home",
        timeout_seconds=0.25,
    )

    assert result == {"confidence": "exact"}
    encoded = captured["payload"]
    assert isinstance(encoded, bytes)
    envelope = json.loads(encoded)
    assert envelope["deadline_budget_ms"] == 250
    assert "deadline_monotonic" in captured
    assert "timeout_seconds" not in captured


def test_command_model_records_allowlisted_error_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"runtime")
    identity = NativeRuntimeIdentity(
        path=runtime,
        size=runtime.stat().st_size,
        mtime_ns=runtime.stat().st_mtime_ns,
        sha256="a" * 64,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="test",
        rule_digest="b" * 64,
        build_sha="c" * 40,
        target="test",
        features=(
            "pre-tool-command-model-shadow-v1",
            "resident-command-model-shadow-v1",
            "resident-protocol-v2",
        ),
    )
    monkeypatch.setattr(
        native_command_model,
        "native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="shadow",
            available=True,
            compatible=True,
            reason="ready",
            identity=identity,
            capabilities=capabilities,
        ),
    )
    monkeypatch.setattr(
        native_command_model,
        "native_resident_client_request",
        lambda **_kwargs: b'{"error":"native_client_deadline_exceeded","retryable":false}',
    )

    assert (
        native_command_model.review_command_model_native(
            "git status",
            guard_home=tmp_path / "guard-home",
        )
        is None
    )
    assert native_resident_client_failure_code() == "native_client_deadline_exceeded"


def test_raw_hook_bridge_preserves_payload_for_rust_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    identity = NativeRuntimeIdentity(
        path=runtime,
        size=runtime.stat().st_size,
        mtime_ns=runtime.stat().st_mtime_ns,
        sha256="a" * 64,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="test",
        rule_digest="b" * 64,
        build_sha="c" * 40,
        target="test",
        features=(
            "hook-envelope-v2",
            "native-resident-client-v1",
            "pre-tool-generic-authority-v1",
        ),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_hook_edge.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ready",
            identity=identity,
            capabilities=capabilities,
        ),
    )
    captured: dict[str, object] = {}

    def fake_client(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return json.dumps(_edge_result(), separators=(",", ":")).encode()

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_hook_edge.native_resident_client_request",
        fake_client,
    )
    raw_payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_input": {"command": "pwd"},
    }
    result = review_raw_hook_native(
        payload=raw_payload,
        harness="claude",
        event="PreToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=None,
        policy_snapshot={"generation": 1},
    )
    assert result == _edge_result()
    encoded = captured["payload"]
    assert isinstance(encoded, bytes)
    envelope = json.loads(encoded)
    assert envelope["raw_payload"] == raw_payload
    assert envelope["harness"] == "claude"
    assert envelope["event"] == "PreToolUse"
    assert captured["raw_hook_envelope"] is True

    for invalid_value in ({"not", "json"}, float("nan")):
        captured.clear()
        invalid_payload = {**raw_payload, "invalid": invalid_value}
        assert (
            review_raw_hook_native(
                payload=invalid_payload,
                harness="claude",
                event="PreToolUse",
                guard_home=tmp_path,
                home_dir=tmp_path,
                cwd=tmp_path,
                source_ref_external_allowed=False,
                observe_mode=False,
                deadline=None,
                policy_snapshot={"generation": 1},
            )
            is None
        )
        assert captured == {}
