from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_command_model
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.daemon.hook_request_parsing import runtime_hook_event_name
from codex_plugin_scanner.guard.hook_execution_environment import (
    collect_hook_execution_environment,
)
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge, review_raw_hook_native
from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_request,
)
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)


@pytest.mark.parametrize("value", ("1", "true", "TRUE", "yes", "on"))
def test_git_config_no_system_accepts_git_truthy_values(monkeypatch, value):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", value)
    assert collect_hook_execution_environment()["git_config_no_system"] is True


def test_execution_lookup_context_is_feature_gated_and_omits_environment_values(monkeypatch):
    from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope

    monkeypatch.setenv("PATH", "/verified/system/bin")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/verified/user/config")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "synthetic-secret-must-not-serialize")
    arguments = dict(
        payload={"tool_name": "bash", "command": "git status --short"},
        harness="omp",
        event="PreToolUse",
        guard_home=Path("/guard"),
        home_dir=Path("/home/test"),
        cwd=Path("/workspace"),
        source_ref_external_allowed=False,
        deadline_budget_ms=500,
        snapshot={"generation": 1},
    )
    legacy = json.loads(_encode_hook_envelope(**arguments))
    assert "execution_environment" not in legacy["source"]
    encoded = _encode_hook_envelope(**arguments, execution_context_supported=True)
    context = json.loads(encoded)["source"]["execution_environment"]
    assert context["path"] == "/verified/system/bin"
    assert context["xdg_config_home"] == "/verified/user/config"
    assert context["git_config_no_system"] is False
    assert "GIT_EXTERNAL_DIFF" in context["environment_names"]
    assert b"synthetic-secret-must-not-serialize" not in encoded
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "different-synthetic-value")
    changed = json.loads(_encode_hook_envelope(**arguments, execution_context_supported=True))
    assert changed["source"]["execution_environment"]["environment_digest"] != context["environment_digest"]
    forwarded = {**context, "path": "/actual/caller/bin"}
    arguments["payload"]["guard_execution_environment"] = forwarded
    encoded = json.loads(_encode_hook_envelope(**arguments, execution_context_supported=True))
    assert encoded["source"]["execution_environment"] == forwarded
    assert "guard_execution_environment" not in encoded["raw_payload"]
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    arguments["payload"].pop("guard_execution_environment", None)
    empty_xdg = json.loads(_encode_hook_envelope(**arguments, execution_context_supported=True))
    empty_context = empty_xdg["source"]["execution_environment"]
    assert empty_context["xdg_config_home"] is None
    assert empty_context["git_config_no_system"] is False
    assert "XDG_CONFIG_HOME" not in empty_context["environment_names"]
    arguments["payload"]["guard_execution_environment"] = None
    unavailable = json.loads(_encode_hook_envelope(**arguments, execution_context_supported=True))
    assert "execution_environment" not in unavailable["source"]


def _edge_result() -> dict[str, object]:
    edge = {
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


@pytest.mark.parametrize("alias", ("UserPromptSubmit", "userPromptSubmitted", "user_prompt_submit", "prompt"))
def test_prompt_event_aliases_enter_one_native_authority_route(alias: str) -> None:
    assert runtime_hook_event_name({"hook_event_name": alias}) == "UserPromptSubmit"


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


def test_edge_decoder_accepts_only_bound_native_prompt_decision() -> None:
    edge = _edge_result()
    result = edge["result"]
    receipt = edge["receipt"]
    assert isinstance(result, dict) and isinstance(receipt, dict)
    action = result["action"]
    assert isinstance(action, dict)
    edge["event_name"] = receipt["event_name"] = action["event"] = "UserPromptSubmit"
    action.update(action_type="prompt", operation="submit", sensitive_target=True)
    result.update(
        decision="deny",
        minimum_action="block",
        policy_action="block",
        reason_code="native_guard_bypass_prompt",
        reason="HOL Guard blocked this prompt because it asks to disable Guard protection.",
        explicitly_benign=False,
        prompt_risk_classes=["local_env_read", "exfil_intent", "guard_bypass_intent"],
    )
    receipt.update(
        decision="deny",
        policy_action="block",
        reason_code="native_guard_bypass_prompt",
        prompt_risk_classes=["local_env_read", "exfil_intent", "guard_bypass_intent"],
    )
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    assert _decode_edge(edge) == edge

    wrong_action = json.loads(json.dumps(edge))
    wrong_action["result"]["action"]["event"] = "PreToolUse"
    assert _decode_edge(wrong_action) is None
    wrong_classes = json.loads(json.dumps(edge))
    wrong_classes["result"]["prompt_risk_classes"] = ["guard_bypass_intent"]
    assert _decode_edge(wrong_classes) is None
    wrong_kind = {**edge, "payload_kind": "source_file_ref"}
    assert _decode_edge(wrong_kind) is None


def test_python_launcher_only_invokes_package_bound_native_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "hol-guard-runtime"
    executable.write_bytes(b"runtime")
    captured: dict[str, object] = {}

    def fake_run(command: tuple[str, ...], **kwargs: object) -> BoundedHookProcessResult:
        captured.update(command=tuple(command), **kwargs)
        return BoundedHookProcessResult(0, '{"ok":true}\n', False, False)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        fake_run,
    )
    result = native_resident_client_request(
        executable=executable,
        guard_home=tmp_path / "guard-home",
        environment={"HOME": str(tmp_path)},
        payload=b"{}",
        timeout_seconds=0.5,
        raw_hook_envelope=True,
    )
    assert result == b'{"ok":true}\n'
    assert captured["command"] == (
        str(executable),
        "hook-client",
        "--stdin",
        str(tmp_path / "guard-home" / "native-runtime"),
    )
    assert captured["input_text"] == "{}"
    assert captured["timeout_seconds"] == 0.5
    assert captured["output_limit"] == 2 * 1024 * 1024
    assert captured["windows_kill_on_job_close"] is False
    assert native_resident_client_failure_code() is None


def test_native_client_forwards_absolute_deadline_without_relative_floor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: tuple[str, ...], **kwargs: object) -> BoundedHookProcessResult:
        captured.update(command=tuple(command), **kwargs)
        return BoundedHookProcessResult(0, '{"ok":true}\n', False, False)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        fake_run,
    )
    deadline = time.monotonic() + 0.001
    result = native_resident_client_request(
        executable=tmp_path / "runtime",
        guard_home=tmp_path / "guard-home",
        environment={},
        payload=b"{}",
        deadline_monotonic=deadline,
    )

    assert result == b'{"ok":true}\n'
    assert captured["deadline_monotonic"] == deadline
    assert captured["timeout_seconds"] is None


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


def test_native_client_records_only_allowlisted_failure_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        lambda *_args, **_kwargs: BoundedHookProcessResult(
            2,
            "",
            False,
            True,
            containment_failed=True,
            stderr="ignored\nnative_resident_start_timeout\nignored",
        ),
    )
    result = native_resident_client_request(
        executable=tmp_path / "runtime",
        guard_home=tmp_path / "guard-home",
        environment={},
        payload=b"{}",
        timeout_seconds=0.5,
    )
    assert result is None
    assert native_resident_client_failure_code() == "native_resident_start_timeout"


@pytest.mark.parametrize(
    ("process_result", "expected_code"),
    (
        (
            BoundedHookProcessResult(7, "", True, True, containment_failed=True),
            "native_client_containment_failed",
        ),
        (BoundedHookProcessResult(7, "", True, True), "native_client_timed_out"),
        (BoundedHookProcessResult(None, "", True, False), "native_client_output_limit_exceeded"),
        (BoundedHookProcessResult(None, "", False, False), "native_client_status_missing"),
        (BoundedHookProcessResult(7, "", False, False), "native_client_exit_nonzero"),
        (BoundedHookProcessResult(0, "", False, False), "native_client_output_missing"),
    ),
)
def test_native_client_classifies_bounded_failure_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_result: BoundedHookProcessResult,
    expected_code: str,
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> BoundedHookProcessResult:
        return process_result

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_resident_client.run_isolated_hook_process",
        fake_run,
    )
    assert (
        native_resident_client_request(
            executable=tmp_path / "runtime",
            guard_home=tmp_path / "guard-home",
            environment={},
            payload=b"{}",
            timeout_seconds=0.5,
        )
        is None
    )
    assert native_resident_client_failure_code() == expected_code


@pytest.mark.parametrize("request_id", [None, "request-1", "different-request"])
@pytest.mark.parametrize("execution_context_supported", [True, False])
def test_raw_hook_bridge_preserves_payload_for_rust_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request_id: str | None,
    execution_context_supported: bool,
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
            *(["git-execution-context-v1"] if execution_context_supported else []),
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
        request_id=request_id,
    )
    if not execution_context_supported:
        assert result is None
        assert not captured
        return
    assert result == (_edge_result() if request_id != "different-request" else None)
    encoded = captured["payload"]
    assert isinstance(encoded, bytes)
    envelope = json.loads(encoded)
    assert envelope["raw_payload"] == raw_payload
    assert envelope["harness"] == "claude"
    assert envelope["event"] == "PreToolUse"
    assert envelope["request_id"] == request_id
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
