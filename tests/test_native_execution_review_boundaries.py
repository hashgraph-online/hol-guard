"""Native bridge review regressions: malformed data must not become authority."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import cast, get_args

import pytest

from codex_plugin_scanner.guard import config, local_supply_chain, native_execution, native_prompt
from codex_plugin_scanner.guard.contained_workspace_write_execution import ContainedWriteOperation
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime import local_mcp_stdio, runner
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.types import PromptRequest, PromptRequestClass


def _decision(**overrides):
    return {
        "action": "review",
        "disposition": "review",
        "proof_routes": [],
        "controlling_reasons": [],
        "reasons": [],
        **overrides,
    }


def _write_payload(operation):
    return {
        "attestation": {"exit_code": 0},
        "decision": _decision(),
        "stdout": "",
        "stderr": "",
        "operation_id": operation,
        "proof": {
            "route": "contained",
            "binding_digest": "a" * 64,
            "satisfied_requirements": ["containment-identity"],
            "enforced": True,
        },
    }


def test_request_ids_are_unique_across_threads():
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(lambda _: native_execution._request_id("review"), range(2000)))
    assert len(set(ids)) == len(ids)
    assert all(value.startswith("review-") and len(value) == 39 for value in ids)


@pytest.mark.parametrize("action", get_args(GuardAction))
def test_native_decision_accepts_only_declared_guard_actions(action):
    assert native_execution._effect_decision(_decision(action=action)).action == action
    reason = native_execution._decision_reason({"source": "policy", "reason_code": "test", "action_floor": action})
    assert reason.action_floor == action


@pytest.mark.parametrize("action", ["ALLOW", "unknown", "", None, 1])
def test_native_decision_rejects_invalid_actions(action):
    with pytest.raises(ValueError):
        native_execution._effect_decision(_decision(action=action))
    with pytest.raises(ValueError):
        native_execution._decision_reason({"source": "policy", "reason_code": "test", "action_floor": action})


@pytest.mark.parametrize("disposition", list(FinalDisposition))
def test_native_disposition_is_an_enum(disposition):
    result = native_execution._effect_decision(_decision(disposition=disposition.value))
    assert result.disposition is disposition


def test_invalid_native_disposition_is_rejected():
    with pytest.raises(ValueError):
        native_execution._effect_decision(_decision(disposition="unknown"))


@pytest.mark.parametrize("operation", get_args(ContainedWriteOperation))
def test_contained_write_accepts_declared_operations(operation):
    assert native_execution._contained_workspace_write_result(_write_payload(operation)).operation_id == operation


def test_contained_write_rejects_unknown_operation():
    with pytest.raises(ValueError, match="invalid contained write operation"):
        native_execution._contained_workspace_write_result(_write_payload("unknown"))


@pytest.mark.parametrize("requests", [[{}, None], ["bad"], "bad", {}, 7])
def test_malformed_prompt_requests_do_not_reach_resident(monkeypatch, tmp_path, requests):
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_: pytest.fail("transport called"))
    assert native_execution.prompt_analyze_native("extract", guard_home=tmp_path, requests=requests) is None


@pytest.mark.parametrize("classes", [["read", 1], "read", {}, 7])
def test_malformed_approval_classes_do_not_reach_resident(monkeypatch, tmp_path, classes):
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_: pytest.fail("transport called"))
    assert native_execution.prompt_analyze_native("extract", guard_home=tmp_path, approved_classes=classes) is None


def test_valid_prompt_requests_keep_their_fields(monkeypatch, tmp_path):
    captured = {}

    def resident(**kwargs):
        captured.update(kwargs)
        return {"result": False}

    monkeypatch.setattr(native_execution, "_resident_request", resident)
    requests = [{"request_id": "r", "severity": 8}]
    assert (
        native_execution.prompt_analyze_native(
            "should_force_reapproval", guard_home=tmp_path, requests=requests, approved_classes=["read"]
        )
        is False
    )
    assert captured["request"]["requests"] == requests
    assert captured["request"]["approved_classes"] == ["read"]


@pytest.mark.parametrize("explicit", [False, True])
def test_mcp_probe_uses_resolved_or_explicit_guard_home(monkeypatch, tmp_path, explicit):
    captured = {}

    def probe(*_args, **kwargs):
        captured.update(kwargs)
        return {"status": "failed", "reason": "test"}

    monkeypatch.setattr(native_execution, "mcp_stdio_probe_native", probe)
    monkeypatch.setattr(config, "resolve_guard_home", lambda: tmp_path / "resolved")
    override = tmp_path / "override" if explicit else None
    result = local_mcp_stdio.run_mcp_catalog(["test-server"], guard_home=override)
    assert captured["guard_home"] == (override if explicit else tmp_path / "resolved")
    assert result.reason == "test"


@pytest.mark.parametrize("error", [OSError("transport"), ValueError("payload")])
def test_prompt_transport_errors_are_explicit(monkeypatch, error):
    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(native_execution, "prompt_analyze_native", fail)
    with pytest.raises(native_prompt.NativePromptAnalysisError, match="native_prompt_analysis_unavailable"):
        runner._prompt_analyze_native("extract", prompt_text="test")


def test_prompt_programming_errors_are_not_hidden(monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("programming regression")

    monkeypatch.setattr(native_execution, "prompt_analyze_native", fail)
    with pytest.raises(RuntimeError, match="programming regression"):
        runner._prompt_analyze_native("extract", prompt_text="test")


@pytest.mark.parametrize("native", [[{"request_id": "r", "request_class": "read"}, None], [None]])
def test_prompt_extraction_rejects_every_malformed_native_result(monkeypatch, native):
    monkeypatch.setattr(native_prompt, "analyze", lambda *_args, **_kwargs: native)
    assert not hasattr(runner, "_extract_prompt_requests_python")
    with pytest.raises(native_prompt.NativePromptAnalysisError, match="invalid_result"):
        runner.extract_prompt_requests("test")


def test_artifact_translation_rejects_partial_native_results(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "_prompt_policy_path", lambda *_: tmp_path / "policy")
    monkeypatch.setattr(runner, "_prompt_analyze_native", lambda *_args, **_kwargs: [{"artifact_id": "a"}, None])
    assert not hasattr(runner, "_prompt_requests_to_artifacts_python")
    with pytest.raises(native_prompt.NativePromptAnalysisError, match="invalid_result"):
        runner.prompt_requests_to_artifacts(
            detection=SimpleNamespace(harness="claude-code"), context=SimpleNamespace(guard_home=tmp_path), requests=[]
        )


def test_approval_filter_cannot_turn_non_string_into_permission(monkeypatch):
    captured = {}

    def native_decision(*_args, **kwargs):
        captured.update(kwargs)
        return True

    monkeypatch.setattr(native_prompt, "analyze", native_decision)
    # Exercise the approval filter independently of the stricter native decoder.
    request = PromptRequest(
        request_id="r",
        request_class=cast(PromptRequestClass, "42"),
        summary="test",
        matched_text="test",
        severity=1,
        confidence=1.0,
    )
    assert runner.should_force_reapproval([request], {"approved_prompt_classes": [42, "read"]})
    assert captured["approved_classes"] == ["read"]


@pytest.mark.parametrize("native,expected", [(["npm"], ["npm"]), (["npm", None], ["fallback"]), ({}, ["fallback"])])
def test_supported_manager_list_is_validated(monkeypatch, tmp_path, native, expected):
    monkeypatch.setattr(local_supply_chain, "package_shim_dashboard_status", lambda _: {})
    monkeypatch.setattr(local_supply_chain, "package_shim_supported_managers", lambda: ("fallback",))
    monkeypatch.setattr(native_execution, "shim_admin_native", lambda *_args, **_kwargs: native)
    result = local_supply_chain._build_package_manager_protection(SimpleNamespace(guard_home=tmp_path))
    assert result["supported_managers"] == expected


@pytest.mark.parametrize(
    "translator",
    [
        native_execution._contained_node_result,
        native_execution._contained_typescript_result,
        native_execution._contained_package_script_result,
        native_execution._contained_workspace_write_result,
    ],
)
@pytest.mark.parametrize("proof", [None, "not-a-proof", []])
def test_contained_result_requires_typed_positive_proof(translator, proof):
    payload = _write_payload("patch-check")
    payload["proof"] = proof
    with pytest.raises(ValueError, match="proof"):
        translator(payload)


def test_package_script_native_returns_dataclass_not_unvalidated_dict(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.contained_package_script_execution import ContainedPackageScriptResult
    from codex_plugin_scanner.guard.runtime.effect_decision import PositiveProof

    payload = _write_payload("bun:test")
    monkeypatch.setattr(native_execution, "_contained_request", lambda **_: payload)
    result = native_execution.contained_package_script_execute_native(
        tmp_path,
        "bun",
        ["run", "test"],
        guard_home=tmp_path,
    )
    assert isinstance(result, ContainedPackageScriptResult)
    assert isinstance(result.proof, PositiveProof)
    assert result.operation_id == "bun:test"
    payload.pop("proof")
    assert (
        native_execution.contained_package_script_execute_native(
            tmp_path,
            "bun",
            ["run", "test"],
            guard_home=tmp_path,
        )
        is None
    )


@pytest.mark.parametrize("request_class", ["42", "unknown", None, 42])
def test_prompt_decoder_rejects_unknown_request_classes(request_class):
    assert runner._prompt_request_from_dict({"request_id": "r", "request_class": request_class}) is None


@pytest.mark.parametrize(
    "remediation",
    [
        [{"kind": "unknown", "label": "test"}],
        [{"kind": "approve_once", "label": "test"}, None],
        [{"kind": "approve_once", "label": "test", "detail": 42}],
        "not-a-list",
    ],
)
def test_prompt_decoder_rejects_partial_or_unknown_remediation(remediation):
    assert (
        runner._prompt_request_from_dict(
            {
                "request_id": "r",
                "request_class": "secret_read",
                "remediation": remediation,
            }
        )
        is None
    )


def test_prompt_decoder_preserves_valid_remediation():
    result = runner._prompt_request_from_dict(
        {
            "request_id": "r",
            "request_class": "secret_read",
            "summary": "Secret access",
            "matched_text": ".env",
            "severity": 8,
            "confidence": 0.9,
            "remediation": [{"kind": "approve_once", "label": "Approve", "detail": "One call"}],
        }
    )
    assert result is not None
    assert result.request_class == "secret_read"
    assert result.remediation[0].kind == "approve_once"
    assert result.remediation[0].detail == "One call"


@pytest.mark.parametrize(
    "fields",
    [
        {"tools": "not-a-list"},
        {"tools": [None]},
        {"tools": [{1: "bad-key"}]},
        {"protocol_version": 1},
        {"server_info": []},
        {"capabilities": "invalid"},
    ],
)
def test_mcp_native_catalog_falls_back_for_malformed_payload(monkeypatch, fields):
    fallback = local_mcp_stdio.McpCatalogResult(reason="python-fallback")
    native = {"status": "ok", "tools": [], **fields}
    monkeypatch.setattr(native_execution, "mcp_stdio_probe_native", lambda *_a, **_k: native)
    monkeypatch.setattr(local_mcp_stdio, "_exchange_tools_list", lambda *_a, **_k: fallback)
    assert local_mcp_stdio.run_mcp_catalog(["test-server"]) is fallback


def test_mcp_native_catalog_preserves_valid_fields():
    tools = [{"name": "read_file", "inputSchema": {"type": "object"}}]
    result = local_mcp_stdio._native_catalog_result(
        {
            "status": "ok",
            "tools": tools,
            "protocol_version": "2025-11-25",
            "server_info": {"name": "test"},
            "capabilities": {"tools": {}},
        }
    )
    assert result is not None and result.complete
    assert result.tools == tuple(tools)
    assert result.server_info == {"name": "test"}
    assert result.capabilities == {"tools": {}}
