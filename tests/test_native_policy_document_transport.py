"""Transport, DTO, and paging boundaries; algorithms replay in compiled Rust."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_document as client
from codex_plugin_scanner.guard import policy_document as document
from codex_plugin_scanner.guard import policy_document_compile as compiler
from codex_plugin_scanner.guard import policy_document_yaml as loader


def _resident(monkeypatch, mutation=None, result=None):
    identity = SimpleNamespace(path=Path("document-runtime"), sha256="a" * 64)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=identity,
        capabilities=SimpleNamespace(features=("request-context-v1", "resident-protocol-v2")),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **kwargs: status)
    monkeypatch.setattr(client, "validate_native_binary", lambda _: identity)
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: Path("document-home").absolute())
    monkeypatch.setattr(client, "_isolated_environment", lambda: {})
    calls = []

    def reply(**kwargs):
        calls.append(kwargs)
        request = json.loads(kwargs["payload"])["request"]
        response = {
            "schema": "guard-request-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + client._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": {
                "kind": "policy_document",
                "query": request["action"]["body"]["query"],
                "result": {"ok": {}} if result is None else result,
            },
        }
        if mutation in {"request_id", "request_sha256"}:
            response[mutation] = "wrong"
        elif mutation in {"kind", "query"}:
            response["payload"][mutation] = "wrong"
        elif mutation == "extra":
            response["allow"] = True
        elif mutation == "missing":
            return None
        elif mutation == "duplicates":
            return b'{"schema":"first","schema":"second"}'
        elif mutation == "error":
            response["status"] = "error"
        return json.dumps(response).encode()

    monkeypatch.setattr(client, "native_resident_client_request", reply)
    return calls, status


@pytest.mark.parametrize(
    "mutation", ["request_id", "request_sha256", "kind", "query", "extra", "missing", "duplicates", "error"]
)
def test_document_rejects_unavailable_unbound_or_malformed_native_authority(monkeypatch, mutation):
    _resident(monkeypatch, mutation)
    with pytest.raises(client.NativePolicyDocumentError):
        client.policy_query("canonical", {"value": {}})


def test_document_preserves_one_absolute_deadline_and_expected_runtime_identity(monkeypatch):
    calls, status = _resident(monkeypatch)
    deadline = time.monotonic() + 1
    assert (
        client.policy_query(
            "canonical", {"value": {}}, deadline_monotonic=deadline, runtime_sha256=status.identity.sha256
        )
        == {}
    )
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == deadline
    request = json.loads(calls[0]["payload"])["request"]
    assert 0 < request["budget_ms"] <= 1000
    assert request["action"] == {"kind": "policy_document", "body": {"query": "canonical", "input": {"value": {}}}}


@pytest.mark.parametrize("case", ["deadline", "runtime_change", "missing_binary", "nonfinite"])
def test_document_rejects_before_transport_without_native_authority(monkeypatch, case):
    calls, _ = _resident(monkeypatch)
    kwargs = {}
    body = {"value": {}}
    if case == "deadline":
        kwargs["deadline_monotonic"] = 0.0
    elif case == "runtime_change":
        kwargs["runtime_sha256"] = "b" * 64
    elif case == "missing_binary":
        monkeypatch.setattr(client, "validate_native_binary", lambda _: None)
    else:
        body = {"value": float("nan")}
    with pytest.raises(client.NativePolicyDocumentError):
        client.policy_query("canonical", body, **kwargs)
    assert not calls


@pytest.mark.parametrize(
    "kind,exception", [("TypeError", TypeError), ("ValueError", ValueError), ("CommandExpressionError", ValueError)]
)
def test_document_preserves_native_semantic_error_types(monkeypatch, kind, exception):
    _resident(monkeypatch, result={"error": {"type": kind, "message": "fixture_error"}})
    with pytest.raises(exception, match="fixture_error"):
        client.policy_query("from_mapping", {})


def test_document_preserves_compilation_error_code_and_rule_id(monkeypatch):
    _resident(
        monkeypatch,
        result={
            "error": {
                "type": "PolicyCompilationError",
                "message": "unsupported:fixture",
                "code": "unsupported",
                "rule_id": "fixture",
            }
        },
    )
    with pytest.raises(compiler.PolicyCompilationError) as caught:
        client.policy_query("compile", {})
    assert (caught.value.code, caught.value.rule_id) == ("unsupported", "fixture")


def _compile_transport(monkeypatch, mutation=None):
    source = document.GuardPolicyDocument(
        document.PolicyMetadata("fixture", "Fixture", 0), document.PolicyDefaults("prompt"), ()
    )
    calls = []

    def rows(query, body, **kwargs):
        calls.append((query, body.copy(), kwargs.copy()))
        item = {
            "rule_id": "native-rule",
            "provenance_json": "{}",
            "decision": {"harness": "pi", "scope": "harness", "action": "block"},
        }
        if mutation == "action":
            item["decision"]["action"] = "claimed_allow"
        elif mutation == "type":
            item["decision"]["harness"] = []
        elif mutation == "scope":
            item["decision"]["scope"] = "claimed-global"
        elif mutation == "missing":
            item.pop("rule_id")
        return [item.copy() for _ in range(65)]

    monkeypatch.setattr(compiler, "policy_query", rows)
    return source, calls


def test_compiled_rows_present_one_native_compilation_without_recomputing_actions(monkeypatch):
    source, calls = _compile_transport(monkeypatch)
    rows = compiler.compile_policy_document(source)
    assert len(rows) == 65
    assert {row.decision.action for row in rows} == {"block"}
    assert len(calls) == 1
    assert calls[0][0] == "compile_dto"
    assert calls[0][1]["dto"]["metadata"]["id"] == "fixture"


@pytest.mark.parametrize("mutation", ["action", "type", "scope", "missing"])
def test_compiled_rows_reject_invalid_native_dto_fields(monkeypatch, mutation):
    source, _ = _compile_transport(monkeypatch, mutation)
    with pytest.raises(client.NativePolicyDocumentError):
        compiler.compile_policy_document(source)


def test_native_document_dto_never_runs_python_command_normalization():
    assert not hasattr(document.CommandCondition, "__post_init__")
    expression = {
        "combinator": "all",
        "conditions": [{"field": "command", "operator": "exact", "value": "native value", "case_sensitive": False}],
    }
    value = document._decode_dto(document.CommandExpression, expression)
    assert value.conditions[0].value == "native value"
    assert isinstance(value.conditions, tuple)


@pytest.mark.parametrize(
    "value",
    [{}, {"combinator": "all", "conditions": []}, {"combinator": "all", "conditions": [], "claimed_allow": True}],
)
def test_native_document_dto_rejects_missing_or_extra_fields(monkeypatch, value):
    if set(value) == {"combinator", "conditions"}:
        value["conditions"] = False
    with pytest.raises(client.NativePolicyDocumentError):
        document._decode_dto(document.CommandExpression, value)


def test_canonical_projection_rejects_non_string_native_output(monkeypatch):
    monkeypatch.setattr(document, "policy_query", lambda *args, **kwargs: {"claimed_allow": True})
    with pytest.raises(client.NativePolicyDocumentError):
        document.canonical_json_bytes({})


def test_yaml_order_matches_frozen_original_text(monkeypatch):
    fixture = json.loads((Path(__file__).parent / "fixtures" / "policy_document_parity.json").read_text())
    for golden in fixture["yaml_order_goldens"]:
        monkeypatch.setattr(document, "policy_query", lambda *args, frame=golden["frame"], **kwargs: frame)
        value = document._decode_dto(document.GuardPolicyDocument, golden["dto"])
        assert loader.format_policy_document_yaml(value) == golden["yaml"]


def test_yaml_scanner_sends_observations_and_preserves_native_error_precedence(monkeypatch):
    calls = []
    result = {"code": "yaml_alias", "line": 1, "column": 4}
    monkeypatch.setattr(loader, "policy_query", lambda query, body: calls.append((query, body)) or result)
    with pytest.raises(loader.PolicyDocumentError) as caught:
        loader._scan_restricted_tokens("k: *alias\nbad: \tvalue")
    assert caught.value.diagnostics == (loader.PolicyDiagnostic("yaml_alias", line=1, column=4),)
    assert calls[0][0] == "validate_yaml_tokens"
    assert any(row[0] == "AliasToken" for row in calls[0][1]["tokens"])
    assert calls[0][1]["tokens"][-1][0] == "scanner_syntax"


def test_native_bounds_preserve_surrogates_order_and_diagnostic_paths(monkeypatch):
    value = {"\udfff": float("nan"), "ordinary": ["\ud800"]}
    claim = client.bounds_claim(value)
    assert claim[0] == "mapping"
    assert base64.b64decode(claim[1][0][0][1]).decode("utf-32-le", "surrogatepass") == "\udfff"
    monkeypatch.setattr(
        loader, "policy_query", lambda *args: {"code": "invalid_unicode", "path_claims": [claim[1][0][0]]}
    )
    with pytest.raises(loader.PolicyDocumentError) as caught:
        loader._validate_bounds(value)
    assert caught.value.diagnostics[0].path == ("\udfff",)


@pytest.mark.parametrize("frame", [{}, {"wire_download": {}}, {"wire_download": {"handle": 1, "offset": 0}}])
def test_malformed_transfer_frames_raise_native_unavailable(monkeypatch, frame):
    _resident(monkeypatch)
    monkeypatch.setattr(client, "_bound_query", lambda *args, **kwargs: frame)
    with pytest.raises(client.NativePolicyDocumentError):
        client.policy_query("from_mapping", {"value": "x" * (600 * 1024)})


def test_mcp_native_outage_returns_structured_retryable_error():
    from codex_plugin_scanner.guard.mcp import policy_tools

    @policy_tools._native_policy_errors
    def unavailable():
        raise client.NativePolicyDocumentError("native_policy_document_unavailable")

    result = json.loads(unavailable())
    assert not result["ok"]
    assert result["error"]["code"] == "policy_compile_failed"
    assert result["error"]["retryable"]


def test_mcp_compile_outage_reaches_the_retryable_envelope(monkeypatch):
    from codex_plugin_scanner.guard.mcp import policy_tools

    def unavailable(_document):
        raise client.NativePolicyDocumentError("native_policy_document_unavailable")

    monkeypatch.setattr(policy_tools, "parse_policy_document_yaml", lambda _yaml: object())
    monkeypatch.setattr(policy_tools, "compile_document_for_import", unavailable)
    with pytest.raises(client.NativePolicyDocumentError):
        policy_tools._parse_and_compile("policy: yaml")


def test_pending_candidate_outage_is_retryable_not_invalid(monkeypatch):
    from codex_plugin_scanner.guard.mcp import policy_tools

    request = SimpleNamespace(status="pending", mode="merge", canonical_policy_yaml="", policy_document_digest="")
    repository = SimpleNamespace(get_request=lambda _request_id: request)
    monkeypatch.setattr(policy_tools, "MCPolicyRequestRepository", lambda _store: repository)
    monkeypatch.setattr(policy_tools, "parse_policy_document_yaml", lambda _yaml: object())

    def unavailable(_document):
        raise client.NativePolicyDocumentError("native_policy_document_unavailable")

    monkeypatch.setattr(policy_tools, "policy_document_digest", unavailable)
    with pytest.raises(policy_tools.PolicyToolError) as caught:
        policy_tools._pending_policy_candidate(object(), "request")
    assert caught.value.code == "policy_compile_failed"
    assert caught.value.retryable


def test_business_rule_detection_reads_match_extensions_locally(monkeypatch):
    from codex_plugin_scanner.guard.business_policy_document_import import has_business_rules

    monkeypatch.setattr(document, "policy_query", lambda *args, **kwargs: pytest.fail("native call"))
    plain = SimpleNamespace(match=document.PolicyMatch(extensions=(("vendor", "{}"),)))
    business = SimpleNamespace(match=document.PolicyMatch(extensions=(("business", "{}"),)))
    assert not has_business_rules(SimpleNamespace(rules=(plain,)))
    assert has_business_rules(SimpleNamespace(rules=(plain, business)))


def test_data_named_like_transfer_headers_stays_policy_data(monkeypatch):
    mapping = {"wire_download": {"handle": "data"}, "wire_upload": "data"}
    _resident(monkeypatch, result={"ok": mapping})
    assert client.policy_query("to_mapping", {}) == mapping


def test_scanner_observations_stop_at_native_admission_boundary(monkeypatch):
    generated = []
    mark = SimpleNamespace(line=0, column=0)

    def tokens(*args, **kwargs):
        for index in range(loader.MAX_POLICY_TOKENS + 100):
            generated.append(index)
            yield SimpleNamespace(start_mark=mark)

    monkeypatch.setattr(loader.yaml, "scan", tokens)
    monkeypatch.setattr(loader, "policy_query", lambda query, body: {"code": "limit_tokens", "line": 1, "column": 1})
    with pytest.raises(loader.PolicyDocumentError) as caught:
        loader._scan_restricted_tokens("")
    assert len(generated) == loader.MAX_POLICY_TOKENS + 1
    assert caught.value.diagnostics[0].code == "limit_tokens"


@pytest.mark.parametrize("corrupt", [None, "offset", "digest", "short"])
def test_large_document_wire_keeps_one_deadline_and_rejects_corrupt_chunks(monkeypatch, corrupt):
    _resident(monkeypatch)
    source = {"value": "x" * (7 * 1024 * 1024)}
    encoded_result = json.dumps({"ok": {"fixture": "y" * (3 * 1024 * 1024)}}).encode()
    token = "b" * 64
    uploaded = bytearray()
    calls = []

    def reply(query, body, **kwargs):
        calls.append((query, kwargs.copy()))
        if query == "wire_start":
            assert body["size"] > 6 * 1024 * 1024
            return {"wire_upload": {"handle": token, "offset": 0}}
        if query == "wire_append":
            assert body["offset"] == len(uploaded)
            uploaded.extend(base64.b64decode(body["bytes"]))
            return {"wire_upload": {"handle": token, "offset": len(uploaded)}}
        if query == "wire_finish":
            assert json.loads(uploaded) == source
            offset = 0
        else:
            assert query == "wire_read"
            offset = body["offset"]
        page = {
            "handle": token,
            "offset": offset,
            "total": len(encoded_result),
            "sha256": hashlib.sha256(encoded_result).hexdigest(),
            "bytes": base64.b64encode(encoded_result[offset : offset + 512 * 1024]).decode(),
        }
        if corrupt == "offset":
            page["offset"] += 1
        elif corrupt == "digest":
            page["sha256"] = "0" * 64
        elif corrupt == "short":
            page["bytes"] = base64.b64encode(b"short").decode()
        return {"wire_download": page}

    monkeypatch.setattr(client, "_bound_query", reply)
    deadline = time.monotonic() + 30
    if corrupt:
        with pytest.raises(client.NativePolicyDocumentError):
            client.policy_query("from_mapping", source, deadline_monotonic=deadline)
    else:
        assert client.policy_query("from_mapping", source, deadline_monotonic=deadline) == {
            "fixture": "y" * (3 * 1024 * 1024)
        }
    assert len({kwargs["deadline_monotonic"] for _, kwargs in calls}) == 1
    assert {kwargs["runtime_sha256"] for _, kwargs in calls} == {"a" * 64}
