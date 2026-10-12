"""Transport contract for the native MCP tool-evidence owner (shared vectors with Rust)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_mcp_tool_evidence as module
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_mcp_tool_evidence import (
    NativeMcpToolEvidenceError,
    firewall_input,
    native_firewall_metadata_patch,
    native_tool_risk_evidence,
    risk_input,
)

_CASES = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "mcp-tool-evidence" / "cases.v1.json").read_text(encoding="utf-8")
)
_RISK = {case["name"]: case for case in _CASES["risk"]}
_FIREWALL = {case["name"]: case for case in _CASES["firewall"]}


def _risk_artifact(source: dict) -> GuardArtifact:
    raw = source["artifact"]
    return GuardArtifact(
        artifact_id="test:tool",
        name=raw["name"],
        harness="codex",
        artifact_type="tool_call",
        source_scope="project",
        config_path=".mcp.json",
        command=raw["command"],
        metadata=raw["metadata"],
    )


def _firewall_artifact(source: dict) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="test:firewall",
        name=source["name"],
        harness="codex",
        artifact_type=source["artifact_type"],
        source_scope="project",
        config_path=source["config_path"],
        command=source["command"],
        args=tuple(source["args"]),
        transport=source["transport"],
        url=source["url"],
        publisher=source["publisher"],
        metadata=source["metadata"],
    )


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


@pytest.mark.parametrize("name", sorted(_RISK))
def test_risk_projection_matches_shared_vector(name: str) -> None:
    case = _RISK[name]
    source = case["source"]
    projected = risk_input(_risk_artifact(source), source["arguments"])
    expected = case["input"]
    assert projected["artifact"] == expected["artifact"]
    assert projected["arguments"] == expected["arguments"]


@pytest.mark.parametrize("name", sorted(_FIREWALL))
def test_firewall_projection_matches_shared_vector(name: str) -> None:
    case = _FIREWALL[name]
    assert firewall_input(_firewall_artifact(case["source"])) == case["input"]


@pytest.mark.parametrize("name", sorted(_RISK))
def test_risk_resident_answer_matches_shared_vector(name: str) -> None:
    case = _RISK[name]
    source = case["source"]
    expected = case["expected"]
    categories, signals, summary = native_tool_risk_evidence(
        _risk_artifact(source),
        source["arguments"],
        risk_categories=None if case["input"]["risk_categories"] is None else tuple(case["input"]["risk_categories"]),
        summary_code=case["input"]["summary_code"],
    )
    assert list(categories) == expected["risk_categories"]
    assert list(signals) == expected["signals"]
    assert summary == expected["summary"]


@pytest.mark.parametrize("name", sorted(_FIREWALL))
def test_firewall_resident_patch_matches_shared_vector(name: str) -> None:
    case = _FIREWALL[name]
    patch = native_firewall_metadata_patch(_firewall_artifact(case["source"]))
    merged = {**case["metadata_before"], **(patch or {})}
    assert merged == case["expected_metadata"]
    changed = [key for key, value in (patch or {}).items() if case["metadata_before"].get(key) != value]
    assert sorted(changed) == sorted(case["expected_patch_changed_keys"] or [])


def test_unavailable_native_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Status:
        mode = "off"
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    case = _RISK[sorted(_RISK)[0]]
    with pytest.raises(NativeMcpToolEvidenceError, match="unavailable"):
        native_tool_risk_evidence(_risk_artifact(case["source"]), case["source"]["arguments"])
    fw = _FIREWALL[sorted(_FIREWALL)[0]]
    with pytest.raises(NativeMcpToolEvidenceError, match="unavailable"):
        native_firewall_metadata_patch(_firewall_artifact(fw["source"]))


def test_client_exceptions_become_typed_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    case = _RISK[sorted(_RISK)[0]]
    for error in (RuntimeError("thread"), OSError("pipe"), TimeoutError("slow")):

        def client(error: Exception = error, **_kwargs: object) -> bytes:
            raise error

        monkeypatch.setattr(module, "native_resident_client_request", client)
        with pytest.raises(NativeMcpToolEvidenceError, match="resident_unavailable"):
            native_tool_risk_evidence(_risk_artifact(case["source"]), case["source"]["arguments"])


def test_mismatched_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        lambda **_: (
            b'{"schema":"guard-mcp-tool-evidence-result.v1","request_id":"x","request_sha256":"y",'
            b'"status":"ok","code":"ok","payload":{"risk_categories":[],"signals":[],"summary":"s"}}'
        ),
    )
    case = _RISK[sorted(_RISK)[0]]
    with pytest.raises(NativeMcpToolEvidenceError, match="result_invalid"):
        native_tool_risk_evidence(_risk_artifact(case["source"]), case["source"]["arguments"])


@pytest.mark.parametrize(
    "raw_payload",
    (
        '{"risk_categories":["not-a-category"],"signals":["x"],"summary":"s"}',
        '{"risk_categories":[],"signals":[],"summary":7}',
        '{"risk_categories":[],"signals":["extra"],"summary":"s"}',
    ),
)
def test_malformed_operation_payload_counts_as_a_resident_failure(
    monkeypatch: pytest.MonkeyPatch, raw_payload: str
) -> None:
    _force_available(monkeypatch)
    failures: list[str] = []
    successes: list[object] = []
    monkeypatch.setattr(module, "native_record_resident_failure", lambda *a, **k: failures.append(k["reason"]))
    monkeypatch.setattr(module, "native_record_resident_success", lambda *a, **k: successes.append(a))

    def client(*, payload: bytes, **_kwargs: object) -> bytes:
        request = json.loads(payload)["request"]
        return json.dumps(
            {
                "schema": module._RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": module._canonical_request_sha256(request),
                "status": "ok",
                "code": "ok",
                "payload": json.loads(raw_payload),
            }
        ).encode()

    monkeypatch.setattr(module, "native_resident_client_request", client)
    case = _RISK[sorted(_RISK)[0]]
    with pytest.raises(NativeMcpToolEvidenceError, match="result_invalid"):
        native_tool_risk_evidence(_risk_artifact(case["source"]), case["source"]["arguments"])
    assert failures == ["native_mcp_tool_evidence_result_invalid"]
    assert successes == []


def test_non_string_server_name_fails_closed() -> None:
    source = dict(_FIREWALL[sorted(_FIREWALL)[0]]["source"])
    artifact = _firewall_artifact({**source, "metadata": {**source["metadata"], "server_name": 5}})
    with pytest.raises(NativeMcpToolEvidenceError, match="server_name_unsupported"):
        firewall_input(artifact)


def test_unsupported_artifact_type_is_typed_error() -> None:
    artifact = _firewall_artifact({**_FIREWALL[sorted(_FIREWALL)[0]]["source"], "artifact_type": "skill"})
    with pytest.raises(NativeMcpToolEvidenceError, match="unsupported_artifact_type"):
        native_firewall_metadata_patch(artifact)


def test_oversized_request_is_rejected_client_side(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    case = _RISK[sorted(_RISK)[0]]
    with pytest.raises(NativeMcpToolEvidenceError, match="request_too_large"):
        native_tool_risk_evidence(_risk_artifact(case["source"]), {"command": "x" * (3 * 1024 * 1024)})
