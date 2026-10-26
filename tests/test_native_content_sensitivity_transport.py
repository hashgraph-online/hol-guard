"""Native sensitivity outage, binding, deadline and privacy boundary tests."""

from __future__ import annotations

import base64
import gzip
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_content_sensitivity as client


def _resident(monkeypatch: pytest.MonkeyPatch, mutation: str | None = None) -> list[dict[str, object]]:
    client._resolution_memo.clear()
    client._path_memo.clear()
    identity = SimpleNamespace(path=Path("fixture-runtime"), sha256="a" * 64)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=identity,
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "request-context-v1")),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **kwargs: status)
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: Path("fixture-home").absolute())
    monkeypatch.setattr(client, "_isolated_environment", lambda: {})
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(client, "native_record_resident_success", lambda *args, **kwargs: None)
    calls: list[dict[str, object]] = []

    def reply(**kwargs):
        calls.append(kwargs)
        envelope = json.loads(kwargs["payload"])
        request = envelope["request"]
        response = {
            "schema": "guard-request-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + client._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": {
                "kind": "content_sensitivity",
                "query": request["action"]["body"]["query"],
                "result": {"ok": [] if request["action"]["body"]["query"] == "content" else "b" * 64},
            },
        }
        if request["action"]["body"]["query"] == "resolution":
            response["payload"]["result"] = {"ok": {"binding": None, "required": False, "reason_code": None}}
        elif request["action"]["body"]["query"] == "path":
            response["payload"]["result"] = {"ok": None}
        if mutation == "request":
            response["request_id"] = "different-request"
        elif mutation == "digest":
            response["request_sha256"] = "sha256:" + "0" * 64
        elif mutation == "query":
            response["payload"]["query"] = "other"
        elif mutation == "kind":
            response["payload"]["kind"] = "other"
        elif mutation == "extra":
            response["payload"]["allow"] = True
        elif mutation == "error":
            response["status"] = "error"
        elif mutation == "rejected":
            response.update(status="error", code="native_request_context_content_input_invalid", payload=None)
        elif mutation in {"native_budget", "native_fault"}:
            code = "budget_exceeded" if mutation == "native_budget" else "content_unavailable"
            response.update(status="error", code=f"native_request_context_{code}", payload=None)
        elif mutation == "missing":
            return None
        elif mutation == "duplicates":
            return b'{"schema":"first","schema":"second"}'
        return json.dumps(response).encode()

    monkeypatch.setattr(client, "native_resident_client_request", reply)
    return calls


@pytest.mark.parametrize("mutation", ["request", "digest", "query", "kind", "extra", "error", "missing", "duplicates"])
def test_sensitivity_rejects_unavailable_malformed_or_unbound_authority(monkeypatch, mutation):
    _resident(monkeypatch, mutation)
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", {})


def test_sensitivity_uses_one_absolute_deadline_for_the_persistent_client(monkeypatch):
    calls = _resident(monkeypatch)
    deadline = time.monotonic() + 0.1
    assert client.content_query("content_version", {}, deadline_monotonic=deadline) == "b" * 64
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == deadline
    envelope = json.loads(calls[0]["payload"])
    assert 0 < envelope["request"]["budget_ms"] <= 100
    assert envelope["request"]["action"] == {
        "kind": "content_sensitivity",
        "body": {"query": "content_version", "input": {}},
    }


def test_default_budget_covers_a_resident_spawn_and_a_loaded_warm_round_trip(monkeypatch):
    calls = _resident(monkeypatch)
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: False)
    client.content_query("content_version", {})
    assert 500 < json.loads(calls[0]["payload"])["request"]["budget_ms"] <= 4000
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: True)
    client.content_query("content_version", {})
    assert 500 < json.loads(calls[1]["payload"])["request"]["budget_ms"] <= 2000


def test_expired_sensitivity_deadline_never_opens_a_client(monkeypatch):
    calls = _resident(monkeypatch)
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", {}, deadline_monotonic=0.0)
    assert not calls


def test_sensitivity_outage_obeys_existing_value_error_rejection_contract(monkeypatch):
    _resident(monkeypatch, "missing")
    with pytest.raises(ValueError):
        client.content_query("content_version", {})


@pytest.mark.parametrize("case", ["oversize", "nonfinite", "rejected", "expired_reply"])
def test_caller_rejections_do_not_quarantine_the_shared_resident(monkeypatch, case):
    calls = _resident(monkeypatch, "rejected" if case == "rejected" else None)
    failures = []
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *args, **kwargs: failures.append(kwargs))
    body = {"unused": "x" * (12 * 1024 * 1024)} if case == "oversize" else {}
    if case == "nonfinite":
        body = {"unused": float("nan")}
    if case == "expired_reply":
        now = time.monotonic()
        # Past both the warm and the cold-start default budget.
        monkeypatch.setattr(client.time, "monotonic", lambda: now + (5 if calls else 0))
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", body)
    assert not failures
    if case in {"oversize", "nonfinite"}:
        assert not calls


@pytest.mark.parametrize("mutation", ["request", "digest", "missing", "duplicates"])
def test_resident_faults_still_update_shared_health(monkeypatch, mutation):
    _resident(monkeypatch, mutation)
    failures = []
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *args, **kwargs: failures.append(kwargs))
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", {})
    assert len(failures) == 1


@pytest.mark.parametrize("text", ["x" * (5 * 1024 * 1024), '\\"' * (5 * 512 * 1024), "界" * (5 * 1024 * 1024 // 3)])
def test_large_output_wire_encoding_is_lossless_and_keeps_the_callers_deadline(monkeypatch, text):
    calls = _resident(monkeypatch)
    body = {"text": text, "suppress_samples": True, "documentation_sample_context": False}
    deadline = time.monotonic() + 30
    assert client.content_query("content", body, deadline_monotonic=deadline) == []
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == deadline
    assert len(calls[0]["payload"]) <= 6 * 1024 * 1024
    packed = json.loads(calls[0]["payload"])["request"]["action"]["body"]["input"]
    decoded = gzip.decompress(base64.b64decode(packed["packed_json_gzip_v1"]))
    assert len(decoded) == packed["decoded_bytes"]
    assert json.loads(decoded) == body


def test_unexpected_binding_recheck_logs_only_exception_class(monkeypatch, caplog):
    from codex_plugin_scanner.guard.runtime import structured_output_mediation as mediation

    calls = []

    def query(query, body, **kwargs):
        calls.append((query, body.copy()))
        return {"recheck_required": True} if query == "mediate_prepare" else None

    def recheck():
        raise LookupError("private payload must never be logged")

    monkeypatch.setattr(mediation, "content_query", query)
    mediation.mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result={},
        validated_receipt=None,
        structured_output_json=None,
        binding=None,
        recheck_binding=recheck,
    )
    assert calls[-1][1]["recheck_error"] is True
    assert "LookupError" in caplog.text
    assert "private payload" not in caplog.text


def test_harness_presentation_is_available_without_native_runtime(monkeypatch):
    from codex_plugin_scanner.guard.runtime import structured_output_mediation as mediation

    def unavailable(*args, **kwargs):
        raise client.NativeContentSensitivityError("offline")

    monkeypatch.setattr(mediation, "content_query", unavailable)
    assert mediation.canonical_harness_name(" Pi_Coding_Agent ") == "pi"
    assert mediation.canonical_harness_name("oh-my-pi") == "omp"


def test_expired_mediation_projects_transport_failure_without_opening_a_client(monkeypatch):
    from codex_plugin_scanner.guard.runtime import structured_output_mediation as mediation

    calls = _resident(monkeypatch)
    result = mediation.mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result={"decision": "allow"},
        validated_receipt=None,
        structured_output_json="{}",
        binding=None,
        deadline_monotonic=0.0,
    )
    assert result.action == "withhold"
    assert result.reason_code == "structured_review_deadline_exceeded"
    assert not calls


def test_status_probe_has_request_deadline_and_memo_expires_on_binary_or_manifest_change(monkeypatch, tmp_path):
    _resident(monkeypatch)
    status = client.native_runtime_status()
    binary = tmp_path / "runtime-fixture"
    binary.write_bytes(b"original")
    status.identity.path = binary
    probes = []
    client._status_memo = None

    def probe(*, deadline_monotonic):
        probes.append(deadline_monotonic)
        return status

    monkeypatch.setattr(client, "native_runtime_status", probe)
    monkeypatch.setattr(client, "_scoped_manifest_still_valid", lambda _: True)
    deadline = time.monotonic() + 0.1
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    assert probes == [deadline]
    binary.write_bytes(b"replacement-with-new-identity")
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    assert len(probes) == 2
    monkeypatch.setattr(client, "_scoped_manifest_still_valid", lambda _: False)
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    assert len(probes) == 3


def test_pure_resolution_memo_binds_input_runtime_and_home_without_caching_grants(monkeypatch):
    calls = _resident(monkeypatch)
    body = {"config": {}, "harness": "pi"}
    result = client.content_query("resolution", body)
    result["required"] = True
    assert client.content_query("resolution", body)["required"] is False
    assert len(calls) == 1
    client.content_query("resolution", {"config": {}, "harness": "omp"})
    client.content_query("resolution", {"config": {"managed_policy_status": "invalid"}, "harness": "pi"})
    status = client.native_runtime_status()
    status.identity.sha256 = "c" * 64
    client.content_query("resolution", body)
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: Path("different-home").absolute())
    client.content_query("resolution", body)
    assert len(calls) == 5
    status.available = False
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("resolution", body)
    assert len(calls) == 5


def test_repeated_path_dto_is_cached_only_for_exact_input_and_admitted_runtime(monkeypatch):
    calls = _resident(monkeypatch)
    body = {"path": "ordinary.txt", "cwd": "/fixture", "home_dir": "/fixture/home"}
    assert client.content_query("path", body) is None
    assert client.content_query("path", body) is None
    assert len(calls) == 1
    client.content_query("path", {**body, "cwd": "/other"})
    client.native_runtime_status().identity.sha256 = "c" * 64
    client.content_query("path", body)
    assert len(calls) == 3
    client.native_runtime_status().available = False
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("path", body)


def test_path_cache_pressure_never_evicts_managed_resolution(monkeypatch):
    calls = _resident(monkeypatch)
    resolution = {"config": {}, "harness": "pi"}
    client.content_query("resolution", resolution)
    for index in range(80):
        client.content_query("path", {"path": f"ordinary-{index}", "cwd": None, "home_dir": "/fixture"})
    client.content_query("resolution", resolution)
    assert len(calls) == 81
    assert len(client._path_memo) == 64


@pytest.mark.parametrize("mutation,failures", [("native_budget", 0), ("native_fault", 1)])
def test_bound_native_errors_preserve_deadline_and_resident_health(monkeypatch, mutation, failures):
    _resident(monkeypatch, mutation)
    recorded = []
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *args, **kwargs: recorded.append(args))
    exception = (
        client.NativeContentSensitivityDeadlineError
        if mutation == "native_budget"
        else client.NativeContentSensitivityError
    )
    with pytest.raises(exception):
        client.content_query("content_version", {})
    assert len(recorded) == failures
