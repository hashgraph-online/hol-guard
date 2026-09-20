"""Failure-only Windows fixture diagnostics with the real Python review decoder."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ci.native_runtime import test_guard_native_runtime_windows_resident as windows
from codex_plugin_scanner.guard import native_runtime


def _control(tmp_path, monkeypatch, *, output=None, raised=None, available=True):
    request = replace(windows._request(tmp_path, "diagnostic-review"), deadline_monotonic=time.monotonic() + 0.75)
    snapshot = {"generation": 7, "policy_digest": "b" * 64, "runtime_identity": "a" * 64}
    calls = []
    diagnostics = []
    original_evidence = windows._review_failure_evidence

    def evidence(*args):
        value = original_evidence(*args)
        diagnostics.append(value)
        return value

    def client(**kwargs):
        calls.append(kwargs)
        if raised is not None:
            raise raised
        return output

    monkeypatch.setattr(native_runtime, "native_resident_client_request", client)
    monkeypatch.setattr(
        native_runtime,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=available,
            compatible=True,
            identity=SimpleNamespace(path=tmp_path / "runtime.exe", sha256="a" * 64),
            capabilities=SimpleNamespace(features=("resident-protocol-v2",)),
            reason="native_ready" if available else "native_unavailable",
        ),
    )
    monkeypatch.setattr(windows, "native_resident_client_failure_code", lambda: None)
    monkeypatch.setattr(windows, "_review_failure_evidence", evidence)
    return request, snapshot, calls, client, diagnostics


def test_successful_review_forwards_once_and_never_collects_failure_evidence(tmp_path, monkeypatch):
    output = json.dumps(
        {"decision": "allow", "model_output_action": "allow_original", "notice": "none", "reason_code": "ok"}
    ).encode()
    request, snapshot, calls, client, _diagnostics = _control(tmp_path, monkeypatch, output=output)

    def unexpected(*_args):
        raise AssertionError("successful review must not collect diagnostics")

    monkeypatch.setattr(windows, "_review_failure_evidence", unexpected)
    windows._require_initial_allow(request, snapshot)
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == request.deadline_monotonic
    envelope = json.loads(calls[0]["payload"])
    assert envelope["request_id"] == request.request_id
    assert envelope["raw_payload"] == request.payload
    assert envelope["policy_snapshot"] == snapshot
    assert native_runtime.native_resident_client_request is client


@pytest.mark.parametrize(
    "output,shape,error",
    [
        (None, "none", None),
        (b"not-json", "invalid_json", None),
        (b"[]", "non_object", None),
        (b'{"error":"native_policy_snapshot_not_current"}', "other_object", "native_policy_snapshot_not_current"),
        (b'{"schema":"guard-hook-edge-result.v2","receipt":{}}', "hook_edge", None),
    ],
)
def test_original_none_result_reports_returned_error_or_decoder_failure(tmp_path, monkeypatch, output, shape, error):
    request, snapshot, calls, client, diagnostics = _control(tmp_path, monkeypatch, output=output)
    with pytest.raises(AssertionError):
        windows._require_initial_allow(request, snapshot)
    assert len(diagnostics) == 1
    evidence = diagnostics[0]
    assert evidence["native_client_calls"] == len(calls) == 1
    assert evidence["native_client_returned"] is True
    assert evidence["client_failure_code"] is None
    assert evidence["response_shape"] == shape
    assert evidence.get("native_error") == error
    assert evidence["resident_failures"] == 1
    assert calls[0]["deadline_monotonic"] == request.deadline_monotonic
    if output is not None:
        assert evidence["response_sha256"] == hashlib.sha256(output).hexdigest()
    if shape == "hook_edge":
        assert evidence["receipt_valid"] is False and evidence["receipt_matches_edge"] is False
    assert native_runtime.native_resident_client_request is client


def test_early_failure_is_not_misattributed_to_a_native_client_call(tmp_path, monkeypatch):
    request, snapshot, calls, client, diagnostics = _control(tmp_path, monkeypatch, available=False)
    with pytest.raises(AssertionError):
        windows._require_initial_allow(request, snapshot)
    assert len(diagnostics) == 1
    evidence = diagnostics[0]
    assert evidence["native_client_calls"] == 0 and calls == []
    assert evidence["native_client_returned"] is False
    assert evidence["response_present"] is False
    assert native_runtime.native_resident_client_request is client


def test_raw_response_and_private_error_text_are_not_printed(tmp_path, monkeypatch):
    private = "C:/Users/synthetic/private-state"
    output = json.dumps({"error": private, "result": {"reviewed_excerpt": private}}).encode()
    request, snapshot, _calls, _client, diagnostics = _control(tmp_path, monkeypatch, output=output)
    with pytest.raises(AssertionError):
        windows._require_initial_allow(request, snapshot)
    assert len(diagnostics) == 1
    evidence = diagnostics[0]
    assert evidence["native_error"] == "other"
    assert private not in json.dumps(evidence)
    assert "reviewed_excerpt" not in json.dumps(evidence)


def test_original_native_exception_and_wrapper_restoration_are_preserved(tmp_path, monkeypatch):
    sentinel = RuntimeError("original native client exception")
    request, snapshot, calls, client, diagnostics = _control(tmp_path, monkeypatch, raised=sentinel)
    with pytest.raises(RuntimeError) as caught:
        windows._require_initial_allow(request, snapshot)
    assert caught.value is sentinel
    assert len(calls) == 1
    assert diagnostics == []
    assert native_runtime.native_resident_client_request is client
