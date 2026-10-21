"""The verified-read decision adapter records resident health only for usable answers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution, native_verified_read_decision
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition

_DECISION = {
    "action": "allow",
    "disposition": "silent-verified",
    "proof_routes": ["verified"],
    "controlling_reasons": [],
    "reasons": [],
}


def _install(monkeypatch: pytest.MonkeyPatch, mutate) -> list[tuple[str, object]]:
    recorded: list[tuple[str, object]] = []

    def fake(*, request, response_schema, record_success, status, **_kwargs) -> dict[str, Any]:
        assert record_success is False
        assert status.identity.sha256 == "0" * 64
        result: dict[str, Any] = {
            "schema": response_schema,
            "request_id": request["request_id"],
            "request_sha256": _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "decision": dict(_DECISION),
        }
        mutate(result)
        return result

    monkeypatch.setattr(native_verified_read_decision, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    monkeypatch.setattr(
        native_verified_read_decision,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="0" * 64)),
    )
    monkeypatch.setattr(
        native_verified_read_decision,
        "native_record_resident_success",
        lambda *_args: recorded.append(("success", None)),
    )
    monkeypatch.setattr(
        native_verified_read_decision,
        "native_record_resident_failure",
        lambda *_args, reason: recorded.append(("failure", reason)),
    )
    return recorded


def _call(tmp_path):
    return native_verified_read_decision.workspace_read_decision(
        operation_id="read-file", binding_digest="sha256:" + "b" * 64, guard_home=tmp_path
    )


def test_a_bound_decision_records_success(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    assert _call(tmp_path).disposition is FinalDisposition.SILENT_VERIFIED
    assert recorded == [("success", None)]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.update(request_sha256="0" * 64),
        lambda result: result.update(code="other"),
        lambda result: result.update(decision="nope"),
        lambda result: result["decision"].update(reasons=[None]),
        lambda result: result["decision"].update(controlling_reasons=["text"]),
    ],
)
def test_an_unusable_reply_raises_the_adapter_error_and_records_a_failure(monkeypatch, tmp_path, mutate) -> None:
    recorded = _install(monkeypatch, mutate)
    with pytest.raises(native_verified_read_decision.NativeVerifiedReadDecisionError):
        _call(tmp_path)
    assert recorded == [("failure", "native_verified_read_decision_result")]


def test_a_missing_resident_reply_leaves_recording_to_the_transport(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_kwargs: None)
    with pytest.raises(native_verified_read_decision.NativeVerifiedReadDecisionError, match="unavailable"):
        _call(tmp_path)
    assert recorded == []


def test_a_resident_failure_fails_the_workspace_read_closed(monkeypatch) -> None:
    from codex_plugin_scanner.guard.runtime import verified_read_execution

    def unavailable(*_args, **_kwargs):
        raise native_verified_read_decision.NativeVerifiedReadDecisionError("native_verified_read_decision_unavailable")

    monkeypatch.setattr(verified_read_execution, "_decision", unavailable)
    monkeypatch.setattr(verified_read_execution, "_source_digest", lambda: "digest")
    monkeypatch.setattr(verified_read_execution, "_current_workspace_context", lambda: "context")
    monkeypatch.setattr(
        verified_read_execution,
        "_perform_read",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="ok\n", operation_id="read-file"),
    )
    monkeypatch.setattr(verified_read_execution, "_proof", lambda *_args, **_kwargs: object())
    assert verified_read_execution.try_execute_verified_local_read(("cat", "README.md")) is None
