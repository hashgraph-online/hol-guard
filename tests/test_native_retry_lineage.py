"""Shim tests for the native retry-lineage client: transport and binding only."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution, native_retry_lineage
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_LINEAGE = {"version": 1, "source": "hook", "harness": "pi", "session_id": "s", "lineage_id": "a" * 64}


def _install(monkeypatch: pytest.MonkeyPatch, mutate=lambda _result: None):
    recorded: list[tuple[str, object]] = []
    sent: list[dict[str, Any]] = []

    def fake(*, operation, request, guard_home, response_schema, record_success, status, **_kwargs):
        assert operation == "retry_lineage_capture"
        assert record_success is False
        assert status.identity.sha256 == "0" * 64
        sent.append({"request": request, "guard_home": guard_home})
        result: dict[str, Any] = {
            "schema": response_schema,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "lineage": dict(_LINEAGE),
        }
        mutate(result)
        return result

    monkeypatch.setattr(native_retry_lineage, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    monkeypatch.setattr(
        native_retry_lineage,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="0" * 64)),
    )
    monkeypatch.setattr(
        native_retry_lineage, "native_record_resident_success", lambda *_args: recorded.append(("success", None))
    )
    monkeypatch.setattr(
        native_retry_lineage,
        "native_record_resident_failure",
        lambda *_args, reason: recorded.append(("failure", reason)),
    )
    return recorded, sent


def test_sends_scalars_only_and_returns_the_bound_record(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    recorded, sent = _install(monkeypatch)
    payload: dict[object, object] = {
        "session_id": "s",
        "turn_id": None,
        "tool_input": {"command": "rm -rf build"},
        "turnId": 42,
        "flag": True,
        "toolCallId": "x" * 300,
        "threadId": "bad-\ud800",
        "bad-\udfff": "dropped",
        7: "dropped",
    }

    lineage = native_retry_lineage.capture_retry_lineage(
        payload,
        harness="pi",
        workspace="/w",
        action_envelope={"command": "ls"},
        guard_home=tmp_path,
    )

    assert lineage == _LINEAGE
    assert recorded == [("success", None)]
    request = sent[0]["request"]
    assert sent[0]["guard_home"] == tmp_path
    # Nothing but a short, encodable string can name an identifier, so every
    # other value reaches the resident as a refusal-equivalent ``false``.
    assert request["payload"] == {
        "session_id": "s",
        "turn_id": None,
        "tool_input": False,
        "turnId": False,
        "flag": False,
        "toolCallId": False,
        "threadId": False,
    }
    assert request["workspace"] == "/w"
    assert request["action_envelope"] == {"command": "ls"}
    assert request["harness"] == "pi"


def test_a_refused_payload_is_a_healthy_answer(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    recorded, _sent = _install(monkeypatch, lambda result: result.update(lineage=None))

    assert native_retry_lineage.capture_retry_lineage({"session_id": 7}, harness="pi", guard_home=tmp_path) is None
    assert recorded == [("success", None)]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.update(request_sha256="sha256:" + "0" * 64),
        lambda result: result.update(request_id="other"),
        lambda result: result.update(code="native_retry_lineage_capture_invalid"),
        lambda result: result.update(lineage=["not", "a", "record"]),
        lambda result: result.update(extra=True),
    ],
)
def test_an_unbound_or_malformed_reply_carries_no_lineage(monkeypatch: pytest.MonkeyPatch, tmp_path, mutate) -> None:
    recorded, _sent = _install(monkeypatch, mutate)

    assert native_retry_lineage.capture_retry_lineage({"session_id": "s"}, harness="pi", guard_home=tmp_path) is None
    assert recorded == [("failure", "native_retry_lineage_capture_result")]


@pytest.mark.parametrize("envelope", [{"score": float("nan")}, {"value": "\ud800"}, {"value": object()}])
def test_an_untransportable_envelope_never_reaches_the_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path, envelope
) -> None:
    recorded, sent = _install(monkeypatch)

    lineage = native_retry_lineage.capture_retry_lineage(
        {"session_id": "s"}, harness="pi", action_envelope=envelope, guard_home=tmp_path
    )

    assert lineage is None
    assert sent == []
    assert recorded == []


def test_an_untransportable_workspace_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    recorded, sent = _install(monkeypatch)

    lineage = native_retry_lineage.capture_retry_lineage(
        {"session_id": "s"}, harness="pi", workspace="/w/bad-\udcff", guard_home=tmp_path
    )

    assert lineage is None
    assert sent == []
    assert recorded == []


def test_a_request_over_the_resident_budget_is_refused_locally(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    recorded, sent = _install(monkeypatch)
    envelope = {"content": "x" * (4 * 1024 * 1024)}

    lineage = native_retry_lineage.capture_retry_lineage(
        {"session_id": "s"}, harness="pi", action_envelope=envelope, guard_home=tmp_path
    )

    assert lineage is None
    assert sent == []
    assert recorded == []
    # Just under the budget still crosses.
    envelope = {"content": "x" * (4 * 1024 * 1024 - 1024)}
    assert (
        native_retry_lineage.capture_retry_lineage(
            {"session_id": "s"}, harness="pi", action_envelope=envelope, guard_home=tmp_path
        )
        == _LINEAGE
    )


def test_an_unavailable_resident_drops_the_lineage(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    recorded, sent = _install(monkeypatch)
    monkeypatch.setattr(native_retry_lineage, "ensure_resident_prerequisite", lambda _home: False)

    assert native_retry_lineage.capture_retry_lineage({"session_id": "s"}, harness="pi", guard_home=tmp_path) is None
    assert sent == []
    assert recorded == []
