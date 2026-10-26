"""The tool-action identity adapter records resident health only for its own answers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution, native_tool_action_identity
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.runtime.secret_file_request_services.request_models import ToolActionRequestMatch

_REQUEST = ToolActionRequestMatch(
    tool_name="Bash",
    normalized_tool_name="bash",
    command_text="cat .env",
    action_class="local secret read",
    reason="reads a local secret",
)
_ARTIFACT_ID = "codex:project:tool-action:" + "a" * 64


def _install(monkeypatch: pytest.MonkeyPatch, mutate) -> list[tuple[str, object]]:
    recorded: list[tuple[str, object]] = []

    def fake(*, request, response_schema, record_success, **_kwargs) -> dict[str, Any]:
        assert record_success is False
        result: dict[str, Any] = {
            "schema": response_schema,
            "request_id": request["request_id"],
            "request_sha256": _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "artifact_id": _ARTIFACT_ID,
        }
        mutate(result)
        return result

    monkeypatch.setattr(native_tool_action_identity, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    monkeypatch.setattr(
        native_tool_action_identity,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="0" * 64)),
    )
    monkeypatch.setattr(
        native_tool_action_identity,
        "native_record_resident_success",
        lambda *_args: recorded.append(("success", None)),
    )
    monkeypatch.setattr(
        native_tool_action_identity,
        "native_record_resident_failure",
        lambda *_args, reason: recorded.append(("failure", reason)),
    )
    return recorded


def _call(tmp_path) -> str:
    return native_tool_action_identity.tool_action_request_artifact_id(
        "codex", _REQUEST, source_scope="project", guard_home=tmp_path
    )


def test_a_bound_answer_records_success(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    assert _call(tmp_path) == _ARTIFACT_ID
    assert recorded == [("success", None)]


def test_a_refusal_is_reported_as_a_refusal_not_an_outage(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: result.update(status="error", code="request_too_large"))
    with pytest.raises(native_tool_action_identity.NativeToolActionIdentityError, match="rejected"):
        _call(tmp_path)
    assert recorded == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.update(request_sha256="0" * 64),
        lambda result: result.update(artifact_id="codex:project:tool-action:nope"),
        lambda result: result.update(extra=True),
    ],
)
def test_an_unusable_answer_records_a_resident_failure(monkeypatch, tmp_path, mutate) -> None:
    recorded = _install(monkeypatch, mutate)
    with pytest.raises(native_tool_action_identity.NativeToolActionIdentityError):
        _call(tmp_path)
    assert recorded == [("failure", "native_tool_action_request_identity_result")]
