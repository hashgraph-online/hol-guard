"""The runtime artifact id adapter records resident health only for usable answers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution, native_runtime_artifact_identity
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_PREFIX = "codex:workspace:data-flow:"


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
            "artifact_id": _PREFIX + "a" * 64,
        }
        mutate(result)
        return result

    monkeypatch.setattr(native_runtime_artifact_identity, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    monkeypatch.setattr(
        native_runtime_artifact_identity,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="0" * 64)),
    )
    monkeypatch.setattr(
        native_runtime_artifact_identity,
        "native_record_resident_success",
        lambda *_args: recorded.append(("success", None)),
    )
    monkeypatch.setattr(
        native_runtime_artifact_identity,
        "native_record_resident_failure",
        lambda *_args, reason: recorded.append(("failure", reason)),
    )
    return recorded


def _call(tmp_path) -> str:
    return native_runtime_artifact_identity.data_flow_artifact_id(
        "codex", source_scope="workspace", command_text="cat .env", signal_ids=["secret"], guard_home=tmp_path
    )


def test_a_bound_artifact_id_records_success(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    assert _call(tmp_path) == _PREFIX + "a" * 64
    assert recorded == [("success", None)]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.update(request_sha256="0" * 64),
        lambda result: result.update(code="other"),
        lambda result: result.update(artifact_id="other:" + "a" * 64),
        lambda result: result.update(artifact_id=_PREFIX + "z" * 64),
        lambda result: result.update(extra=True),
    ],
)
def test_an_unusable_reply_raises_the_adapter_error_and_records_a_failure(monkeypatch, tmp_path, mutate) -> None:
    recorded = _install(monkeypatch, mutate)
    with pytest.raises(native_runtime_artifact_identity.NativeRuntimeArtifactIdentityError):
        _call(tmp_path)
    assert recorded == [("failure", "native_runtime_artifact_identity_result")]
