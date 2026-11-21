import json
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard import native_hook_direct as direct

_EDGE = {
    "schema": "guard-hook-edge-result.v2",
    "authority": "rust",
    "harness": "codex",
    "event_name": "PreToolUse",
    "payload_kind": "inline",
    "result": {"decision": "allow", "minimum_action": "allow", "policy_action": "allow"},
    "receipt": {"request_id": "req-1", "decision_id": "a" * 64},
    "harness_response": {"policy_action": "allow"},
    "containment_route": "none",
}

_LIFECYCLE_EDGE = {"harness_response": {"hookSpecificOutput": {"hookEventName": "PermissionRequest"}}}


def test_native_hook_direct_decodes_an_answer(monkeypatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        direct, "native_runtime_status", lambda **_kwargs: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))
    )

    def resident(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"schema": "guard-hook-direct-result.v1", "outcome": "answer", "edge": _EDGE}

    monkeypatch.setattr(direct, "_resident_request", resident)
    result = direct.native_hook_direct(
        harness="codex",
        guard_home=tmp_path,
        payload={"hook_event_name": "PreToolUse"},
        workspace=tmp_path,
        home_dir=tmp_path,
        deadline=None,
    )
    assert result == _EDGE
    assert calls[0]["operation"] == "hook_direct"
    assert calls[0]["required_feature"] == "hook-direct-v1"


def test_native_hook_direct_preserves_defer(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        direct, "native_runtime_status", lambda **_kwargs: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))
    )
    monkeypatch.setattr(
        direct,
        "_resident_request",
        lambda **_kwargs: {
            "schema": "guard-hook-direct-result.v1",
            "outcome": "defer",
            "reason": "review_queue",
        },
    )
    assert direct.native_hook_direct(
        harness="codex",
        guard_home=tmp_path,
        payload={},
        workspace=None,
        home_dir=None,
        deadline=None,
    ) == {"outcome": "defer", "reason": "review_queue"}


def test_native_hook_direct_decodes_lifecycle_answer(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        direct, "native_runtime_status", lambda **_kwargs: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))
    )
    monkeypatch.setattr(
        direct,
        "_resident_request",
        lambda **_kwargs: {"schema": "guard-hook-direct-result.v1", "outcome": "answer", "edge": _LIFECYCLE_EDGE},
    )

    assert (
        direct.native_hook_direct(
            harness="claude-code",
            guard_home=tmp_path,
            payload={"hook_event_name": "PermissionRequest"},
            workspace=None,
            home_dir=None,
            deadline=None,
        )
        == _LIFECYCLE_EDGE
    )


def test_native_hook_direct_records_health_after_valid_answer(monkeypatch, tmp_path: Path) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(
        direct, "native_runtime_status", lambda **_kwargs: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))
    )
    monkeypatch.setattr(direct, "native_record_resident_success", lambda *_args: recorded.append("success"))
    monkeypatch.setattr(
        direct,
        "_resident_request",
        lambda **_kwargs: {
            "schema": "guard-hook-direct-result.v1",
            "outcome": "answer",
            "edge": _EDGE,
        },
    )

    assert (
        direct.native_hook_direct(
            harness="codex",
            guard_home=tmp_path,
            payload={},
            workspace=None,
            home_dir=None,
            deadline=None,
        )
        == _EDGE
    )
    assert recorded == ["success"]


def test_native_hook_direct_records_health_after_invalid_answer(monkeypatch, tmp_path: Path) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(
        direct, "native_runtime_status", lambda **_kwargs: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))
    )
    monkeypatch.setattr(direct, "native_record_resident_failure", lambda *_args, **_kwargs: recorded.append("failure"))
    monkeypatch.setattr(
        direct,
        "_resident_request",
        lambda **_kwargs: {
            "schema": "guard-hook-direct-result.v1",
            "outcome": "answer",
            "edge": {"malformed": True},
        },
    )

    assert (
        direct.native_hook_direct(
            harness="codex",
            guard_home=tmp_path,
            payload={},
            workspace=None,
            home_dir=None,
            deadline=None,
        )
        is None
    )
    assert recorded == ["failure"]


def test_resident_request_accepts_a_direct_union_without_a_status_field(monkeypatch, tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"runtime")
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=runtime, sha256="a" * 64),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "hook-direct-v1")),
    )
    monkeypatch.setattr(
        native_execution,
        "native_resident_client_request",
        lambda **_kwargs: json.dumps(
            {"schema": "guard-hook-direct-result.v1", "outcome": "answer", "edge": _EDGE}
        ).encode(),
    )

    result = native_execution._resident_request(
        operation="hook_direct",
        request={},
        guard_home=tmp_path,
        timeout_seconds=1.0,
        required_feature="hook-direct-v1",
        record_success=False,
        status=status,
    )

    assert result == {"schema": "guard-hook-direct-result.v1", "outcome": "answer", "edge": _EDGE}
