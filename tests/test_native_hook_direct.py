from pathlib import Path
from types import SimpleNamespace

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


def test_native_hook_direct_decodes_an_answer(monkeypatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(direct, "native_runtime_status", lambda **_kwargs: SimpleNamespace(identity=object()))

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
    monkeypatch.setattr(direct, "native_runtime_status", lambda **_kwargs: SimpleNamespace(identity=object()))
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
