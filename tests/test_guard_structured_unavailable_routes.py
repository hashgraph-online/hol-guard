"""Daemon availability routes preserve managed structured withholding."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.hook_review import hook_worker, hook_worker_unavailable
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("required", [False, True])
def test_daemon_unavailable_routes_withhold_only_required_structured_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
    required: bool,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    worker = hook_worker.HookWorker(store=GuardStore(guard_home))

    def render(kind, adapter, params, **_transport):
        if kind == "unavailable_event":
            return None
        assert kind == "structured_outage"
        assert adapter == harness
        assert params == {"event_name": "PostToolUse"}
        overlay = hook_worker_unavailable.withhold_structured_destination({}) if required else {}
        return "document", overlay

    monkeypatch.setattr(hook_worker_unavailable, "native_render_cli", render)
    # Pin the native edge as unavailable so the result is independent of any
    # runtime binary installed on the machine running the test.
    monkeypatch.setattr(worker, "_review_raw_hook_native", lambda **_: None)
    try:
        result = worker.review_http_payload(
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "note.json"},
                "tool_response": [{"type": "text", "text": '{"note":"synthetic"}'}],
                "structured_output_json": '{"note":"synthetic"}',
            },
            params={},
            default_harness=harness,
            guard_home=guard_home,
            home_dir=tmp_path,
            workspace=workspace,
        )
    finally:
        worker.close()
    assert result["decision"] == "allow"
    assert worker._last_native_decision_receipt is None
    if required:
        mediation = result["structured_content_mediation"]
        assert mediation["action"] == "withhold"
        assert mediation["reason_code"] == "structured_native_edge_unavailable"
        assert not mediation.get("native_decision_id")
    else:
        assert "structured_content_mediation" not in result


def test_unavailable_event_route_uses_native_projection_and_activity_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[dict[str, object]] = []

    class StubWorker:
        def _apply_structured_unavailable_overlay(self, response, **_kwargs):
            return response

        def _record_post_tool_activity(self, **kwargs):
            recorded.append(kwargs)

    native = {
        "event_name": "PostToolUse",
        "response": {"decision": "allow"},
        "activity_recorded": True,
    }
    monkeypatch.setattr(hook_worker_unavailable, "native_unavailable_event_response", lambda *args, **kwargs: native)
    result = hook_worker_unavailable.unavailable_event_response(
        StubWorker(),
        payload={"hook_event_name": "post_toolcall"},
        harness="pi",
        guard_home=tmp_path,
        workspace=None,
        deadline=None,
    )
    assert result == {"decision": "allow"}
    assert recorded == []


def test_unavailable_event_uses_standalone_rust_without_sending_tool_contents(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    def standalone(feature, command, request, *, deadline, **_transport):
        assert feature == "native-hook-unavailable-event-v1"
        assert command == "hook-unavailable-event"
        assert request == {"harness": "claude-code", "payload": {"hookEventName": "PermissionRequestV2"}}
        assert deadline == 12.0
        return {
            "event_name": "PermissionRequest",
            "response": {"guard_permission_passthrough": True},
            "activity_recorded": False,
        }

    class StubWorker:
        def _apply_structured_unavailable_overlay(self, response, **_kwargs):
            return response

    monkeypatch.setattr(hook_worker_unavailable, "native_unavailable_event_response", lambda *_a, **_k: None)
    monkeypatch.setattr(runtime_request, "runtime_answer", standalone)
    assert hook_worker_unavailable.unavailable_event_response(
        StubWorker(),
        payload={"hookEventName": "PermissionRequestV2", "tool_input": {"text": "fixture"}},
        harness="claude-code",
        guard_home=tmp_path,
        workspace=None,
        deadline=12.0,
    ) == {"guard_permission_passthrough": True}


def test_structured_outage_overlay_does_not_read_python_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[dict[str, object]] = []

    def render(kind, harness, params, **_kwargs):
        seen.append({"kind": kind, "harness": harness, "params": params})
        return "document", {}

    monkeypatch.setattr(hook_worker_unavailable, "native_render_cli", render)
    overlay = hook_worker_unavailable.structured_outage_overlay(
        harness="pi",
        event_name="PostToolUse",
        guard_home=tmp_path,
        deadline=None,
        load_config=lambda: (_ for _ in ()).throw(AssertionError("python config read")),
    )
    assert overlay == {}
    assert seen == [{"kind": "structured_outage", "harness": "pi", "params": {"event_name": "PostToolUse"}}]
