"""Unknown native input can only receive an exact fixture-controlled block."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import queue_native_pre_tool_review
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_launcher_approval import LauncherApprovalControl


def _session(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    metrics = SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": 0}})
    return SimpleNamespace(
        workspace=workspace,
        store=store,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
    )


def _queue(session, harness="codex"):
    row = queue_native_pre_tool_review(
        session.store,
        harness=harness,
        payload={},
        native_result={"minimum_action": "review", "reason": "Unknown input qualification"},
        workspace=session.workspace,
        guard_home=session.store.guard_home,
    )
    assert row is not None
    return row["request_id"]


def _result(controller, operation):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = controller.result(operation)
        if result["state"] != "waiting":
            return result
        time.sleep(0.01)
    pytest.fail("unknown-input control did not terminate")


@pytest.mark.parametrize("harness", ["codex", "claude-code"])
def test_missing_command_can_only_be_blocked_through_real_resolution(tmp_path, harness):
    session = _session(tmp_path)
    controller = LauncherApprovalControl(session)
    try:
        with pytest.raises(ValueError, match="invalid_identity"):
            controller.begin(harness, {}, resolution="allow")
        started = controller.begin(harness, {}, resolution="block", timeout_seconds=2)
        request_id = _queue(session, harness)
        result = _result(controller, started["operation_id"])
        assert result["state"] == "resolved", result
        assert result["request_id"] == request_id
        assert result["resolution"] == "block" and result["approval_durable"] is True
        row = session.store.get_approval_request(request_id)
        assert row["launch_target"] == "tool:tool"
        assert row["action_envelope_json"]["command"] is None
        assert row["action_envelope_json"]["action_type"] == ("config_change" if harness == "codex" else "mcp_tool")
        assert row["resolution_action"] == "block"
        assert result["matching"] == "exact_identity_and_new_row"
        assert str(tmp_path) not in json.dumps(result)
        with session.store._connect() as connection:
            assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
    finally:
        controller.close()


@pytest.mark.parametrize(
    "payload",
    [{"tool_name": "Read"}, {"tool_input": {"url": "https://example.invalid"}}, {"tool_input": {"path": "/tmp/x"}}],
)
def test_nonempty_noncommand_identity_cannot_use_empty_input_block_helper(tmp_path, payload):
    controller = LauncherApprovalControl(_session(tmp_path))
    try:
        with pytest.raises(ValueError, match="invalid_identity"):
            controller.begin("codex", payload, resolution="block")
    finally:
        controller.close()


def test_old_unknown_request_cannot_be_silently_selected(tmp_path):
    session = _session(tmp_path)
    request_id = _queue(session)
    controller = LauncherApprovalControl(session)
    try:
        started = controller.begin("codex", {}, resolution="block", timeout_seconds=0.1)
        assert _queue(session) == request_id
        result = _result(controller, started["operation_id"])
        assert result["state"] == "failed"
        assert session.store.get_approval_request(request_id)["status"] == "pending"
    finally:
        controller.close()


@pytest.mark.parametrize(
    ("harness", "action_type", "tool_name", "accepted"),
    [
        ("codex", "config_change", None, True),
        ("codex", "config_change", "tool", False),
        ("claude-code", "config_change", None, False),
    ],
)
def test_only_exact_codex_canonical_empty_profile_is_accepted(
    tmp_path, monkeypatch, harness, action_type, tool_name, accepted
):
    import threading

    session = _session(tmp_path)
    controller = LauncherApprovalControl(session)
    release = threading.Event()
    original = controller._new_pending

    def delayed(operation):
        assert release.wait(2)
        return original(operation)

    monkeypatch.setattr(controller, "_new_pending", delayed)
    try:
        started = controller.begin(harness, {}, resolution="block", timeout_seconds=2)
        request_id = _queue(session, harness)
        row = session.store.get_approval_request(request_id)
        envelope = {**row["action_envelope_json"], "action_type": action_type, "tool_name": tool_name}
        with session.store._connect() as connection:
            connection.execute(
                "update approval_requests set action_envelope_json=? where request_id=?",
                (json.dumps(envelope), request_id),
            )
        release.set()
        result = _result(controller, started["operation_id"])
        assert result["state"] == ("resolved" if accepted else "failed")
        assert session.store.get_approval_request(request_id)["status"] == ("resolved" if accepted else "pending")
    finally:
        release.set()
        controller.close()
