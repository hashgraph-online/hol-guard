"""A user's refusal sticks briefly; impossible approvals never start a wait."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.test_native_review_approval_coordination import _edge, _worker


@pytest.mark.parametrize("ask", [False, True])
def test_keep_blocked_does_not_requeue_identical_retry(tmp_path: Path, monkeypatch, ask: bool) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge("omp", action_type="unknown"), ask=ask)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "learn",
        "tool_input": {"memory": "Synthetic note"},
        "session_id": "test-session",
        "tool_call_id": "first",
    }
    kwargs = dict(
        payload=payload,
        params={},
        default_harness="omp",
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=tmp_path / "workspace",
    )
    worker.review_http_payload(**kwargs)
    pending = store.list_approval_requests(status="pending")
    assert len(pending) == 1
    store.resolve_approval_request(
        pending[0]["request_id"],
        resolution_action="block",
        resolution_scope="once",
        reason="Keep blocked",
        resolved_at=datetime.now(timezone.utc).isoformat(),
    )
    for _ in range(2):
        refused = worker.review_http_payload(**kwargs)
        assert refused["reason_code"] == "native_review_user_block"
        assert refused["policy_action"] == "block"
        assert refused["prompted"] is False
        assert "approval_request_id" not in refused
        assert "waiting for" not in str(refused)
        assert store.list_approval_requests(status="pending") == []
    payload["tool_input"] = {"memory": "Different synthetic note"}
    worker.review_http_payload(**kwargs)
    assert len(store.list_approval_requests(status="pending")) == 1
    worker.close()


def test_real_native_omp_hook_honors_keep_blocked(tmp_path: Path, monkeypatch, native_hook_force) -> None:
    from codex_plugin_scanner.guard.config import update_guard_settings
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.store import GuardStore

    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    store = GuardStore(home / ".hol-guard")
    update_guard_settings(store.guard_home, {"blocked_request_mode": "ask"})
    worker = HookWorker(store=store, workspace=workspace)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "learn",
        "tool_input": {"memory": "Synthetic retry test"},
        "session_id": "retry-test",
        "tool_call_id": "initial",
        "cwd": str(workspace),
    }
    kwargs = dict(
        payload=payload,
        params={},
        default_harness="omp",
        home_dir=home,
        guard_home=store.guard_home,
        workspace=workspace,
    )
    try:
        first = worker.review_http_payload(**kwargs)
        assert first["reason_code"] == "native_pre_tool_unknown_review"
        pending = store.list_approval_requests(status="pending")
        assert len(pending) == 1
        store.resolve_approval_request(
            pending[0]["request_id"],
            resolution_action="block",
            resolution_scope="once",
            reason="Keep blocked",
            resolved_at=datetime.now(timezone.utc).isoformat(),
        )
        for call_id in ("retry-one", "retry-two"):
            payload["tool_call_id"] = call_id
            refused = worker.review_http_payload(**kwargs)
            assert refused["reason_code"] == "native_review_user_block"
            assert refused["prompted"] is False
            assert store.list_approval_requests(status="pending") == []
    finally:
        worker.close()


def test_old_refusal_does_not_block_a_new_review(tmp_path: Path, monkeypatch) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge("omp", action_type="unknown"))
    kwargs = dict(
        payload={"hook_event_name": "PreToolUse", "tool_name": "learn", "tool_input": {"memory": "Synthetic note"}},
        params={},
        default_harness="omp",
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=tmp_path / "workspace",
    )
    worker.review_http_payload(**kwargs)
    pending = store.list_approval_requests(status="pending")
    store.resolve_approval_request(
        pending[0]["request_id"],
        resolution_action="block",
        resolution_scope="once",
        reason="Keep blocked",
        resolved_at=(datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(),
    )
    response = worker.review_http_payload(**kwargs)
    assert response["prompted"] is True
    assert len(store.list_approval_requests(status="pending")) == 1
    worker.close()


@pytest.mark.parametrize("command", ["python3 script.py --seed 7", "git push origin dev --dry-run"])
def test_ask_without_retry_binding_does_not_offer_approval_wait(tmp_path: Path, monkeypatch, command: str) -> None:
    edge = _edge("omp", action_type="command")
    edge["result"].update(reason_code="native_command_review_required")
    worker, store = _worker(tmp_path, monkeypatch, edge)
    response = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": command}},
        params={},
        default_harness="omp",
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=tmp_path / "workspace",
    )
    assert response["prompted"] is False
    assert response["blocked_request_mode"] == "safe-alternative"
    assert "approval_request_id" not in response
    assert "approval_url" not in response
    assert "approving it there will not let you run it" in response["reason"]
    assert len(store.list_approval_requests(status="pending")) == 1
    worker.close()
