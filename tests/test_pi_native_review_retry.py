"""Pi/OMP exact retry and acknowledged Watch delivery regressions."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.test_native_review_fixtures import _edge, _worker


@pytest.mark.parametrize("harness", ("pi", "omp"))
@pytest.mark.parametrize("tool_name", ("read", "eval"))
def test_pi_exact_retry_with_new_call_id_consumes_approval_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, tool_name: str
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge(harness))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_call_id": "original-call",
        "session_id": "fixture-session",
        "tool_input": {"path": "src/example.py", "code": "1 + 1"},
    }
    kwargs = {
        "payload": payload,
        "params": {},
        "default_harness": harness,
        "home_dir": tmp_path / "home",
        "guard_home": tmp_path / "guard-home",
        "workspace": tmp_path / "workspace",
    }
    first = worker.review_http_payload(**kwargs)
    request_id = first["approval_request_id"]
    store.resolve_approval_request(
        request_id,
        resolution_action="allow",
        resolution_scope="once",
        reason="operator approved exact action",
        resolved_at=datetime.now(timezone.utc).isoformat(),
    )
    payload["tool_call_id"] = "retry-call"
    retry = worker.review_http_payload(**kwargs)
    assert retry["policy_action"] == "allow"
    assert retry.get("block") is not True
    assert store.list_approval_requests(status="pending") == []
    payload["tool_call_id"] = "later-call"
    later = worker.review_http_payload(**kwargs)
    assert later["policy_action"] == "review"
    assert later["decision"] == "deny"


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_acknowledged_watch_does_not_queue_unsupported_pi_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    edge = _edge(harness)
    edge["result"]["reason_code"] = "native_pre_tool_unknown_review"
    worker, store = _worker(tmp_path, monkeypatch, edge)
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: {"mode": "observe"})
    response = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_name": "eval", "tool_input": {"code": "1 + 1"}},
        params={},
        default_harness=harness,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert response["decision"] == "allow"
    assert response["policy_action"] == "warn"
    assert response.get("block") is not True
    assert "approval_request_id" not in response
    assert store.list_approval_requests(status="pending") == []
