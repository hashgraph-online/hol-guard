"""Compiled native PreTool secret reads must queue Approval Center."""

from __future__ import annotations

import sys
from pathlib import Path

from native_hook_client_support import _invoke, _request, _result
from native_hook_client_support import native_runtime as _native_runtime_fixture  # noqa: F401

_TESTS_DIR = Path(__file__).resolve().parents[2] / "tests"
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from test_native_review_approval_coordination import _worker


def test_protected_dotenv_shell_read_queues_approval(
    native_runtime: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch,
) -> None:
    runtime, state_dir = native_runtime
    request = _request(
        runtime,
        tmp_path,
        command="cat .env.synthetic",
        risk_actions={"local_secret_read": "require-reapproval"},
    )
    edge = _invoke(runtime, state_dir, request)
    result = _result(edge)
    assert result["minimum_action"] == "require-reapproval"
    assert result["policy_action"] == "require-reapproval"
    assert result["reason_code"] in {
        "native_policy_reapproval_required",
        "native_sensitive_access_review",
    }
    assert result["minimum_action"] != "allow"

    worker, store = _worker(tmp_path, monkeypatch, edge)
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "tool_input": {"command": "cat .env.synthetic"},
        },
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert response.get("prompted") is True
    assert isinstance(response.get("approval_request_id"), str)
    assert store.list_approval_requests(status="pending")
    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] != "allow"
