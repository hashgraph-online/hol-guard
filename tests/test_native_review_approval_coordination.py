"""Native PreToolUse review queues a resolvable approval-center request."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker, HookWorkerUnsupported
from codex_plugin_scanner.guard.store import GuardStore


def _edge(harness: str, *, url: str = "https://example.test") -> dict[str, object]:
    return {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": harness,
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "result": {
            "schema": "guard-pre-tool-result.v1",
            "version": 1,
            "authority": "rust",
            "decision": "deny",
            "policy_action": "review",
            "minimum_action": "review",
            "reason_code": "native_network_review",
            "reason": "HOL Guard requires review before this network action can execute.",
        },
    }


def _test_request_digest(harness: str, payload: object, workspace: object) -> str:
    semantic = dict(payload) if isinstance(payload, dict) else payload
    if isinstance(semantic, dict):
        for key in (
            "event",
            "eventName",
            "hook_event_name",
            "hookEventName",
            "hook_name",
            "hookName",
            "timestamp",
            "timestamp_ms",
            "timestampMs",
            "created_at",
            "createdAt",
            "received_at",
            "receivedAt",
        ):
            semantic.pop(key, None)
    encoded = json.dumps(
        {"harness": harness, "payload": semantic, "workspace": str(workspace) if workspace is not None else None},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edge: dict[str, object]) -> tuple[HookWorker, GuardStore]:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )

    def review_raw_hook_native(*_args: object, **kwargs: object) -> dict[str, object]:
        rendered = copy.deepcopy(edge)
        result = rendered["result"]
        assert isinstance(result, dict)
        harness = str(rendered["harness"])
        workspace = kwargs.get("cwd")
        digest = _test_request_digest(harness, kwargs.get("payload"), workspace)
        rendered["receipt"] = {
            "schema": "guard-native-hook-decision-receipt.v1",
            "version": 1,
            "authority": "rust",
            "decision_id": digest,
            "request_id": f"sha256:{digest}",
            "request_digest": digest,
            "harness": harness,
            "event_name": "PreToolUse",
            "payload_kind": "inline",
            "policy_generation": 1,
            "policy_digest": None,
            "rule_digest": None,
            "runtime_identity": None,
            "decision": result["decision"],
            "model_output_action": "not_applicable",
            "policy_action": result["policy_action"],
            "observed_policy_action": None,
            "reason_code": result["reason_code"],
            "workspace_bound": workspace is not None,
            "source_ref_external_allowed": False,
            "reviewed_output_sha256": None,
            "observe_mode": False,
            "deadline_budget_ms": None,
        }
        return rendered

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        review_raw_hook_native,
    )
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_runtime_state(
        session_id="native-review",
        daemon_host="127.0.0.1",
        daemon_port=4781,
        started_at="2026-09-05T00:00:00+00:00",
        last_heartbeat_at="2026-09-05T00:00:00+00:00",
    )
    return HookWorker(store=store), store


def test_cursor_native_review_asks_and_queues_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge("cursor"))
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.test"},
        },
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )

    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "ask"
    assert response["policy_action"] == "review"
    assert isinstance(response.get("approval_request_id"), str)
    assert response["primary_approval_request_id"] == response["approval_request_id"]
    assert response["guardApprovalRequestId"] == response["approval_request_id"]
    pending = store.list_approval_requests(status="pending")
    assert len(pending) == 1
    assert pending[0]["policy_action"] == "review"
    assert str(pending[0]["artifact_hash"]).startswith("native-review-v4:")
    envelope = pending[0].get("action_envelope_json")
    assert isinstance(envelope, dict)
    assert envelope["tool_name"] == "WebFetch"
    assert envelope["event_name"] == "PreToolUse"
    assert envelope["pre_execution_result"] == "review"
    assert envelope["action_type"] == "network_request"
    assert "example.test" in envelope.get("network_hosts", [])


def test_native_block_stays_terminal_without_an_approval_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge = _edge("codex")
    result = edge["result"]
    assert isinstance(result, dict)
    result["minimum_action"] = "block"
    result["policy_action"] = "block"
    result["reason_code"] = "native_destructive_command"
    worker, store = _worker(tmp_path, monkeypatch, edge)
    response = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "rm -rf /"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )

    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "deny"
    assert response["policy_action"] == "block"
    assert "approval_request_id" not in response
    assert store.list_approval_requests(status="pending") == []


def test_native_review_does_not_raise_worker_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker, _store = _worker(tmp_path, monkeypatch, _edge("codex"))
    try:
        worker.review_http_payload(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"url": "https://example.test"}},
            params={},
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
        )
    except HookWorkerUnsupported:
        pytest.fail("native review must queue an approval instead of raising HookWorkerUnsupported")


def test_native_review_queue_failure_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge("codex"))

    def fail_persist(*_args: object, **_kwargs: object) -> str:
        raise OSError("approval store unavailable")

    monkeypatch.setattr(store, "add_approval_request", fail_persist)
    response = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"url": "https://example.test"}},
        params={},
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )

    hook_output = response["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "deny"
    assert response["policy_action"] == "block"
    assert response["reason_code"] == "native_review_queue_failed"
    assert "approval_request_id" not in response
    assert "approval_url" not in response
    assert store.list_approval_requests(status="pending") == []


def test_native_review_honors_resolved_allow_on_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge("cursor"))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://example.test"},
    }
    kwargs = {
        "payload": payload,
        "params": {},
        "default_harness": "cursor",
        "home_dir": tmp_path / "home",
        "guard_home": tmp_path / "guard-home",
        "workspace": tmp_path / "workspace",
    }
    first = worker.review_http_payload(**kwargs)
    request_id = first.get("approval_request_id")
    assert isinstance(request_id, str)
    resolved = store.resolve_harness_native_approval_request(
        request_id,
        reason="cursor accepted the native review",
        resolved_at=datetime.now(timezone.utc).isoformat(),
        expected_harness="cursor",
    )
    assert resolved is True
    second = worker.review_http_payload(**kwargs)
    hook_output = second["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"
    assert second["policy_action"] == "allow"
    assert store.list_approval_requests(status="pending") == []


def test_native_review_allow_does_not_cross_workspace_or_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker, store = _worker(tmp_path, monkeypatch, _edge("cursor"))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://example.test"},
    }
    first = worker.review_http_payload(
        payload=payload,
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    request_id = first.get("approval_request_id")
    assert isinstance(request_id, str)
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="cursor accepted the native review",
        resolved_at=datetime.now(timezone.utc).isoformat(),
        expected_harness="cursor",
    )
    other_workspace = worker.review_http_payload(
        payload=payload,
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=None,
    )
    assert other_workspace["policy_action"] == "review"
    other_tool = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "tool_input": {"url": "https://example.test"},
        },
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert other_tool["policy_action"] == "review"


@pytest.mark.parametrize("mutation", ("replay", "expired", "future", "input", "legacy", "floor"))
def test_native_review_retry_is_bound_expiring_and_one_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    edge = _edge("cursor")
    worker, store = _worker(tmp_path, monkeypatch, edge)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env", "timeout": 1000},
    }
    kwargs = {
        "payload": payload,
        "params": {},
        "default_harness": "cursor",
        "home_dir": tmp_path / "home",
        "guard_home": tmp_path / "guard-home",
        "workspace": workspace,
    }
    first = worker.review_http_payload(**kwargs)
    request_id = first["approval_request_id"]
    assert isinstance(request_id, str)
    approved_at = datetime.now(timezone.utc)
    if mutation == "expired":
        approved_at -= timedelta(minutes=6)
    elif mutation == "future":
        approved_at += timedelta(minutes=1)
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="verified harness Accept",
        resolved_at=approved_at.isoformat(),
        expected_harness="cursor",
    )
    if mutation == "input":
        payload["tool_input"]["timeout"] = 2000
    elif mutation == "legacy":
        with store._connect() as connection:
            connection.execute(
                "update approval_requests set artifact_hash = ? where request_id = ?", (request_id, request_id)
            )
    elif mutation == "floor":
        edge["result"]["reason_code"] = "native_sensitive_access_review"
    elif mutation == "replay":
        second = worker.review_http_payload(**kwargs)
        assert second["policy_action"] == "allow"
    response = worker.review_http_payload(**kwargs)
    assert response["policy_action"] == "review"
    assert response.get("approval_reuse_status") != "accepted"


@pytest.mark.parametrize(
    "command",
    (
        "bash check.sh",
        "sh check.sh",
        "ash check.sh",
        "python3 check.py",
        "python3.12 check.py",
        "python3 -m reader",
        "node check.js",
        "./check",
        "bunx vitest run __tests__/guard-extension-public-promotions.test.ts --reporter=dot",
    ),
)
def test_mutable_code_launches_never_reuse_python_side_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    edge = _edge("cursor")
    worker, store = _worker(tmp_path, monkeypatch, edge)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    kwargs = {
        "payload": payload,
        "params": {},
        "default_harness": "cursor",
        "home_dir": tmp_path / "home",
        "guard_home": tmp_path / "guard-home",
        "workspace": workspace,
    }
    first = worker.review_http_payload(**kwargs)
    request_id = first["approval_request_id"]
    assert isinstance(request_id, str)
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="verified harness Accept",
        resolved_at=datetime.now(timezone.utc).isoformat(),
        expected_harness="cursor",
    )
    second = worker.review_http_payload(**kwargs)
    assert second["policy_action"] == "review"
    assert second.get("approval_reuse_status") != "accepted"


@pytest.mark.parametrize(
    "command",
    (
        "PATH=/tmp/tools cat .env",
        "LC_ALL=C cat .env",
        "cat .env\n./check",
        "cat .env\r\nbash check.sh",
    ),
)
def test_environment_and_command_lists_never_reuse_python_side_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    edge = _edge("cursor")
    worker, store = _worker(tmp_path, monkeypatch, edge)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}
    kwargs = {
        "payload": payload,
        "params": {},
        "default_harness": "cursor",
        "home_dir": tmp_path / "home",
        "guard_home": tmp_path / "guard-home",
        "workspace": workspace,
    }
    first = worker.review_http_payload(**kwargs)
    request_id = first["approval_request_id"]
    assert isinstance(request_id, str)
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="verified harness Accept",
        resolved_at=datetime.now(timezone.utc).isoformat(),
        expected_harness="cursor",
    )
    second = worker.review_http_payload(**kwargs)
    assert second["policy_action"] == "review"
    assert second.get("approval_reuse_status") != "accepted"


def test_native_review_retry_is_atomic_between_two_consumers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    edge = _edge("cursor")
    worker, store = _worker(tmp_path, monkeypatch, edge)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .env"}}
    response = worker.review_http_payload(
        payload=payload,
        params={},
        default_harness="cursor",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
    )
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    now = datetime.now(timezone.utc).isoformat()
    assert store.resolve_harness_native_approval_request(
        request_id,
        reason="verified harness Accept",
        resolved_at=now,
        expected_harness="cursor",
    )
    request = store.get_approval_request(request_id)
    assert request is not None
    barrier = Barrier(2)

    def consume() -> bool:
        barrier.wait(timeout=10)
        return store.consume_native_review_approval(
            harness="cursor",
            artifact_id=request["artifact_id"],
            artifact_name=request["artifact_name"],
            artifact_hash=request["artifact_hash"],
            launch_target=request["launch_target"],
            workspace=str(workspace),
            now=now,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: consume(), range(2)))
    assert sorted(results) == [False, True]
