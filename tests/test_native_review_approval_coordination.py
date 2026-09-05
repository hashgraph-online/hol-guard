"""Native PreToolUse review queues a resolvable approval-center request."""

from __future__ import annotations

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


def _worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edge: dict[str, object]) -> tuple[HookWorker, GuardStore]:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: edge,
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
        payload={"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": "https://example.test"}},
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
    pending = store.list_approval_requests(status="pending")
    assert len(pending) == 1
    assert pending[0]["policy_action"] == "review"


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
