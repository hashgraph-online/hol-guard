"""A native approval may be spent by only one concurrent consumer."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_binding import (
    NATIVE_REVIEW_BINDING_FIELD,
    native_review_policy_binding,
)
from tests.test_native_review_approval_coordination import _edge, _worker

from .native_review_approval_support import _bound_review_evidence


def test_native_review_retry_is_atomic_between_two_consumers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    edge = _edge("cursor")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .env"}}
    result = edge["result"]
    assert isinstance(result, dict)
    bound_result, receipt = _bound_review_evidence(
        harness="cursor", payload=payload, workspace=workspace, native_result=result
    )
    edge["result"] = bound_result
    edge["receipt"] = receipt
    current_binding = native_review_policy_binding(
        harness="cursor", native_result=bound_result, verified_receipt=receipt
    )
    worker, store = _worker(tmp_path, monkeypatch, edge)
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
    policy_binding = request["action_envelope_json"][NATIVE_REVIEW_BINDING_FIELD]
    assert isinstance(policy_binding, Mapping)
    assert policy_binding == current_binding
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
            policy_binding=current_binding,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: consume(), range(2)))
    assert sorted(results) == [False, True]
