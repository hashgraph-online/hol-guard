"""Native review queueing reuses the pause path's resident review binding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.test_native_review_exact_action_always import (
    _HARNESS,
    _hook_worker,
    _native_package_intent,  # noqa: F401  (autouse fixture)
    _verdict,
    _wrangler_workspace,
)


def test_native_review_asks_the_resident_for_the_review_binding_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """Queueing a review reuses the pause path's binding instead of a second resident round trip."""
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval

    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    worker, _store = _hook_worker(tmp_path, monkeypatch, result, receipt)
    bindings: list[str | None] = []
    real_evidence = hook_native_review_approval.review_evidence_parts

    def counting_evidence(review_evidence: Any) -> tuple[bool, str | None, str | None, str | None] | None:
        evidence = real_evidence(review_evidence)
        bindings.append(None if evidence is None else evidence[1])
        return evidence

    monkeypatch.setattr(hook_native_review_approval, "review_evidence_parts", counting_evidence)
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "session_id": "binding-once",
            "tool_use_id": "tool-binding-once",
            "tool_name": "Bash",
            "tool_input": {"command": "npx wrangler --version"},
            "cwd": str(workspace),
        },
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
    )
    assert response["policy_action"] == "review"
    assert len(bindings) == 1


def test_native_review_queues_and_reads_its_row_in_one_resident_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """The queue write answers the stored row; the hook reads nothing back separately."""
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    worker, store = _hook_worker(tmp_path, monkeypatch, result, receipt)
    native_store_call = store._native_store_call
    calls: list[tuple[str, object]] = []

    def record(method: str, args: dict[str, object]) -> object:
        calls.append((method, args.get("return_row")))
        return native_store_call(method, args)

    monkeypatch.setattr(store, "_native_store_call", record)
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "session_id": "row-once",
            "tool_use_id": "tool-row-once",
            "tool_name": "Bash",
            "tool_input": {"command": "npx wrangler --version"},
            "cwd": str(workspace),
        },
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
    )
    assert response["policy_action"] == "review"
    queued = [method for method, return_row in calls if return_row is True]
    assert len(queued) == 1
    assert queued[0] == "queue_native_review"
    assert "get_approval_request" not in [method for method, _ in calls]
    stored = store.get_approval_request(str(response["approval_request_id"]))
    assert stored is not None
    assert stored["request_id"] == response["approval_request_id"]
