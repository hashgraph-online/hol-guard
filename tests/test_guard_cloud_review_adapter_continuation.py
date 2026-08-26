from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.continuation_runtime import (
    continuation_offer_payload,
    continue_request_after_application,
    record_live_hook_completion,
)
from codex_plugin_scanner.guard.live_process_identity import current_process_identity
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-08-24T12:00:00+00:00"


def _seed_adapter_request(store: GuardStore, harness: str) -> dict[str, object]:
    request_id = f"adapter-{harness}"
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness=harness,
            artifact_id=f"{harness}:project:automatic-continuation",
            artifact_name="Adapter continuation",
            artifact_hash=f"hash-{harness}",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("tool_action_request",),
            source_scope="project",
            config_path=f"/workspace/{harness}.json",
            workspace="/workspace/cloud-review",
            action_envelope_json={"action_type": "file_read", "target_paths": ["src/file.py"]},
            review_command=f"hol-guard approvals approve {request_id}",
            approval_url=f"http://127.0.0.1/requests/{request_id}",
        ),
        _NOW,
    )
    identity = current_process_identity()
    assert identity is not None
    metadata: dict[str, object] = {}
    if harness == "codex":
        metadata = {
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2026-08-24T12:01:00+00:00",
            "codex_browser_wait_process": identity,
            "hook_event_name": "PreToolUse",
        }
    session = store.upsert_guard_session(
        session_id=f"session-{harness}",
        harness=harness,
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name=f"{harness}-hook",
        client_title=f"{harness} hook",
        client_version="1.0.0",
        workspace="/workspace/cloud-review",
        capabilities=["approval-resolution"],
        now=_NOW,
    )
    store.upsert_guard_operation(
        operation_id=f"operation-{harness}",
        session_id=str(session["session_id"]),
        harness=harness,
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token=None,
        metadata=metadata,
        now=_NOW,
    )
    request = store.get_approval_request(request_id)
    assert request is not None
    return request


@pytest.mark.parametrize("harness", [contract.harness for contract in HARNESS_CONTRACTS])
def test_every_adapter_proves_or_refuses_automatic_continuation(tmp_path: Path, harness: str) -> None:
    store = GuardStore(tmp_path / harness)
    request = _seed_adapter_request(store, harness)

    offer = continuation_offer_payload(store, request_row=request, now=_NOW, headless=False)

    if offer["capability"] != "suspended-response":
        assert offer["hookAttached"] is False
        return
    assert harness == "codex"
    waiting = continue_request_after_application(store, request_row=request, action="allow_once", now=_NOW)
    assert waiting["continuationStatus"] == "waiting"
    completed = record_live_hook_completion(
        store,
        request_id=str(request["request_id"]),
        action="allow",
        now="2026-08-24T12:00:01+00:00",
    )
    assert isinstance(completed, Mapping)
    assert completed["continuationStatus"] == "resumed"
    assert completed["continuationReason"] == "live_hook_completed"
