"""HGP-180: real adapter continuation capabilities after signed approval."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import list_adapters
from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.continuation_runtime import (
    continuation_offer_payload,
    continue_request_after_application,
)
from codex_plugin_scanner.guard.live_process_identity import current_process_identity
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-17T12:00:00+00:00"


def _seed(store: GuardStore, harness: str) -> dict[str, object]:
    request_id = f"real-{harness}"
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness=harness,
            artifact_id=f"{harness}:project:paused",
            artifact_name="Paused action",
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
    metadata: dict[str, object] = {}
    if harness == "codex" and identity is not None:
        metadata = {
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2026-09-17T12:01:00+00:00",
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


_HARNESSES = tuple(
    adapter.harness
    for adapter in list_adapters()
    if adapter.harness in {contract.harness for contract in HARNESS_CONTRACTS}
)


@pytest.mark.parametrize("harness", _HARNESSES)
def test_shipped_adapter_families_report_observed_continuation(tmp_path: Path, harness: str) -> None:
    adapter = next(item for item in list_adapters() if item.harness == harness)
    assert adapter.harness == harness
    store = GuardStore(tmp_path / harness)
    request = _seed(store, harness)
    offer = continuation_offer_payload(store, request_row=request, now=_NOW, headless=False)
    capability = offer["capability"]
    assert capability in {"suspended-response", "session-resume", "retry-only", "unsupported"}
    blocked = continue_request_after_application(store, request_row=request, action="block", now=_NOW)
    assert isinstance(blocked, Mapping)
    assert blocked["continuationStatus"] in {"blocked_not_resumed", "not_applicable"}
    allowed = continue_request_after_application(store, request_row=request, action="allow_once", now=_NOW)
    assert isinstance(allowed, Mapping)
    status = allowed["continuationStatus"]
    if capability == "retry-only":
        assert status in {"manual_retry_required", "waiting", "resumed", "already_resumed"}
        assert allowed.get("continuationReason")
    elif capability == "unsupported":
        assert status != "resumed"
    elif status in {"resumed", "already_resumed"}:
        assert capability in {"suspended-response", "session-resume"}
