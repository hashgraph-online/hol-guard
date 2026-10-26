"""Adversarial tests for how stored hook retry lineage is kept and kept private.

The capture grammar is native (``retry_lineage_capture_op``); these records are
built the way the resident builds them so the store tests need no resident.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier

import pytest

from codex_plugin_scanner.guard.continuation_contract import ContinuationOffer, ContinuationResult
from codex_plugin_scanner.guard.continuation_payload import continuation_payload
from codex_plugin_scanner.guard.continuation_runtime import continuation_offer_payload
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.local_request_snapshots import local_request_snapshot_payload
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_continuation import continuation_store_call

_NOW = "2026-09-29T12:00:00+00:00"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _lineage(tool_call_id: str = "provider-tool-call-001", **extra: str) -> dict[str, object]:
    """A valid record, as the resident captures one for a provider hook payload."""

    record: dict[str, object] = {
        "version": 1,
        "source": "hook",
        "harness": "pi",
        "session_id": "provider-session-001",
        "tool_call_id": tool_call_id,
        "turn_id": "provider-turn-001",
        "invocation_id": "provider-invocation-001",
        "provider_request_id": "provider-request-001",
        "workspace_sha256": _sha256("/workspace/example"),
        "device_sha256": _sha256("device-001"),
        **extra,
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    record["lineage_id"] = _sha256(canonical)
    return record


def test_operation_update_cannot_replace_first_retry_lineage(tmp_path: Path) -> None:
    initial = _lineage()
    changed = _lineage("attacker-substituted-call")
    assert initial["lineage_id"] != changed["lineage_id"]

    store = GuardStore(tmp_path / "guard")
    _ = store.upsert_guard_session(
        session_id="guard-session",
        harness="pi",
        surface="harness-adapter",
        status="active",
        client_name="pi-hook",
        client_title=None,
        client_version="test",
        workspace="/workspace/example",
        capabilities=["approval-resolution"],
        now=_NOW,
    )
    _ = store.upsert_guard_operation(
        operation_id="guard-operation",
        session_id="guard-session",
        harness="pi",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=["request-001"],
        resume_token=None,
        metadata={"retry_lineage": initial, "hook_event_name": "PreToolUse"},
        now=_NOW,
    )
    _ = store.upsert_guard_operation(
        operation_id="guard-operation",
        session_id="guard-session",
        harness="pi",
        operation_type="tool_call",
        status="manual_retry_required",
        approval_request_ids=["request-001"],
        resume_token=None,
        metadata={"retry_lineage": changed, "continuation": {"status": "manual_retry_required"}},
        now=_NOW,
    )

    saved = store.get_guard_operation("guard-operation")
    assert saved is not None
    metadata = saved["metadata"]
    assert isinstance(metadata, Mapping)
    assert metadata["retry_lineage"] == initial
    assert metadata["continuation"] == {"status": "manual_retry_required"}


def test_continuation_store_update_cannot_replace_first_retry_lineage(tmp_path: Path) -> None:
    initial = _lineage()
    changed = _lineage("continuation-substituted-call")

    store = GuardStore(tmp_path / "continuation-store")
    _ = store.upsert_guard_operation(
        operation_id="continuation-operation",
        session_id="guard-session",
        harness="pi",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=["request-continuation"],
        resume_token=None,
        metadata={"retry_lineage": initial},
        now=_NOW,
    )
    _ = store.seed_request_resume(
        request_id="request-continuation",
        operation_id="continuation-operation",
        harness="pi",
        strategy="manual-only",
        supported=False,
        thread_id=None,
        now=_NOW,
    )
    claim = store.claim_continuation_attempt(
        request_id="request-continuation",
        offer_hash="continuation-offer",
        action="allow_once",
        now=_NOW,
        lease_seconds=30,
    )
    assert claim is not None
    finalized = continuation_store_call(
        store,
        "store_finalize",
        request_id="request-continuation",
        offer_hash="continuation-offer",
        action="allow_once",
        claim_id=claim,
        evidence_id="continuation-evidence",
        terminal=False,
        resume_seed={
            "operation_id": "continuation-operation",
            "harness": "pi",
            "strategy": "manual-only",
            "supported": False,
            "thread_id": None,
        },
        resume_update={
            "resolution_action": "allow",
            "strategy": "manual-only",
            "supported": False,
            "status": "pending",
            "reason": "waiting",
            "message": None,
            "last_error": None,
            "attempt_count": 1,
            "last_attempt_at": _NOW,
            "sent_at": None,
        },
        operation_update={
            "operation_id": "continuation-operation",
            "status": "waiting_on_approval",
            "metadata": {
                "retry_lineage": changed,
                "continuation": {"status": "waiting"},
                "legacy_score": float("nan"),
            },
        },
        events=[],
        now=_NOW,
    )

    assert finalized["finalized"] is True
    saved = store.get_guard_operation("continuation-operation")
    assert saved is not None
    metadata = saved["metadata"]
    assert isinstance(metadata, Mapping)
    assert metadata["retry_lineage"] == initial
    assert metadata["continuation"] == {"status": "waiting"}
    score = metadata["legacy_score"]
    assert isinstance(score, float) and math.isnan(score)


def test_public_continuation_snapshot_contains_no_raw_retry_lineage(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    request = {
        "request_id": "request-001",
        "harness": "pi",
        "continuation_snapshot": None,
    }
    lineage = _lineage()
    operation = {
        "metadata": {"retry_lineage": lineage},
        "session_id": "guard-session",
        "harness": "pi",
    }

    snapshot = continuation_offer_payload(
        store,
        request_row=request,
        now=_NOW,
        headless=True,
        operation=operation,
    )

    encoded = json.dumps(snapshot, sort_keys=True)
    assert "provider-session-001" not in encoded
    assert "provider-tool-call-001" not in encoded
    assert "provider-turn-001" not in encoded
    assert set(snapshot) == {"correlationId", "capability", "hookAttached", "opaqueTargetId", "waitDeadline"}


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_public_and_cloud_serialization_omit_retry_lineage(tmp_path: Path) -> None:
    lineage = _lineage()
    offer = ContinuationOffer(
        correlation_id="gcr_00000000-0000-0000-0000-000000000001",
        harness="pi",
        capability="retry-only",
        original_hook_attached=False,
    )
    result = ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status="manual_retry_required",
        reason="manual_retry_required",
        completed_at=datetime.fromisoformat(_NOW),
        evidence_id="evidence-001",
    )
    public = continuation_payload(offer, result, replayed=False)
    store = GuardStore(tmp_path / "cloud")
    request = GuardApprovalRequest(
        request_id="request-001",
        harness="pi",
        artifact_id="pi:project:tool",
        artifact_name="Test tool",
        artifact_hash="hash-001",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/workspace/example",
        review_command="hol-guard approvals approve request-001",
        approval_url="http://127.0.0.1:5474/requests/request-001",
        action_envelope_json={"action_type": "shell_command", "retry_lineage": lineage},
    )
    _ = store.add_approval_request(request, _NOW)
    cloud = local_request_snapshot_payload(store)

    assert "retry_lineage" not in json.dumps(public)
    assert "retry_lineage" not in json.dumps(cloud)
    assert "provider-session-001" not in json.dumps(cloud)


def test_concurrent_first_writers_retain_a_valid_lineage(tmp_path: Path) -> None:
    left = _lineage(original_request_id="request-left")
    right = _lineage("provider-tool-call-right", original_request_id="request-right")
    barrier = Barrier(2)

    def write(store: GuardStore, lineage: dict[str, object]) -> None:
        _ = barrier.wait(timeout=5)
        _ = store.upsert_guard_operation(
            operation_id="concurrent-operation",
            session_id="guard-session",
            harness="pi",
            operation_type="tool_call",
            status="waiting_on_approval",
            approval_request_ids=[],
            resume_token=None,
            metadata={"retry_lineage": lineage},
            now=_NOW,
        )

    stores = (GuardStore(tmp_path / "guard"), GuardStore(tmp_path / "guard"))
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write, stores[index], lineage) for index, lineage in enumerate((left, right))]
        for future in futures:
            future.result()

    saved = stores[0].get_guard_operation("concurrent-operation")
    assert saved is not None
    metadata = saved["metadata"]
    assert isinstance(metadata, Mapping)
    retained = metadata["retry_lineage"]
    assert retained in (left, right)
