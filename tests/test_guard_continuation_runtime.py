"""Durable continuation execution across proven and fallback harness capabilities."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.continuation_contract import ContinuationOffer, ContinuationResult
from codex_plugin_scanner.guard.continuation_runtime import (
    continue_request_after_application,
    record_live_hook_completion,
)
from codex_plugin_scanner.guard.continuation_worker import StoreContinuationPlan
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-08-24T12:00:00+00:00"


def _successful_isolated_plan(
    _plan: object,
    offer: ContinuationOffer,
    _action: str,
    _timeout_seconds: float,
) -> ContinuationResult:
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status="resumed",
        reason="app_server_turn_started",
        completed_at=datetime.fromisoformat(NOW),
        evidence_id="evidence-app-server-0001",
    )


def _blocking_waiting_isolated_plan(
    plan: StoreContinuationPlan,
    offer: ContinuationOffer,
    _action: str,
    _timeout_seconds: float,
) -> ContinuationResult:
    guard_home = Path(plan.guard_home)
    (guard_home / "continuation-child-started").write_text("started", encoding="utf-8")
    release = guard_home / "continuation-child-release"
    deadline = time.monotonic() + 5.0
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status="waiting",
        reason="original_hook_waiting",
        completed_at=datetime.fromisoformat(NOW),
        evidence_id="evidence-stale-waiting-owner",
    )


def _seed_request(
    store: GuardStore, *, harness: str, request_id: str, metadata: dict[str, object]
) -> dict[str, object]:
    request = GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=f"{harness}:project:read-source",
        artifact_name="Read source",
        artifact_hash=f"hash-{request_id}",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_response",),
        source_scope="project",
        config_path=f"/workspace/{harness}.json",
        workspace="/workspace/guard-continuation-runtime",
        launch_target="Read source",
        action_envelope_json={"action_type": "file_read", "tool_name": "Read", "target_paths": ["src/file.py"]},
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
    )
    store.add_approval_request(request, NOW)
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness=harness,
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name=f"{harness}-hook",
        client_title=f"{harness} hook",
        client_version="1.0.0",
        workspace="/workspace/guard-continuation-runtime",
        capabilities=["approval-resolution"],
        now=NOW,
    )
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness=harness,
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token="resume-token-not-in-response",
        metadata=metadata,
        now=NOW,
    )
    result = store.get_approval_request(request_id)
    assert result is not None
    return result


@pytest.mark.parametrize("harness", ["pi", "omp", "grok", "openclaw", "hermes"])
def test_retry_only_harnesses_persist_a_manual_retry_once(tmp_path: Path, harness: str) -> None:
    store = GuardStore(tmp_path / harness)
    request = _seed_request(store, harness=harness, request_id=f"request-{harness}", metadata={"session_id": "opaque"})

    first = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)
    second = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)

    assert first["continuationStatus"] == "manual_retry_required"
    assert first["localManualRetryNotification"] is True
    assert "harness_resume" not in first
    assert "resume-token-not-in-response" not in str(first)
    assert second["continuationEvidenceId"] == first["continuationEvidenceId"]
    assert "localManualRetryNotification" not in second
    resume = store.get_request_resume(f"request-{harness}")
    assert resume is not None
    assert resume["continuation_contract_version"] == "guard.harness-continuation.v2"
    assert resume["continuation_offer_hash"]
    evidence = resume["continuation_evidence"]
    assert isinstance(evidence, list)
    assert isinstance(evidence[0], Mapping)
    assert evidence[0]["evidenceId"] == first["continuationEvidenceId"]
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1
    assert len(store.list_events(event_name="review.continuation.manual_retry_required")) == 1


def test_live_codex_hook_reports_waiting_without_starting_a_second_resume(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "codex-live")
    request = _seed_request(
        store,
        harness="codex",
        request_id="request-codex-live",
        metadata={
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2026-08-24T12:01:00+00:00",
            "hook_event_name": "PreToolUse",
        },
    )

    payload = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)

    assert payload["continuationStatus"] == "waiting"
    assert "resumeStatus" not in payload
    assert "resumeReason" not in payload
    codex_resume = payload["codexResume"]
    assert isinstance(codex_resume, Mapping)
    assert codex_resume["strategy"] == "codex-live-hook"
    persisted = store.get_request_resume("request-codex-live")
    assert persisted is not None
    assert persisted["status"] == "pending"
    replay = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)
    assert replay["continuationEvidenceId"] == payload["continuationEvidenceId"]
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1

    completed = record_live_hook_completion(
        store,
        request_id="request-codex-live",
        action="allow",
        now="2026-08-24T12:00:01+00:00",
    )
    assert completed is not None
    assert completed["continuationStatus"] == "resumed"
    assert len(store.list_events(event_name="review.continuation.terminal")) == 1


def test_live_hook_completion_wins_over_inflight_waiting_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "live-completion-race"
    store = GuardStore(guard_home)
    request = _seed_request(
        store,
        harness="codex",
        request_id="request-live-completion-race",
        metadata={
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2026-08-24T12:01:00+00:00",
            "hook_event_name": "PreToolUse",
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.continuation_runtime._run_store_continuation_plan",
        _blocking_waiting_isolated_plan,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            continue_request_after_application,
            store,
            request_row=request,
            action="allow_once",
            now=NOW,
            timeout_seconds=4.0,
        )
        started = guard_home / "continuation-child-started"
        deadline = time.monotonic() + 3.0
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started.exists(), "spawned continuation did not reach the deterministic interleaving"
        completed = record_live_hook_completion(
            store,
            request_id="request-live-completion-race",
            action="allow",
            now="2026-08-24T12:00:01+00:00",
        )
        (guard_home / "continuation-child-release").write_text("release", encoding="utf-8")
        returned = future.result(timeout=5.0)

    assert completed is not None
    assert returned["continuationStatus"] == "resumed"
    assert returned["continuationEvidenceId"] == completed["continuationEvidenceId"]
    resume = store.get_request_resume("request-live-completion-race")
    assert resume is not None
    assert resume["continuation_status"] == "resumed"
    assert resume["status"] == "sent"
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1
    assert len(store.list_events(event_name="review.continuation.terminal")) == 1


def test_codex_app_server_result_is_bounded_and_opaque(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "codex-app-server")
    request = _seed_request(
        store,
        harness="codex",
        request_id="request-codex-session",
        metadata={"codex_thread_id": "thread-safe-0001"},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.continuation_runtime._run_store_continuation_plan",
        _successful_isolated_plan,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.continuation_runtime.codex_app_server_target_reachable",
        lambda _metadata: True,
    )

    payload = continue_request_after_application(
        store,
        request_row=request,
        action="allow_once",
        now=NOW,
        timeout_seconds=2.0,
        headless=False,
    )

    assert payload["continuationStatus"] == "resumed", payload
    assert "resumeStatus" not in payload
    codex_resume = payload["codexResume"]
    assert isinstance(codex_resume, Mapping)
    assert codex_resume["strategy"] == "codex-app-server-thread"
    assert "thread-safe-0001" not in str(payload)


def test_cancelled_continuation_persists_failure_before_returning(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "cancelled")
    request = _seed_request(store, harness="pi", request_id="request-cancelled", metadata={})

    payload = continue_request_after_application(
        store,
        request_row=request,
        action="allow_once",
        now=NOW,
        cancelled=lambda: True,
    )

    assert payload["continuationStatus"] == "failed"
    assert payload["continuationReason"] == "continuation_cancelled"
    resume = store.get_request_resume("request-cancelled")
    assert resume is not None
    assert resume["continuation_cancelled_at"] == NOW
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1


def test_continuation_derives_valid_correlation_instead_of_using_raw_job_id(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "derived-correlation")
    request_id = "command-job-raw-123"
    request = _seed_request(store, harness="pi", request_id=request_id, metadata={})

    first = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)
    replay = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)

    correlation_id = str(first["correlationId"])
    assert correlation_id.startswith("gcr_")
    assert len(correlation_id) == len("gcr_00000000-0000-0000-0000-000000000000")
    assert correlation_id != request_id
    assert replay["correlationId"] == correlation_id


def test_cross_worker_race_executes_one_durable_continuation(tmp_path: Path) -> None:
    guard_home = tmp_path / "race"
    seed_store = GuardStore(guard_home)
    _ = _seed_request(seed_store, harness="pi", request_id="request-race", metadata={})

    def continue_from_worker() -> dict[str, object]:
        worker_store = GuardStore(guard_home)
        request = worker_store.get_approval_request("request-race")
        assert request is not None
        return continue_request_after_application(worker_store, request_row=request, action="allow_once", now=NOW)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: continue_from_worker(), range(2)))

    evidence_ids = {str(result["continuationEvidenceId"]) for result in results}
    assert len(evidence_ids) == 1
    assert len(seed_store.list_events(event_name="review.continuation.attempt")) == 1
    assert len(seed_store.list_events(event_name="review.continuation.terminal")) == 1


def test_stale_continuation_claim_recovery_is_lease_bounded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "stale-claim")
    first = store.claim_continuation_attempt(
        request_id="request-stale",
        offer_hash="offer-stale",
        action="allow_once",
        now="2026-08-24T12:00:00+00:00",
        lease_seconds=30,
    )
    active = store.claim_continuation_attempt(
        request_id="request-stale",
        offer_hash="offer-stale",
        action="allow_once",
        now="2026-08-24T12:00:10+00:00",
        lease_seconds=30,
    )
    recovered = store.claim_continuation_attempt(
        request_id="request-stale",
        offer_hash="offer-stale",
        action="allow_once",
        now="2026-08-24T12:00:31+00:00",
        lease_seconds=30,
    )

    assert first is not None
    assert active is None
    assert recovered is not None
    assert recovered != first


def test_stale_claimant_cannot_commit_after_lease_recovery(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "claim-owner")
    first = store.claim_continuation_attempt(
        request_id="request-owner",
        offer_hash="offer-owner",
        action="allow_once",
        now="2026-08-24T12:00:00+00:00",
        lease_seconds=1,
    )
    recovered = store.claim_continuation_attempt(
        request_id="request-owner",
        offer_hash="offer-owner",
        action="allow_once",
        now="2026-08-24T12:00:02+00:00",
        lease_seconds=30,
    )
    assert first is not None
    assert recovered is not None

    with pytest.raises(RuntimeError, match="claim ownership changed"):
        store.finalize_continuation_attempt(
            request_id="request-owner",
            offer_hash="offer-owner",
            action="allow_once",
            claim_id=first,
            evidence_id="evidence-stale-owner-0001",
            terminal=True,
            resume_seed={
                "operation_id": None,
                "harness": "pi",
                "strategy": "manual-only",
                "supported": False,
                "thread_id": None,
            },
            resume_update={"status": "skipped", "attempt_count": 1},
            operation_update=None,
            events=[],
            now="2026-08-24T12:00:02+00:00",
        )

    assert store.get_request_resume("request-owner") is None
    assert store.list_events(event_name="review.continuation.attempt") == []


def test_replay_repairs_crash_window_side_effects_idempotently(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "repair")
    request = _seed_request(store, harness="pi", request_id="request-repair", metadata={})
    first = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)
    evidence_id = str(first["continuationEvidenceId"])
    with sqlite3.connect(store.path) as connection:
        connection.execute("delete from guard_continuation_effects where evidence_id = ?", (evidence_id,))
        connection.execute("delete from guard_events where payload_json like ?", (f'%"{evidence_id}"%',))

    replay = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)
    second_replay = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)

    assert replay["continuationEvidenceId"] == evidence_id
    assert second_replay["continuationEvidenceId"] == evidence_id
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1
    assert len(store.list_events(event_name="review.continuation.terminal")) == 1
    assert len(store.list_events(event_name="review.continuation.manual_retry_required")) == 1
