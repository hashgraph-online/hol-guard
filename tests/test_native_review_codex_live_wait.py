"""A Codex hook that waits for approval is released when the user allows it."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.codex_live_decision import (
    complete_codex_live_decision,
    resolve_codex_live_allow_authority,
)
from codex_plugin_scanner.guard.codex_live_decision_revalidation import revalidate_codex_live_allow
from codex_plugin_scanner.guard.continuation_contract import ContinuationOffer
from codex_plugin_scanner.guard.continuation_payload import offer_hash
from codex_plugin_scanner.guard.continuation_runtime import _live_hook_recorded_offer
from codex_plugin_scanner.guard.continuation_snapshot import validated_continuation_snapshot
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.local_approval_continuation import apply_local_approval_continuation
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
    process_start_token,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_local_once_authority import (
    EXACT_CLOUD_AUTHORITY_KIND,
    persist_local_once_approval,
)
from tests.native_pretool_edge_fixtures import canonical_receipt_bytes
from tests.native_review_evidence_support import with_review_evidence
from tests.test_native_command_observations import _edge, _observations, _receipt

_HARNESS = "codex"


def _hook_payload(workspace: Path) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "codex-session",
        "tool_use_id": "tool-1",
        "tool_name": "Bash",
        "tool_input": {"command": "cat package.json"},
        "cwd": str(workspace),
    }


def _hook_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[HookWorker, GuardStore]:
    from codex_plugin_scanner.guard.config import update_guard_settings

    observations = _observations()
    result = _edge(observations)["result"]
    result.update(minimum_action="review", action={"action_type": "unknown"})
    receipt = _receipt(observations)
    receipt["harness"] = _HARNESS

    def review_raw_hook_native(*_args: object, **kwargs: object) -> dict[str, object]:
        bound_receipt = copy.deepcopy(receipt)
        bound_receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(bound_receipt)).hexdigest()
        edge = {
            "schema": "guard-hook-edge-result.v2",
            "authority": "rust",
            "harness": _HARNESS,
            "event_name": "PreToolUse",
            "payload_kind": "inline",
            "result": {
                "schema": "guard-pre-tool-result.v1",
                "version": 1,
                "authority": "rust",
                "reason": "HOL Guard requires review before this command can execute.",
                **copy.deepcopy(result),
            },
            "receipt": bound_receipt,
        }
        return with_review_evidence(edge, **kwargs)

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", review_raw_hook_native)
    store = GuardStore(tmp_path / "guard-home")
    update_guard_settings(store.guard_home, {"blocked_request_mode": "ask", "approval_wait_timeout_seconds": 300})
    store.upsert_runtime_state(
        session_id="native-review",
        daemon_host="127.0.0.1",
        daemon_port=4781,
        started_at="2026-09-05T00:00:00+00:00",
        last_heartbeat_at="2026-09-05T00:00:00+00:00",
    )
    return HookWorker(store=store), store


def _review(worker: HookWorker, tmp_path: Path, workspace: Path, wait: dict[str, object] | None) -> dict[str, object]:
    payload = _hook_payload(workspace)
    if wait is not None:
        payload.update(wait)
    return worker.review_http_payload(
        payload=payload,
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
    )


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name": "fixture"}\n', encoding="utf-8")
    return workspace


def _snapshot(row: dict[str, Any]) -> dict[str, object] | None:
    for key in ("continuation_snapshot", "continuation_snapshot_json"):
        snapshot = validated_continuation_snapshot(row.get(key))
        if snapshot is not None:
            return snapshot
    return None


def _live_wait(timeout_seconds: int = 120) -> dict[str, object]:
    identity = current_process_identity()
    assert identity is not None
    return {CODEX_BROWSER_WAIT_PROCESS_KEY: identity, CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: timeout_seconds}


def _allow_once(store: GuardStore, request_id: str, workspace: Path) -> None:
    row = store.get_approval_request(request_id)
    assert row is not None
    contract = request_scope_contract(row)
    assert contract is not None
    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="allow once",
        persist_policy=None,
        scope_contract_version=str(row["scope_contract_version"]),
        scope_contract_digest=str(row["scope_contract_digest"]),
    )


def _allow_from_cloud(store: GuardStore, request_id: str, workspace: Path) -> None:
    """Resolve the request the way an exact Cloud Review decision lands.

    The Cloud allow is stored as exact-cloud one-shot authority, apart from
    the local approvals an ordinary allow-once writes.
    """

    row = store.get_approval_request(request_id)
    assert row is not None
    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="allow once from Cloud Review",
        persist_policy=False,
        scope_contract_version=str(row["scope_contract_version"]),
        scope_contract_digest=str(row["scope_contract_digest"]),
    )
    resolved = store.get_approval_request(request_id)
    assert resolved is not None
    key, key_id = store._policy_integrity_secret_material(create=True)  # pyright: ignore[reportPrivateUsage]
    assert key is not None and key_id is not None
    created_at = str(resolved["resolved_at"])
    expires_at = (datetime.fromisoformat(created_at) + timedelta(hours=1)).isoformat()
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        approval_id = persist_local_once_approval(
            connection,
            request_id=request_id,
            harness=_HARNESS,
            artifact_id=str(resolved["artifact_id"]),
            artifact_hash=str(resolved["artifact_hash"]),
            workspace=str(resolved["workspace"]),
            publisher=None,
            action="allow",
            created_at=created_at,
            expires_at=expires_at,
            integrity_key=key,
            integrity_key_id=key_id,
            authority_kind=EXACT_CLOUD_AUTHORITY_KIND,
        )
    assert approval_id is not None


def _daemon_revalidates(worker: HookWorker, store: GuardStore, tmp_path: Path, request_id: str) -> bool:
    """Run the fresh policy check the daemon makes before releasing the hook."""

    request = store.get_approval_request(request_id)
    assert request is not None
    workspace = Path(str(request["workspace"]))
    authority = resolve_codex_live_allow_authority(
        store, request=request, request_id=request_id, now=str(request["resolved_at"])
    )
    return revalidate_codex_live_allow(
        request,
        {"hook_input": json.dumps(_hook_payload(workspace))},
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        previous=store.get_request_resume(request_id),
        request_id=request_id,
        authority_resolved=authority is not None,
        reviewer=lambda hook_payload, review_workspace, claimed_hash, claimed_request_id: worker.review_http_payload(
            payload=dict(hook_payload),
            params={},
            default_harness=_HARNESS,
            home_dir=tmp_path / "home",
            guard_home=store.guard_home,
            workspace=review_workspace,
            claim_saved_approval=False,
            claimed_saved_allow_hash=claimed_hash,
            claimed_approval_request_id=claimed_request_id,
        ),
    )


@pytest.mark.parametrize("allow", [_allow_once, _allow_from_cloud], ids=["local", "cloud-review"])
def test_an_allow_once_passes_the_daemon_revalidation_and_resumes_the_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, allow: Any
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)
    review = _review(worker, tmp_path, workspace, _live_wait())
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)

    allow(store, request_id, workspace)
    fresh_allow_authorized = _daemon_revalidates(worker, store, tmp_path, request_id)
    resolved = store.get_approval_request(request_id)
    assert resolved is not None
    completed = complete_codex_live_decision(
        store,
        request_id=request_id,
        now=str(resolved["resolved_at"]),
        fresh_allow_authorized=fresh_allow_authorized,
    )

    assert fresh_allow_authorized is True
    assert completed["completed"] is True, completed
    continuation = completed["continuation"]
    assert isinstance(continuation, dict)
    assert continuation["continuationStatus"] == "resumed"


def test_a_cloud_review_allow_does_not_release_a_different_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)
    review = _review(worker, tmp_path, workspace, _live_wait())
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    _allow_from_cloud(store, request_id, workspace)
    resolved = store.get_approval_request(request_id)
    assert resolved is not None

    replayed = worker.review_http_payload(
        payload=_hook_payload(workspace),
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=workspace,
        claim_saved_approval=False,
        claimed_saved_allow_hash=str(resolved["artifact_hash"]),
        claimed_approval_request_id="another-request",
    )

    output = replayed["hookSpecificOutput"]
    assert isinstance(output, dict)
    assert output["permissionDecision"] == "deny"


def test_allowing_a_waiting_codex_review_releases_the_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)

    review = _review(worker, tmp_path, workspace, _live_wait())
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    row = store.get_approval_request(request_id)
    assert row is not None
    snapshot = _snapshot(row)
    assert snapshot is not None
    assert snapshot["capability"] == "suspended-response"
    assert snapshot["hookAttached"] is True
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    assert operation["status"] == "waiting_on_approval"

    _allow_once(store, request_id, workspace)
    resolved = store.get_approval_request(request_id)
    assert resolved is not None
    completed = complete_codex_live_decision(
        store,
        request_id=request_id,
        now=str(resolved["resolved_at"]),
        fresh_allow_authorized=True,
    )

    assert completed["completed"] is True, completed
    assert completed["action"] == "allow"
    continuation = completed["continuation"]
    assert isinstance(continuation, dict)
    assert continuation["continuationStatus"] == "resumed"


def test_wait_budget_is_bounded_by_the_bridge_and_the_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)

    review = _review(worker, tmp_path, workspace, _live_wait(timeout_seconds=30))
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["codex_browser_wait_timeout_seconds"] == 30


@pytest.mark.parametrize(
    "wait",
    [
        None,
        {CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120},
        {CODEX_BROWSER_WAIT_PROCESS_KEY: {"pid": 1, "startToken": "posix:not-this-process"}},
        {
            CODEX_BROWSER_WAIT_PROCESS_KEY: {"pid": 1, "startToken": "posix:not-this-process"},
            CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
        },
    ],
    ids=["no-bridge", "no-process", "no-budget", "other-process"],
)
def test_a_review_without_a_live_waiting_bridge_stays_a_manual_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, wait: dict[str, object] | None
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)

    review = _review(worker, tmp_path, workspace, wait)
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    row = store.get_approval_request(request_id)
    assert row is not None
    snapshot = _snapshot(row)
    assert snapshot is not None
    assert snapshot["capability"] == "retry-only"
    assert store.get_guard_operation_for_approval_request(request_id) is None


def test_the_waiting_operation_exists_before_the_request_can_be_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval

    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)
    persist_review = hook_native_review_approval._persist_review
    linked_at_persist: list[bool] = []

    def persist(persist_fn: Any, request: Any, now: str, claude_review: Any) -> Any:
        linked_at_persist.append(store.get_guard_operation_for_approval_request(request.request_id) is not None)
        return persist_review(persist_fn, request, now, claude_review)

    monkeypatch.setattr(hook_native_review_approval, "_persist_review", persist)
    _review(worker, tmp_path, workspace, _live_wait())

    assert linked_at_persist == [True]


def test_a_wait_that_cannot_be_linked_is_queued_as_a_manual_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)

    def fail(**_kwargs: object) -> dict[str, object]:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "upsert_guard_operation", fail)
    review = _review(worker, tmp_path, workspace, _live_wait())
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    row = store.get_approval_request(request_id)
    assert row is not None
    snapshot = _snapshot(row)
    assert snapshot is not None
    assert snapshot["capability"] == "retry-only"


def test_a_block_the_waiting_hook_already_completed_is_not_recorded_again_after_it_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)
    bridge = subprocess.Popen(["sleep", "60"])
    try:
        start_token = process_start_token(bridge.pid)
        assert start_token is not None
        review = _review(
            worker,
            tmp_path,
            workspace,
            {
                CODEX_BROWSER_WAIT_PROCESS_KEY: {"pid": bridge.pid, "startToken": start_token},
                CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
            },
        )
        request_id = review["approval_request_id"]
        assert isinstance(request_id, str)
        row = store.get_approval_request(request_id)
        assert row is not None
        apply_approval_resolution(
            store=store,
            request_id=request_id,
            action="block",
            scope="artifact",
            workspace=str(workspace),
            reason="block",
            persist_policy=None,
            scope_contract_version=str(row["scope_contract_version"]),
            scope_contract_digest=str(row["scope_contract_digest"]),
        )
        resolved = store.get_approval_request(request_id)
        assert resolved is not None
        completed = complete_codex_live_decision(store, request_id=request_id, now=str(resolved["resolved_at"]))
        assert completed["completed"] is True, completed
    finally:
        bridge.kill()
        bridge.wait()
    recorded = store.get_request_resume(request_id)
    assert recorded is not None
    assert recorded["continuation_capability"] == "suspended-response"
    assert recorded["continuation_status"] == "blocked_not_resumed"

    # The daemon's decision handler continues the request after the bridge has
    # already consumed the block and exited, so it sees no live hook.
    later = (datetime.fromisoformat(str(resolved["resolved_at"])) + timedelta(seconds=1)).isoformat()
    updated, _ = apply_local_approval_continuation(
        store=store,
        updated={},
        request_id=request_id,
        action="block",
        harness="codex",
        copy={"title": "Decision saved.", "body": "Return to Codex."},
        now=lambda: later,
    )

    after = store.get_request_resume(request_id)
    assert after is not None
    assert after["continuation_capability"] == "suspended-response"
    assert after["continuation_offer_hash"] == recorded["continuation_offer_hash"]
    assert after["continuation_evidence"] == recorded["continuation_evidence"]
    codex_resume = updated.get("codexResume")
    assert isinstance(codex_resume, dict)
    assert codex_resume.get("capability") == "suspended-response"
    with sqlite3.connect(store.path) as connection:
        terminals = connection.execute(
            "select count(*) from guard_events where event_name = 'review.continuation.terminal'"
        ).fetchone()[0]
    assert terminals == 1


_FROZEN_CORRELATION = "gcr_00000000-0000-4000-8000-000000000001"


def _frozen_block(wait_deadline: str) -> tuple[dict[str, object], dict[str, object], ContinuationOffer]:
    retry_only = ContinuationOffer(
        correlation_id=_FROZEN_CORRELATION,
        harness="codex",
        capability="retry-only",
        original_hook_attached=False,
    )
    snapshot = {
        "capability": "suspended-response",
        "correlationId": _FROZEN_CORRELATION,
        "hookAttached": True,
        "opaqueTargetId": None,
        "waitDeadline": wait_deadline,
    }
    resume: dict[str, object] = {
        "continuation_capability": "suspended-response",
        "continuation_action": "block",
        "continuation_status": "blocked_not_resumed",
    }
    return {"continuation_snapshot": snapshot}, resume, retry_only


def test_a_frozen_deadline_keeps_its_offset_when_the_block_is_replayed(native_context_digest: Path) -> None:
    deadline = "2026-10-29T03:15:00+02:00"
    request_row, resume, retry_only = _frozen_block(deadline)
    recorded = ContinuationOffer(
        correlation_id=_FROZEN_CORRELATION,
        harness="codex",
        capability="suspended-response",
        original_hook_attached=True,
        wait_deadline=datetime.fromisoformat(deadline),
    )
    resume["continuation_offer_hash"] = offer_hash(recorded)

    replay = _live_hook_recorded_offer(request_row, resume, offer=retry_only, action="block")

    assert replay is not None
    frozen, frozen_hash = replay
    assert frozen.capability == "suspended-response"
    assert frozen_hash == resume["continuation_offer_hash"]


@pytest.mark.parametrize("deadline", ["not-a-time", "2026-10-29T03:15:00"])
def test_a_frozen_deadline_that_cannot_be_read_declines_the_replay(native_context_digest: Path, deadline: str) -> None:
    request_row, resume, retry_only = _frozen_block(deadline)
    resume["continuation_offer_hash"] = "sha256:" + "0" * 64

    assert _live_hook_recorded_offer(request_row, resume, offer=retry_only, action="block") is None


def test_a_retry_folded_into_the_pending_row_releases_the_retrying_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)
    earlier_bridge = subprocess.Popen(["sleep", "60"])
    try:
        start_token = process_start_token(earlier_bridge.pid)
        assert start_token is not None
        first = _review(
            worker,
            tmp_path,
            workspace,
            {
                CODEX_BROWSER_WAIT_PROCESS_KEY: {"pid": earlier_bridge.pid, "startToken": start_token},
                CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
            },
        )
    finally:
        earlier_bridge.kill()
        earlier_bridge.wait()

    retry = _review(worker, tmp_path, workspace, _live_wait())
    request_id = retry["approval_request_id"]
    assert request_id == first["approval_request_id"]
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["codex_browser_wait_process"] == current_process_identity()

    _allow_once(store, request_id, workspace)
    resolved = store.get_approval_request(request_id)
    assert resolved is not None
    completed = complete_codex_live_decision(
        store,
        request_id=request_id,
        now=str(resolved["resolved_at"]),
        fresh_allow_authorized=True,
    )

    assert completed["completed"] is True, completed
    continuation = completed["continuation"]
    assert isinstance(continuation, dict)
    assert continuation["continuationStatus"] == "resumed"
