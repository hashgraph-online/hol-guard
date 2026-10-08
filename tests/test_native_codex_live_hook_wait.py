"""A waiting Codex hook stays attached when native review queues the pause."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.continuation_runtime import (
    continue_request_after_application,
    record_live_hook_completion,
)
from codex_plugin_scanner.guard.daemon.hook_native_review_approval import pause_native_pre_tool_for_approval
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
)
from codex_plugin_scanner.guard.review_correlation import cloud_review_correlation_id
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_command_observations import _edge, _observations, _receipt, _rehash
from tests.test_native_review_policy_binding import _resign_identity


@pytest.fixture(autouse=True)
def questionnaire_mode(tmp_path: Path) -> None:
    update_guard_settings(tmp_path / "guard-home", {"blocked_request_mode": "ask"})


def _codex_review() -> tuple[dict[str, Any], dict[str, Any]]:
    observations = _observations()
    observations["observations"] = []
    observations["binding"]["observation_count"] = 0
    _rehash(observations)
    result = _edge(observations)["result"]
    result.update(
        schema="guard-pre-tool-result.v1",
        version=1,
        authority="rust",
        minimum_action="review",
        action={"action_type": "command"},
        reason="This file read requires approval.",
    )
    receipt = _receipt(observations)
    receipt["harness"] = "codex"
    _resign_identity(receipt)
    return result, receipt


def _pause(
    store: GuardStore,
    root: Path,
    *,
    harness: str,
    payload: dict[str, object],
) -> dict[str, Any]:
    result, receipt = _codex_review()
    if harness != "codex":
        receipt = copy.deepcopy(receipt)
        receipt["harness"] = harness
        _resign_identity(receipt)
    return pause_native_pre_tool_for_approval(
        store,
        harness=harness,
        payload=payload,
        native_result=result,
        native_receipt=receipt,
        workspace=root,
        guard_home=root / "guard-home",
        home_dir=root / "home",
    )


def _live_payload() -> dict[str, object]:
    identity = current_process_identity()
    assert identity is not None
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "release-gate-project/authorization-recovery/.npmrc"},
        CODEX_BROWSER_WAIT_PROCESS_KEY: identity,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 60,
    }


def test_live_codex_pause_waits_for_the_original_hook_then_resumes_once(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    response = _pause(store, tmp_path, harness="codex", payload=_live_payload())
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    assert operation["status"] == "waiting_on_approval"
    assert operation["approval_request_ids"] == [request_id]
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["codex_hook_waits_for_browser_approval"] is True
    request = store.get_approval_request(request_id)
    assert request is not None
    now = datetime.now(timezone.utc)
    waiting = continue_request_after_application(
        store,
        request_row=request,
        action="allow",
        now=now.isoformat(),
    )
    assert waiting["continuationStatus"] == "waiting"
    assert waiting["continuationReason"] == "original_hook_waiting"
    completed = record_live_hook_completion(
        store,
        request_id=request_id,
        action="allow",
        now=(now + timedelta(seconds=1)).isoformat(),
    )
    assert completed is not None
    assert completed["continuationStatus"] == "resumed"
    assert completed["continuationReason"] == "live_hook_completed"
    resume = store.get_request_resume(request_id)
    assert resume is not None
    assert resume["status"] == "sent"
    assert resume["continuation_status"] == "resumed"
    assert resume["resolution_action"] == "allow"


def test_live_codex_pause_freezes_the_attached_hook_before_upload(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    response = _pause(store, tmp_path, harness="codex", payload=_live_payload())
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    request = store.get_approval_request(request_id)
    assert request is not None
    snapshot = request["continuation_snapshot"]
    assert isinstance(snapshot, dict)
    assert snapshot["capability"] == "suspended-response"
    assert snapshot["hookAttached"] is True
    assert snapshot["opaqueTargetId"] is None
    assert snapshot["correlationId"] == cloud_review_correlation_id(request_id)
    assert isinstance(snapshot["waitDeadline"], str) and snapshot["waitDeadline"]

    with store._connect() as connection:
        created = connection.execute(
            """select payload_json from guard_review_outbox_events
               where local_request_id = ? and event_type = 'review.request.created'""",
            (request_id,),
        ).fetchone()
    assert created is not None
    created_snapshot = json.loads(json.loads(created["payload_json"])["requestSnapshot"]["continuation_snapshot_json"])
    assert created_snapshot["capability"] == "suspended-response"
    assert created_snapshot["correlationId"] == snapshot["correlationId"]

    now = datetime.now(timezone.utc)
    completed = record_live_hook_completion(
        store,
        request_id=request_id,
        action="allow",
        now=(now + timedelta(seconds=1)).isoformat(),
    )
    assert completed is not None
    assert completed["continuationCapability"] == "suspended-response"
    assert completed["correlationId"] == snapshot["correlationId"]
    with store._connect() as connection:
        terminal = connection.execute(
            """select payload_json from guard_review_outbox_events
               where local_request_id = ? and event_type = 'review.continuation.resumed'""",
            (request_id,),
        ).fetchone()
    assert terminal is not None
    result = json.loads(terminal["payload_json"])["continuationResult"]
    assert result["capability"] == created_snapshot["capability"]
    assert result["correlationId"] == created_snapshot["correlationId"]
    assert result["status"] == "resumed"


def test_detached_block_cites_the_published_pause_binding(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    response = _pause(store, tmp_path, harness="codex", payload=_live_payload())
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    request = store.get_approval_request(request_id)
    assert request is not None
    snapshot = request["continuation_snapshot"]
    assert isinstance(snapshot, dict)
    assert snapshot["capability"] == "suspended-response"
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    detached = dict(metadata)
    detached["codex_browser_wait_process"] = {"pid": 2_147_483_646, "startToken": "stale-start-token"}
    store.upsert_guard_operation(
        operation_id=str(operation["operation_id"]),
        session_id=str(operation["session_id"]),
        harness="codex",
        operation_type=str(operation["operation_type"]),
        status=str(operation["status"]),
        approval_request_ids=[request_id],
        resume_token=None,
        metadata=detached,
        now=datetime.now(timezone.utc).isoformat(),
    )
    blocked = continue_request_after_application(
        store,
        request_row=request,
        action="block",
        now=datetime.now(timezone.utc).isoformat(),
        headless=False,
    )
    assert blocked["continuationStatus"] == "blocked_not_resumed"
    with store._connect() as connection:
        row = connection.execute(
            """select payload_json from guard_review_outbox_events
               where local_request_id = ? and event_type = 'review.continuation.blocked_not_resumed'""",
            (request_id,),
        ).fetchone()
    assert row is not None
    result = json.loads(row["payload_json"])["continuationResult"]
    assert result["status"] == "blocked_not_resumed"
    assert result["capability"] == snapshot["capability"]
    assert result["correlationId"] == snapshot["correlationId"]


def test_detached_allow_remains_a_retry_only_degradation(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    response = _pause(store, tmp_path, harness="codex", payload=_live_payload())
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    request = store.get_approval_request(request_id)
    assert request is not None
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    detached = dict(metadata)
    detached["codex_browser_wait_process"] = {"pid": 2_147_483_646, "startToken": "stale-start-token"}
    store.upsert_guard_operation(
        operation_id=str(operation["operation_id"]),
        session_id=str(operation["session_id"]),
        harness="codex",
        operation_type=str(operation["operation_type"]),
        status=str(operation["status"]),
        approval_request_ids=[request_id],
        resume_token=None,
        metadata=detached,
        now=datetime.now(timezone.utc).isoformat(),
    )
    manual = continue_request_after_application(
        store,
        request_row=request,
        action="allow",
        now=datetime.now(timezone.utc).isoformat(),
        headless=False,
    )
    assert manual["continuationStatus"] == "manual_retry_required"
    assert manual["continuationCapability"] == "retry-only"
    with store._connect() as connection:
        row = connection.execute(
            """select payload_json from guard_review_outbox_events
               where local_request_id = ? and event_type = 'review.continuation.manual_retry_required'""",
            (request_id,),
        ).fetchone()
    assert row is not None
    result = json.loads(row["payload_json"])["continuationResult"]
    assert result["capability"] == "retry-only"
    assert result["status"] == "manual_retry_required"


def test_codex_pause_without_a_live_hook_stays_retry_only(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    response = _pause(
        store,
        tmp_path,
        harness="codex",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "notes.txt"},
        },
    )
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    assert store.get_guard_operation_for_approval_request(request_id) is None
    request = store.get_approval_request(request_id)
    assert request is not None
    snapshot = request["continuation_snapshot"]
    assert isinstance(snapshot, dict)
    assert snapshot["capability"] == "retry-only"
    assert snapshot["hookAttached"] is False
    now = datetime.now(timezone.utc).isoformat()
    manual = continue_request_after_application(store, request_row=request, action="allow", now=now)
    assert manual["continuationStatus"] == "manual_retry_required"
    assert record_live_hook_completion(store, request_id=request_id, action="allow", now=now) is None


def test_stale_process_identity_cannot_attach_a_codex_hook(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    payload = _live_payload()
    identity = payload[CODEX_BROWSER_WAIT_PROCESS_KEY]
    assert isinstance(identity, dict)
    payload[CODEX_BROWSER_WAIT_PROCESS_KEY] = {"pid": 2_147_483_646, "startToken": identity["startToken"]}
    response = _pause(store, tmp_path, harness="codex", payload=payload)
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    assert store.get_guard_operation_for_approval_request(request_id) is None


def test_non_codex_pause_does_not_gain_codex_hook_attachment(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    response = _pause(store, tmp_path, harness="claude-code", payload=_live_payload())
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    assert store.get_guard_operation_for_approval_request(request_id) is None
