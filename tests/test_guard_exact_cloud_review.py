# pyright: reportMissingImports=false

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser, _resolve_legacy_args, main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cloud_review_dispatch
from codex_plugin_scanner.guard.daemon import command_queue_worker as queue_worker_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.review_contracts import (
    GuardReviewContractError,
    _anchored_review_verification_keys,
    build_local_review_request_claim,
    validated_review_verification_keys_from_sync,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime.command_capability import (
    CommandCapabilityError,
    issue_command_capability,
    mark_command_job_consumed,
)
from codex_plugin_scanner.guard.runtime.command_executors import (
    COMMAND_OPERATION_SCHEMA_VERSIONS,
    SUPPORTED_COMMAND_OPERATIONS,
    execute_guard_command_job,
)
from codex_plugin_scanner.guard.runtime.command_queue_authority import (
    authorize_command_queue_job,
    command_queue_oauth_target,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    ExactCloudReviewError,
    _oauth_metadata,
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_operations,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request as _add_request,
)
from tests.guard_exact_cloud_review_support import (
    connected_exact_review_store as _connected_store,
)
from tests.guard_exact_cloud_review_support import (
    exact_review_job as _job,
)
from tests.guard_exact_cloud_review_support import (
    remote_approval as _remote_approval,
)
from tests.guard_exact_cloud_review_support import (
    review_request as _request,
)
from tests.guard_review_signing_helpers import review_verification_keys


def test_review_sync_keys_require_preanchored_key_material(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    review_keys = review_verification_keys(workspace_id="workspace-1")
    policy_anchor = {**review_keys[0], "purpose": "policy_bundle"}
    store.set_sync_payload(
        "policy_bundle_keyring",
        [policy_anchor],
        "2026-08-25T00:00:00+00:00",
    )

    admitted = validated_review_verification_keys_from_sync(
        review_keys,
        store=store,
        workspace_id="workspace-1",
    )
    store.set_sync_payload(
        "guard_review_verification_keyring",
        [key.to_dict() for key in admitted],
        "2026-08-25T00:01:00+00:00",
    )

    assert [key.to_dict() for key in admitted] == review_keys
    assert _anchored_review_verification_keys(store)[0].purpose == "remote_approval"


def test_review_sync_keys_reject_unanchored_key_material(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    with pytest.raises(GuardReviewContractError, match="unknown_signing_key"):
        validated_review_verification_keys_from_sync(
            review_verification_keys(workspace_id="workspace-1"),
            store=store,
            workspace_id="workspace-1",
        )


def test_exact_cloud_review_resolves_one_request_without_policy_or_memory(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    target = _request("exact-target")
    other = _request("exact-other")
    _add_request(store, target)
    _add_request(store, other)
    policies_before = store.list_policy_decisions()
    enable_exact_cloud_review(store)

    resolution = apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(store, target.request_id, receipt_id="exact-receipt-1"),
        expected_harness="codex",
    )

    assert resolution.request_id == target.request_id
    assert resolution.resolved_request["resolution_scope"] == "artifact"
    target_row = store.get_approval_request(target.request_id)
    other_row = store.get_approval_request(other.request_id)
    assert target_row is not None and target_row["status"] == "resolved"
    assert other_row is not None and other_row["status"] == "pending"
    assert store.list_policy_decisions() == policies_before
    assert store.get_sync_payload("guard_review_memory_registry") is None
    resolved_at = resolution.resolved_request["resolved_at"]
    assert isinstance(resolved_at, str)
    authority_lookup = store.resolve_policy_decision_lookup(
        harness=target.harness,
        artifact_id=target.artifact_id,
        artifact_hash=target.artifact_hash,
        workspace=target.workspace,
        publisher=target.publisher,
        now=resolved_at,
        consume_one_shot=False,
    )
    authority = authority_lookup["decision"]
    assert authority is not None
    assert authority["request_id"] == target.request_id
    assert authority["source"] == "approval-gate-once"
    assert store.claim_approval_reuse_decision(authority, now=resolved_at) is True
    assert (
        store.peek_local_once_approval(
            harness=target.harness,
            artifact_id=target.artifact_id,
            artifact_hash=target.artifact_hash,
            workspace=target.workspace,
            publisher=target.publisher,
            now=resolved_at,
        )
        is None
    )
    audit = store.list_events(limit=1, event_name="cloud_review.exact_applied")
    assert audit
    audit_payload = audit[0].get("payload")
    assert isinstance(audit_payload, dict)
    assert audit_payload["receipt_id"] == "exact-receipt-1"


def test_exact_cloud_review_replay_is_durable_and_rejected_before_resolution(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-replay")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    approval = _remote_approval(store, request.request_id, receipt_id="exact-receipt-replay")
    apply_exact_cloud_review(store, remote_approval=approval)

    reopened = GuardStore(store.guard_home)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_replayed"):
        apply_exact_cloud_review(reopened, remote_approval=approval)
    reopened_request = reopened.get_approval_request(request.request_id)
    assert reopened_request is not None and reopened_request["status"] == "resolved"


def test_exact_cloud_review_capability_is_separate_from_generic_commands(tmp_path: Path) -> None:
    missing_store = _connected_store(tmp_path / "missing-device", missing_device_id=True)
    missing_credentials = missing_store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(missing_credentials, dict) and missing_credentials["machine_id"]
    with pytest.raises(ExactCloudReviewError, match="cloud_review_device_binding_missing"):
        enable_exact_cloud_review(missing_store)
    store = _connected_store(tmp_path)
    oauth_state = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_state, dict)
    without_device = {key: value for key, value in oauth_state.items() if key != "device_id"}
    store.set_sync_payload("oauth_local_credentials", without_device, datetime.now(timezone.utc).isoformat())
    with pytest.raises(ExactCloudReviewError, match="cloud_review_device_binding_missing"):
        enable_exact_cloud_review(store)
    store.set_sync_payload("oauth_local_credentials", oauth_state, datetime.now(timezone.utc).isoformat())
    status = enable_exact_cloud_review(store)

    assert status["enabled"] is True
    request = _request("exact-missing-device-atomic")
    _add_request(store, request)
    approval = _remote_approval(store, request.request_id, receipt_id="exact-missing-device-atomic")
    store.set_sync_payload("oauth_local_credentials", without_device, datetime.now(timezone.utc).isoformat())
    with pytest.raises(ExactCloudReviewError, match="cloud_review_device_binding_missing"):
        apply_exact_cloud_review(store, remote_approval=approval)
    pending = store.get_approval_request(request.request_id)
    assert pending is not None and pending["status"] == "pending"
    store.set_sync_payload("oauth_local_credentials", oauth_state, datetime.now(timezone.utc).isoformat())
    diagnostics = status.get("diagnostics")
    assert isinstance(diagnostics, dict)
    assert {"capability", "oauth", "outbox", "worker"} <= diagnostics.keys()
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)
    with pytest.raises(CommandCapabilityError, match="unsupported_capability_operation"):
        issue_command_capability(
            store,
            operations=(EXACT_CLOUD_REVIEW_OPERATION,),
            supported_operations=SUPPORTED_COMMAND_OPERATIONS,
        )
    disabled = disable_exact_cloud_review(store)
    assert disabled["enabled"] is False
    assert exact_cloud_review_operations(store) == ()
    assert store.get_sync_payload("guard_exact_cloud_review_revocation") is not None


def test_exact_cloud_review_rejects_tampered_or_revoked_capabilities(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-revoked")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    remote_approval = _remote_approval(store, request.request_id, receipt_id="exact-tampered")
    capability = store.get_sync_payload("guard_exact_cloud_review_capability")
    assert isinstance(capability, dict)
    tampered = {**capability, "workspaceId": "other-workspace"}
    store.set_sync_payload("guard_exact_cloud_review_capability", tampered, "2026-08-24T12:00:00+00:00")
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_signature_invalid"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval,
        )

    disable_exact_cloud_review(store)
    store.set_sync_payload("guard_exact_cloud_review_capability", capability, "2026-08-24T12:00:00+00:00")
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revoked"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval,
        )


def test_exact_cloud_review_cli_status_is_routable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    guard_home = tmp_path / "guard-home"

    assert main(["guard", "cloud-review", "status", "--guard-home", str(guard_home), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["operation"] == EXACT_CLOUD_REVIEW_OPERATION
    assert payload["enabled"] is False


def test_hol_guard_routes_cloud_review_as_a_top_level_command() -> None:
    assert _resolve_legacy_args(
        ["cloud-review", "status"],
        program_mode="combined",
        program_name="hol-guard",
    ) == ["guard", "cloud-review", "status"]
    parser = _build_parser("hol-guard", program_mode="combined")
    assert parser.parse_args(["guard", "connect", "--enable-cloud-review"]).enable_cloud_review is True
    assert parser.parse_args(["guard", "connect", "--headless", "--enable-cloud-review"]).headless is True
    assert parser.parse_args(["guard", "cloud-review", "enable"]).cloud_review_command == "enable"


def test_successful_connect_issues_cloud_review_capability_only_after_explicit_consent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed"},
    )
    base_payload: dict[str, object] = {"status": "connected"}

    unchanged = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=False),
        store=store,
        guard_home=store.guard_home,
        payload=base_payload,
        exit_code=0,
    )
    assert unchanged is base_payload
    assert exact_cloud_review_operations(store) == ()

    failed_connect = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload=base_payload,
        exit_code=1,
    )
    assert failed_connect["cloud_review"] == {
        "enabled": False,
        "reason": "connect_not_completed",
    }
    assert exact_cloud_review_operations(store) == ()

    connected = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload=base_payload,
        exit_code=0,
    )
    cloud_review = connected["cloud_review"]
    assert isinstance(cloud_review, dict)
    assert cloud_review["enabled"] is True
    assert cloud_review["pending_requests_requeued"] == 0
    assert cloud_review["pending_request_requeue_status"] == "requeued"
    assert cloud_review["worker"] == {"status": "refreshed"}
    assert isinstance(cloud_review["capability"], dict)
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)


def test_cloud_review_enable_requeues_existing_pending_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _connected_store(tmp_path)
    request = _request("pending-before-consent")
    _add_request(store, request)
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed"},
    )

    exit_code = cloud_review_dispatch._run_guard_cloud_review_command(
        argparse.Namespace(
            cloud_review_command="enable",
            expires_in_days=30,
            json=True,
        ),
        guard_home=store.guard_home,
        store=store,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["pending_requests_requeued"] == 1
    assert payload["pending_request_requeue_status"] == "requeued"
    assert payload["worker"] == {"status": "refreshed"}


def test_cloud_review_requeue_database_failure_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)

    def fail_requeue(*, changed_at: str) -> int:
        del changed_at
        raise sqlite3.OperationalError("database is busy")

    monkeypatch.setattr(store, "requeue_pending_review_events", fail_requeue)

    assert cloud_review_dispatch._requeue_pending_cloud_review_requests(store) == (
        0,
        "retry_required",
    )


def test_connect_consent_preserves_enabled_capability_when_requeue_needs_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_requeue_pending_cloud_review_requests",
        lambda _store: (0, "retry_required"),
    )
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed"},
    )

    connected = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )

    cloud_review = connected["cloud_review"]
    assert isinstance(cloud_review, dict)
    assert cloud_review["capability_enabled"] is True
    assert cloud_review["enabled"] is True
    assert cloud_review["reason"] == "pending_request_requeue_failed"
    assert cloud_review["pending_request_requeue_status"] == "retry_required"
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)


def test_cloud_review_enable_reports_requeue_retry_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _connected_store(tmp_path)
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_requeue_pending_cloud_review_requests",
        lambda _store: (0, "retry_required"),
    )
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed"},
    )

    exit_code = cloud_review_dispatch._run_guard_cloud_review_command(
        argparse.Namespace(cloud_review_command="enable", expires_in_days=30, json=True),
        guard_home=store.guard_home,
        store=store,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["status"] == "enabled"
    assert payload["pending_requests_requeued"] == 0
    assert payload["pending_request_requeue_status"] == "retry_required"
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)


def test_exact_cloud_review_queue_job_requires_no_generic_capability_or_local_approval(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    guard_runner_module._persist_rotated_oauth_refresh_token(
        store=store,
        credentials=credentials,
        refresh_token="rotated-refresh-token",
    )
    oauth_state = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_state, dict)
    assert oauth_state["device_id"] == credentials["dpop_public_jwk_thumbprint"]
    request = _request("exact-queue")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    request_row = store.get_approval_request(request.request_id)
    assert isinstance(request_row, dict)
    request_claim = build_local_review_request_claim(
        request_row=request_row,
        oauth=_oauth_metadata(store),
        store=store,
    )
    assert request_claim["deviceId"] == oauth_state["device_id"]
    assert request_claim["machineId"] == oauth_state["machine_id"]
    assert command_queue_oauth_target(store) == (oauth_state["device_id"], oauth_state["workspace_id"])
    job = _job(
        store,
        _remote_approval(
            store,
            request.request_id,
            receipt_id="exact-receipt-queue",
            source_claim=request_claim,
        ),
    )

    authorized = authorize_command_queue_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    assert authorized.identity["deviceId"] == oauth_state["device_id"]
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_wrong_target"):
        authorize_command_queue_job(
            store,
            {**job, "deviceId": oauth_state["machine_id"]},
            schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    result = execute_guard_command_job(
        job,
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=store.guard_home),
        store=store,
    )

    assert authorized.operation == EXACT_CLOUD_REVIEW_OPERATION
    assert authorized.requires_local_approval is False
    result_data = result.get("data")
    assert isinstance(result_data, dict)
    assert result_data["status"] == "completed"
    assert result_data["applicationStatus"] == "applied"
    assert result_data["applicationReason"] is None
    assert store.get_sync_payload("guard_review_memory_registry") is None
    second = _request("exact-queue-replay-second")
    _add_request(store, second)
    mark_command_job_consumed(store, authorized)
    replay = _job(store, _remote_approval(store, second.request_id, receipt_id="exact-job-second"))

    with pytest.raises(CommandCapabilityError, match="remote_exact_job_replayed"):
        authorize_command_queue_job(store, replay, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)

    second_row = store.get_approval_request(second.request_id)
    assert second_row is not None and second_row["status"] == "pending"
    recovery_now = datetime.now(timezone.utc).isoformat()
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=recovery_now,
    )
    store.delete_sync_payload("oauth_local_credentials")
    recovered = store._recover_missing_oauth_local_credentials_payload(now=recovery_now)
    assert isinstance(recovered, dict)
    assert recovered["device_id"] == oauth_state["device_id"]
    assert "dpop_private_key_pem" not in recovered
    assert "dpop_public_jwk" not in recovered
    assert "dpop_public_jwk_thumbprint" not in recovered
    assert "refresh_token" not in recovered

    assert store.repair_oauth_local_credential_storage_from_primary() is True
    restarted = GuardStore(store.guard_home)
    persisted = restarted.get_sync_payload("oauth_local_credentials")
    assert isinstance(persisted, dict)
    assert "dpop_public_jwk_thumbprint" not in persisted


def test_command_queue_worker_refresh_serializes_with_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    enable_exact_cloud_review(store)
    starts: list[str] = []
    monkeypatch.setattr(
        daemon_server_module,
        "start_command_queue_worker",
        lambda *_args: starts.append("start") or None,
    )
    lifecycle_daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    lifecycle_daemon.start()
    lifecycle_daemon._finish_service_lock.acquire()
    entered = threading.Event()
    refresh_result: dict[str, object] = {}

    def _refresh_during_shutdown() -> None:
        entered.set()
        refresh_result.update(lifecycle_daemon.refresh_command_queue_worker())

    refresh_thread = threading.Thread(target=_refresh_during_shutdown)
    refresh_thread.start()
    assert entered.wait(timeout=1)
    lifecycle_daemon._shutdown_started.set()
    lifecycle_daemon._finish_service_lock.release()
    refresh_thread.join(timeout=2)
    try:
        assert refresh_thread.is_alive() is False
        assert refresh_result["running"] is False
        assert starts == ["start"]
    finally:
        lifecycle_daemon.stop()

    old_release = threading.Event()
    old_thread = threading.Thread(target=old_release.wait)
    old_thread.start()
    old_stop = threading.Event()
    old_stop.set()
    old_worker = queue_worker_module.CommandQueueWorker(thread=old_thread, stop_event=old_stop)
    monkeypatch.setattr(queue_worker_module, "command_queue_enabled", lambda _store: True)
    monkeypatch.setattr(queue_worker_module, "_COMMAND_QUEUE_THREAD_JOIN_TIMEOUT_SECONDS", 0.01)
    try:
        assert queue_worker_module.start_command_queue_worker(store, old_worker) is old_worker
    finally:
        old_release.set()
        old_thread.join(timeout=1)
