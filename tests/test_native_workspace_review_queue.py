from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import (
    CommandCapabilityError,
    mark_command_job_consumed,
)
from codex_plugin_scanner.guard.runtime.command_executors import COMMAND_OPERATION_SCHEMA_VERSIONS
from codex_plugin_scanner.guard.runtime.command_queue_authority import authorize_transport_command_queue_job
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    authorize_exact_cloud_review_job,
    disable_exact_cloud_review,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review_executor import execute_exact_cloud_review_operation
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import (
    exact_result,
    exact_transport_job,
)
from codex_plugin_scanner.guard.runtime.native_workspace_review import NativeWorkspaceReviewError
from codex_plugin_scanner.guard.runtime.native_workspace_review_queue import (
    NativeWorkspaceReviewQueueError,
    is_native_workspace_review_job,
    native_workspace_review_payload,
    native_workspace_review_transport_candidate,
    require_native_workspace_review_authority,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    exact_review_job,
    review_request,
)


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "regular"])
def test_native_transport_hint_requires_installed_file_and_preserves_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    store = connected_exact_review_store(tmp_path)
    monkeypatch.setattr(command_queue, "review_verification_keyring_ready", lambda _store: False)
    authority = store.guard_home / "native-runtime" / "workspace-review-authority.v1.json"
    authority.parent.mkdir(parents=True, exist_ok=True)
    if kind == "directory":
        authority.mkdir()
    elif kind == "symlink":
        target = tmp_path / "untrusted-authority.json"
        target.write_text("{}", encoding="utf-8")
        authority.symlink_to(target)
    elif kind == "regular":
        authority.write_text("{}", encoding="utf-8")
    assert native_workspace_review_transport_candidate(store) is (kind == "regular")
    assert ("guard.review.resolveExact" in command_queue.lease_ready_operations(store)) is (kind == "regular")
    if kind == "regular":
        disable_exact_cloud_review(store)
        assert command_queue.lease_ready_operations(store) == ()


def _native_job(store, request_id: str = "native-request") -> dict[str, object]:
    job = exact_review_job(store, {})
    job.update(
        {
            "id": "native-job-1",
            "leaseId": "native-lease-1",
            "expiresAt": "2026-09-27T23:00:00+00:00",
            "payload": {
                "localRequestId": request_id,
                "receiptId": "native-receipt-1",
                "envelope": {"decision": "allow"},
            },
            "serverResolvedBinding": {"localRequestId": request_id},
        }
    )
    return job


def _native_store(tmp_path: Path, request_id: str = "native-request"):
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request(request_id))
    return store


def test_native_transport_hint_cannot_authorize_legacy_payload_without_keyring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    authority = store.guard_home / "native-runtime" / "workspace-review-authority.v1.json"
    authority.parent.mkdir(parents=True, exist_ok=True)
    authority.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(command_queue, "review_verification_keyring_ready", lambda _store: False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.command_queue_authority.review_verification_keyring_ready",
        lambda _store: False,
    )
    assert "guard.review.resolveExact" in command_queue.lease_ready_operations(store)
    job = exact_transport_job(exact_review_job(store, {}))
    with pytest.raises(CommandCapabilityError, match="cloud_review_verification_unavailable"):
        authorize_transport_command_queue_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)


def test_native_payload_is_exact_and_mixed_payloads_do_not_fallback() -> None:
    parsed = native_workspace_review_payload(
        {
            "localRequestId": "request-1",
            "receiptId": "receipt-1",
            "envelope": {"decision": "allow"},
        }
    )
    assert parsed is not None
    assert parsed.local_request_id == "request-1"
    assert parsed.receipt_id == "receipt-1"
    with pytest.raises(NativeWorkspaceReviewQueueError, match="remote_native_workspace_review_invalid"):
        native_workspace_review_payload(
            {
                "localRequestId": "request-1",
                "receiptId": "receipt-1",
                "envelope": {"decision": "allow"},
                "remoteApproval": {},
            }
        )
    for identifier in (" request-1", "request-1 ", "x" * 129):
        with pytest.raises(NativeWorkspaceReviewQueueError, match="remote_native_workspace_review_invalid"):
            native_workspace_review_payload(
                {
                    "localRequestId": identifier,
                    "receiptId": "receipt-1",
                    "envelope": {"decision": "allow"},
                }
            )
    with pytest.raises(NativeWorkspaceReviewQueueError, match="remote_native_workspace_review_invalid"):
        native_workspace_review_payload(
            {
                "localRequestId": "request-1",
                "receiptId": " receipt-1",
                "envelope": {"decision": "allow"},
            }
        )


def test_native_consumption_bypass_requires_exact_operation() -> None:
    payload = {
        "localRequestId": "request-1",
        "receiptId": "receipt-1",
        "envelope": {"decision": "allow"},
    }
    assert is_native_workspace_review_job({"operation": "guard.review.resolveExact", "payload": payload}) is True
    assert is_native_workspace_review_job({"operation": "guard.packageShims.status", "payload": payload}) is False


def test_nonnative_operation_with_native_fields_keeps_generic_consumption_mark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _native_store(tmp_path)
    job = _native_job(store)
    job["operation"] = "guard.packageShims.status"
    marked: list[str] = []
    monkeypatch.setattr(command_queue, "command_queue_should_poll", lambda _store: True)
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {"sync_url": "https://guard.example/sync", "access_token": "token"},
    )
    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lambda *_args, **_kwargs: job)
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda _auth, *, method, path, payload: {"ok": True},
    )
    monkeypatch.setattr(command_queue, "_execute_job", lambda *_args: {"status": "completed"})
    monkeypatch.setattr(
        command_queue,
        "authorize_command_queue_job",
        lambda _store, item, **_kwargs: SimpleNamespace(
            identity={"id": item["id"]},
            operation=item["operation"],
            requires_local_approval=False,
        ),
    )
    monkeypatch.setattr(command_queue, "consume_local_command_approval", lambda *_args: True)
    monkeypatch.setattr(
        command_queue,
        "mark_command_job_consumed",
        lambda _store, authorized, **_kwargs: marked.append(authorized.operation),
    )
    monkeypatch.setattr(command_queue, "audit_command_decision", lambda *_args, **_kwargs: None)

    command_queue.poll_command_queue_once(
        store, HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path)
    )

    assert marked == ["guard.packageShims.status"]


def test_native_authorization_uses_resident_readiness_and_skips_replay_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _native_store(tmp_path)
    job = _native_job(store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.require_native_workspace_review_authority",
        lambda *_args: None,
    )
    authorized = authorize_exact_cloud_review_job(store, job, now="2026-09-27T12:00:00+00:00")
    mark_command_job_consumed(store, authorized, now="2026-09-27T12:00:00+00:00")
    replay = authorize_exact_cloud_review_job(store, job, now="2026-09-27T12:01:00+00:00")
    assert replay.operation == authorized.operation
    assert replay.requires_local_approval is False


def test_native_authorization_rejects_wrong_target_revocation_and_not_enrolled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _native_store(tmp_path)
    job = _native_job(store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.require_native_workspace_review_authority",
        lambda *_args: None,
    )
    wrong_target = {**job, "deviceId": "wrong-device"}
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_wrong_target"):
        authorize_exact_cloud_review_job(store, wrong_target, now="2026-09-27T12:00:00+00:00")

    disable_exact_cloud_review(store, now="2026-09-27T12:00:00+00:00")
    with pytest.raises(CommandCapabilityError, match="cloud_review_capability_revoked"):
        authorize_exact_cloud_review_job(store, job, now="2026-09-27T12:00:00+00:00")

    store = _native_store(tmp_path / "not-enrolled")
    job = _native_job(store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.require_native_workspace_review_authority",
        lambda *_args: (_ for _ in ()).throw(NativeWorkspaceReviewQueueError("native_workspace_review_not_enrolled")),
    )
    with pytest.raises(CommandCapabilityError, match="native_workspace_review_not_enrolled"):
        authorize_exact_cloud_review_job(store, job, now="2026-09-27T12:00:00+00:00")


def test_native_preflight_preserves_binding_failure_and_distinguishes_local_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _native_store(tmp_path)
    command = native_workspace_review_payload(_native_job(store)["payload"])
    assert command is not None

    def reject_binding(*_args: object) -> None:
        raise NativeWorkspaceReviewError("native_workspace_review_decision_binding_mismatch")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.matching_workspace_review_snapshot",
        reject_binding,
    )
    with pytest.raises(NativeWorkspaceReviewQueueError, match="native_workspace_review_decision_binding_mismatch"):
        require_native_workspace_review_authority(store, command)

    def fail_local_io(*_args: object) -> None:
        raise OSError("unavailable")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.matching_workspace_review_snapshot",
        fail_local_io,
    )
    with pytest.raises(NativeWorkspaceReviewQueueError, match="native_workspace_review_not_enrolled"):
        require_native_workspace_review_authority(store, command)


def test_native_transport_requires_exact_route_and_payload_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _native_store(tmp_path)
    job = _native_job(store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.require_native_workspace_review_authority",
        lambda *_args: None,
    )
    with pytest.raises(CommandCapabilityError, match="remote_exact_transport_required"):
        authorize_transport_command_queue_job(
            store,
            job,
            schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
            now="2026-09-27T12:00:00+00:00",
        )
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_operation_invalid"):
        authorize_transport_command_queue_job(
            store,
            exact_transport_job({**job, "operation": "guard.packageShims.status"}),
            schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
            now="2026-09-27T12:00:00+00:00",
        )


def test_native_executor_applies_receipt_without_external_resume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload: dict[str, object] = {
        "localRequestId": "request-1",
        "receiptId": "receipt-1",
        "envelope": {"decision": "allow"},
    }
    applied = {
        "resolution_action": "allow",
        "native_replayed": True,
        "resolved_request": {"request_id": "request-1", "status": "resolved"},
    }
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.apply_native_workspace_review_decision",
        lambda *_args, **_kwargs: applied,
    )
    execution = execute_exact_cloud_review_operation(
        payload=payload,
        store=cast(GuardStore, cast(object, SimpleNamespace(guard_home=tmp_path))),
        generated_at="2026-09-27T12:00:00+00:00",
        resume_after_approval=lambda **_kwargs: pytest.fail("native delivery must not resume an external action"),
    )
    data = execution["data"]
    assert isinstance(data, dict)
    assert data["continuationStatus"] == "not_applicable"
    assert data["nativeReplayed"] is True
    assert data["localRequestId"] == "request-1"


def test_native_exact_result_binds_server_request_and_receipt() -> None:
    job: dict[str, object] = {
        "id": "native-job-1",
        "leaseId": "native-lease-1",
        "payload": {
            "localRequestId": "request-1",
            "receiptId": "receipt-1",
            "envelope": {"decision": "allow"},
        },
        "serverResolvedBinding": {"localRequestId": "request-1"},
    }
    result = exact_result(
        job,
        {
            "generatedAt": "2026-09-27T12:00:00+00:00",
            "data": {
                "applicationReason": None,
                "applicationStatus": "applied",
                "applicationUpdatedAt": "2026-09-27T12:00:00+00:00",
                "continuationReason": "native_workspace_review_no_external_replay",
                "continuationStatus": "not_applicable",
                "continuationUpdatedAt": "2026-09-27T12:00:00+00:00",
                "localRequestId": "request-1",
                "receiptId": "receipt-1",
            },
        },
    )
    assert result["localRequestId"] == "request-1"
    assert result["receiptId"] == "receipt-1"


def test_native_lost_ack_redelivery_skips_generic_mark_and_external_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _native_store(tmp_path)
    job = _native_job(store)
    now = "2026-09-27T12:00:00+00:00"
    calls: list[tuple[str, str]] = []
    execution = {
        "data": {
            "applicationReason": None,
            "applicationStatus": "applied",
            "applicationUpdatedAt": now,
            "continuationReason": "native_workspace_review_no_external_replay",
            "continuationStatus": "not_applicable",
            "continuationUpdatedAt": now,
            "localRequestId": "native-request",
            "receiptId": "native-receipt-1",
        },
        "generatedAt": now,
    }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_queue.require_native_workspace_review_authority",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {
            "sync_url": "https://guard.example/api/guard/receipts/sync",
            "access_token": "token",
        },
    )
    monkeypatch.setattr(command_queue, "_execute_job", lambda *_args: execution)
    monkeypatch.setattr(
        command_queue,
        "mark_command_job_consumed",
        lambda *_args, **_kwargs: pytest.fail("native jobs must rely on resident claims, not generic replay marks"),
    )

    def exact_request(_auth: dict[str, object], *, method: str, path: str, payload: dict[str, object]):
        del payload
        calls.append((method, path))
        if path == "/lease":
            return {"item": job, "protocolVersion": 2}
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_exact_json_request", exact_request)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path)
    command_queue.poll_command_queue_once(store, context)
    command_queue.poll_command_queue_once(store, context)

    assert calls.count(("POST", "/native-job-1/result")) == 2
