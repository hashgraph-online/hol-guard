# pyright: reportMissingImports=false

from __future__ import annotations

import sqlite3
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_exact_cloud_review as exact_store_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_dispatch_cloud_review import provision_connect_time_exact_cloud_review
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import command_executors as command_executor_module
from codex_plugin_scanner.guard.runtime.command_capability import CommandCapabilityError
from codex_plugin_scanner.guard.runtime.command_queue_authority import authorize_command_queue_job
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    enable_exact_cloud_review,
)
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


def test_exact_cloud_review_uses_local_time_not_forged_queue_admission(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-expired-receipt")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    approval = _remote_approval(
        store,
        request.request_id,
        receipt_id="exact-expired-receipt",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    job = _job(
        store,
        approval,
        created_at=issued_at + timedelta(minutes=1),
        expires_at=issued_at + timedelta(hours=6),
    )

    result = command_executor_module.execute_guard_command_job(
        job,
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=store.guard_home),
        store=store,
        now=lambda: (issued_at + timedelta(minutes=6)).isoformat(),
    )

    assert result["failureCode"] == "remote_approval_expired"
    row = store.get_approval_request(request.request_id)
    assert row is not None and row["status"] == "pending"


def test_exact_cloud_review_receipt_expiry_boundary_and_strict_wire(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    current = datetime.now(timezone.utc).replace(microsecond=0)
    accepted = _request("exact-boundary-accepted")
    rejected = _request("exact-boundary-rejected")
    invalid_decision = _request("exact-wire-invalid-decision")
    transaction_expired = _request("exact-transaction-expired")
    capability_expired = _request("exact-capability-expired")
    for request in (accepted, rejected, invalid_decision, transaction_expired, capability_expired):
        _add_request(store, request)
    enable_exact_cloud_review(store, now=current.isoformat(), ttl_seconds=600)
    expires_at = current + timedelta(minutes=5)

    apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(
            store,
            accepted.request_id,
            receipt_id="exact-boundary-accepted",
            issued_at=current,
            expires_at=expires_at,
        ),
        now=(expires_at - timedelta(microseconds=1)).isoformat(),
    )
    with pytest.raises(ExactCloudReviewError, match="remote_approval_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                rejected.request_id,
                receipt_id="exact-boundary-rejected",
                issued_at=current,
                expires_at=expires_at,
            ),
            now=expires_at.isoformat(),
        )
    with pytest.raises(ExactCloudReviewError, match="remote_exact_decision_invalid"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                invalid_decision.request_id,
                receipt_id="exact-wire-invalid-decision",
                decision="allow",
            ),
        )
    monkeypatch.setattr(
        exact_store_module.StoreExactCloudReviewMixin,
        "_exact_transaction_now",
        staticmethod(lambda: expires_at.isoformat()),
    )
    with pytest.raises(ExactCloudReviewError, match="remote_approval_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                transaction_expired.request_id,
                receipt_id="exact-transaction-expired",
                issued_at=current,
                expires_at=expires_at,
            ),
            now=(current + timedelta(seconds=1)).isoformat(),
        )
    enable_exact_cloud_review(store, now=current.isoformat(), ttl_seconds=300)
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                capability_expired.request_id,
                receipt_id="exact-capability-expired",
                issued_at=current,
                expires_at=current + timedelta(minutes=10),
            ),
            now=(current + timedelta(seconds=1)).isoformat(),
        )


def test_exact_cloud_review_rejects_stale_requests_and_durable_binding_drift(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    stale = _request("exact-stale-request")
    store.add_approval_request(stale, "2020-01-01T00:00:00+00:00")
    enable_exact_cloud_review(store)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, stale.request_id, receipt_id="exact-stale-request"),
        )

    fresh = _request("exact-binding-drift")
    _add_request(store, fresh)
    enable_exact_cloud_review(store)
    capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(capability, dict)
    original_credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(original_credentials, dict)
    drift_approval = _remote_approval(store, fresh.request_id, receipt_id="exact-binding-drift")
    restored_approval = _remote_approval(store, fresh.request_id, receipt_id="exact-binding-restore")
    dpop = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="replacement-refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id="grant-2",
        machine_id="machine-2",
        device_id=dpop.public_jwk_thumbprint,
        workspace_id="workspace-2",
        now=datetime.now(timezone.utc).isoformat(),
    )
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_binding_mismatch"):
        apply_exact_cloud_review(
            store,
            remote_approval=drift_approval,
        )
    original_public_jwk = original_credentials["dpop_public_jwk"]
    assert isinstance(original_public_jwk, dict)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="restored-refresh-token",
        dpop_private_key_pem=str(original_credentials["dpop_private_key_pem"]),
        dpop_public_jwk={str(key): str(value) for key, value in original_public_jwk.items()},
        dpop_public_jwk_thumbprint=str(original_credentials["dpop_public_jwk_thumbprint"]),
        grant_id="grant-1",
        machine_id=str(original_credentials["machine_id"]),
        device_id=str(original_credentials["device_id"]),
        workspace_id="workspace-1",
        now=datetime.now(timezone.utc).isoformat(),
    )
    store.set_sync_payload("guard_exact_cloud_review_capability_v1", capability, datetime.now(timezone.utc).isoformat())
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revoked"):
        apply_exact_cloud_review(
            store,
            remote_approval=restored_approval,
        )


def test_exact_cloud_review_rejects_envelope_after_oauth_grant_rotation(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-grant-rotation")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    old_envelope = _remote_approval(store, request.request_id, receipt_id="exact-grant-1")
    old_job = _job(store, old_envelope)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    public_jwk = credentials["dpop_public_jwk"]
    assert isinstance(public_jwk, dict)
    store.set_oauth_local_credentials(
        issuer=str(credentials["issuer"]),
        client_id=str(credentials["client_id"]),
        refresh_token=str(credentials["refresh_token"]),
        dpop_private_key_pem=str(credentials["dpop_private_key_pem"]),
        dpop_public_jwk={str(key): str(value) for key, value in public_jwk.items()},
        dpop_public_jwk_thumbprint=str(credentials["dpop_public_jwk_thumbprint"]),
        grant_id="grant-2",
        machine_id=str(credentials["machine_id"]),
        device_id=str(credentials["device_id"]),
        workspace_id=str(credentials["workspace_id"]),
        now=datetime.now(timezone.utc).isoformat(),
    )
    enable_exact_cloud_review(store)

    with pytest.raises(CommandCapabilityError, match="remote_exact_job_wrong_grant"):
        authorize_command_queue_job(
            store,
            old_job,
            schema_versions=command_executor_module.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    with pytest.raises(ExactCloudReviewError, match="remote_exact_wrong_target"):
        apply_exact_cloud_review(store, remote_approval=old_envelope)


def test_exact_cloud_review_rechecks_active_dpop_keypair_inside_apply_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-dpop-race")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    envelope = _remote_approval(store, request.request_id, receipt_id="exact-dpop-race")
    original_resolve = store.resolve_one_request_with_signed_remote_exact_result

    def rotate_then_resolve(request_id: str, **kwargs: object) -> dict[str, object]:
        credentials = store.get_oauth_local_credentials(allow_primary=False)
        assert isinstance(credentials, dict)
        rotated = generate_dpop_key_pair()
        store.set_oauth_local_credentials(
            issuer=str(credentials["issuer"]),
            client_id=str(credentials["client_id"]),
            refresh_token=str(credentials["refresh_token"]),
            dpop_private_key_pem=rotated.private_key_pem,
            dpop_public_jwk=rotated.public_jwk,
            dpop_public_jwk_thumbprint=str(credentials["dpop_public_jwk_thumbprint"]),
            grant_id=str(credentials["grant_id"]),
            machine_id=str(credentials["machine_id"]),
            device_id=str(credentials["device_id"]),
            workspace_id=str(credentials["workspace_id"]),
            now=datetime.now(timezone.utc).isoformat(),
        )
        return original_resolve(request_id, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", rotate_then_resolve)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_oauth_changed"):
        apply_exact_cloud_review(store, remote_approval=envelope)


def test_exact_cloud_review_reuses_durable_remote_receipt_ledger(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-shared-receipt-ledger")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(store, request.request_id, receipt_id="exact-shared-receipt"),
    )
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select request_id from guard_exact_cloud_review_receipts where receipt_id = ?",
            ("exact-shared-receipt",),
        ).fetchone()
    assert row == (request.request_id,)


def test_connect_time_consent_provisions_exact_review_only_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_dispatch_cloud_review._refresh_cloud_review_worker",
        lambda _guard_home: {"running": True, "status": "refreshed"},
    )

    enabled = provision_connect_time_exact_cloud_review(
        args=Namespace(enable_exact_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )
    failed = provision_connect_time_exact_cloud_review(
        args=Namespace(enable_exact_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "error"},
        exit_code=1,
    )

    enabled_review = enabled.get("exact_cloud_review")
    assert isinstance(enabled_review, dict)
    assert enabled_review.get("enabled") is True
    worker = enabled_review.get("worker")
    assert isinstance(worker, dict) and worker.get("running") is True
    assert failed.get("exact_cloud_review") == {"enabled": False, "reason": "connect_not_completed"}
