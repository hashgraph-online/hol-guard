from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import (
    COMMAND_CAPABILITY_STATE_KEY,
    LOCAL_CONFIRMATION_COMMAND_OPERATIONS,
    READ_ONLY_COMMAND_OPERATIONS,
    STATE_CHANGING_COMMAND_OPERATIONS,
    CommandCapabilityError,
    approve_pending_command,
    authorize_command_job,
    command_capability_status,
    consume_local_command_approval,
    issue_command_capability,
    mark_command_job_consumed,
    pending_command_approvals,
    register_pending_command,
    revoke_command_capability,
)
from codex_plugin_scanner.guard.runtime.command_executors import (
    COMMAND_OPERATION_SCHEMA_VERSIONS,
    SUPPORTED_COMMAND_OPERATIONS,
)
from codex_plugin_scanner.guard.store import GuardStore


def _connected_store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    installation_id = store.get_device_metadata()["installation_id"]
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id=installation_id,
        workspace_id="workspace-1",
        now=datetime.now(timezone.utc).isoformat(),
    )
    return store


def _issue(store: GuardStore, *operations: str) -> dict[str, object]:
    return issue_command_capability(
        store,
        operations=tuple(operations),
        supported_operations=SUPPORTED_COMMAND_OPERATIONS,
    )


def _job(
    store: GuardStore,
    operation: str = "guard.packageShims.status",
    *,
    job_id: str = "job-1",
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert credentials is not None
    return {
        "id": job_id,
        "leaseId": f"lease-{job_id}",
        "operation": operation,
        "schemaVersion": COMMAND_OPERATION_SCHEMA_VERSIONS[operation],
        "deviceId": credentials["machine_id"],
        "workspaceId": credentials["workspace_id"],
        "nonce": f"nonce-{job_id}",
        "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "idempotencyKey": f"idempotency-{job_id}",
        "payload": {} if payload is None else payload,
    }


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path,
        workspace_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )


def test_command_channel_defaults_off_and_environment_cannot_enable_it(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)

    assert command_queue.command_queue_enabled(store, environ={}) is False
    assert (
        command_queue.command_queue_enabled(
            store,
            environ={command_queue.COMMAND_QUEUE_ENABLED_ENV: "true"},
        )
        is False
    )
    assert command_capability_status(store)["enabled"] is False


def test_environment_opt_out_pauses_but_does_not_destroy_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "false")

    status = command_capability_status(store)

    assert status["enabled"] is False
    assert status["capability_valid"] is True
    assert status["reason"] == "command_queue_environment_disabled"
    assert status["operations"] == ["guard.packageShims.status"]
    assert command_queue.command_queue_enabled(store) is False


def test_capability_rejects_future_issue_time_and_empty_issuer(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    current = datetime.now(timezone.utc)

    with pytest.raises(CommandCapabilityError, match="capability_issuer_required"):
        issue_command_capability(
            store,
            operations=("guard.packageShims.status",),
            supported_operations=SUPPORTED_COMMAND_OPERATIONS,
            issuer=" ",
        )

    issue_command_capability(
        store,
        operations=("guard.packageShims.status",),
        supported_operations=SUPPORTED_COMMAND_OPERATIONS,
        now=(current + timedelta(minutes=10)).isoformat(),
    )

    status = command_capability_status(store, now=current.isoformat())
    assert status["enabled"] is False
    assert status["reason"] == "capability_issued_in_future"


def test_every_supported_operation_has_one_local_side_effect_classification() -> None:
    classified = (
        set(READ_ONLY_COMMAND_OPERATIONS)
        | set(LOCAL_CONFIRMATION_COMMAND_OPERATIONS)
        | set(STATE_CHANGING_COMMAND_OPERATIONS)
    )

    assert classified == set(SUPPORTED_COMMAND_OPERATIONS)
    assert not (set(READ_ONLY_COMMAND_OPERATIONS) & set(STATE_CHANGING_COMMAND_OPERATIONS))


def test_existing_review_capability_implies_mfa_gated_sync_repair(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    status = _issue(
        store,
        "guard.approval.resolve",
        "guard.localRequests.snapshot",
    )

    operations = status["operations"]
    assert isinstance(operations, list)
    assert "guard.liveRequests.reassignQuarantined" in operations


def test_snapshot_only_capability_does_not_imply_sync_repair(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    status = _issue(store, "guard.localRequests.snapshot")

    operations = status["operations"]
    assert isinstance(operations, list)
    assert "guard.liveRequests.reassignQuarantined" not in operations


def test_mfa_gated_sync_repair_does_not_require_a_second_local_approval(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    _issue(
        store,
        "guard.approval.resolve",
        "guard.localRequests.snapshot",
    )
    authorized = authorize_command_job(
        store,
        _job(
            store,
            "guard.liveRequests.reassignQuarantined",
            payload={
                "source": "default",
                "workspaceId": "workspace-1",
            },
        ),
        schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
    )

    assert authorized.requires_local_approval is False


def test_capability_is_signed_exact_revocable_and_does_not_disable_sync(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {"state": "result_pending", "pending_result": {"legacy": True}},
        datetime.now(timezone.utc).isoformat(),
    )
    status = _issue(store, *READ_ONLY_COMMAND_OPERATIONS)

    assert status["enabled"] is True
    assert store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY) is None
    assert status["operations"] == sorted(READ_ONLY_COMMAND_OPERATIONS)
    assert command_queue.command_queue_enabled(store, environ={}) is True

    stored = store.get_sync_payload(COMMAND_CAPABILITY_STATE_KEY)
    assert isinstance(stored, dict)
    store.set_sync_payload(
        COMMAND_CAPABILITY_STATE_KEY,
        {**stored, "operations": ["guard.app.update"]},
        datetime.now(timezone.utc).isoformat(),
    )
    tampered = command_capability_status(store)
    assert tampered["enabled"] is False
    assert tampered["reason"] == "signed_payload_invalid_signature"

    _issue(store, "guard.packageShims.status")
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {"state": "leased", "active_job": {"id": "job-before-revoke"}},
        datetime.now(timezone.utc).isoformat(),
    )
    revoked = revoke_command_capability(store)
    assert revoked["enabled"] is False
    assert store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY) is None
    assert store.get_cloud_sync_profile() is not None
    assert store.get_oauth_local_credentials(allow_primary=False) is not None


def test_disconnect_revokes_command_capability(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {"state": "result_pending", "pending_result": {"job": {"id": "job-1"}}},
        datetime.now(timezone.utc).isoformat(),
    )

    store.clear_oauth_local_credentials()

    assert store.get_sync_payload(COMMAND_CAPABILITY_STATE_KEY) is None
    assert store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY) is None
    assert command_queue.command_queue_enabled(store, environ={}) is False


def test_job_authorization_binds_target_schema_payload_expiry_and_replay(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    job = _job(store, payload={"detail": "summary"})

    authorized = authorize_command_job(
        store,
        job,
        schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
    )
    assert authorized.requires_local_approval is False
    assert consume_local_command_approval(store, authorized) is True
    mark_command_job_consumed(store, authorized)

    with pytest.raises(CommandCapabilityError, match="command_replayed"):
        authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)

    changed_payload = {**job, "payload": {"detail": "changed"}}
    with pytest.raises(CommandCapabilityError, match="command_replayed"):
        authorize_command_job(
            store,
            changed_payload,
            schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
        )

    wrong_device = {**_job(store, job_id="job-2"), "deviceId": "another-device"}
    with pytest.raises(CommandCapabilityError, match="command_device_mismatch"):
        authorize_command_job(store, wrong_device, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)

    expired = {
        **_job(store, job_id="job-3"),
        "expiresAt": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
    }
    with pytest.raises(CommandCapabilityError, match="command_expired"):
        authorize_command_job(store, expired, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)


def test_state_change_requires_exact_single_use_local_approval(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(
        store,
        job,
        schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
    )

    assert authorized.requires_local_approval is True
    assert consume_local_command_approval(store, authorized) is False
    pending = register_pending_command(store, authorized, job)
    assert pending["id"] == "job-1"
    assert pending_command_approvals(store)[0]["operation"] == operation

    result = approve_pending_command(store, "job-1")
    assert result["approved"] is True

    changed_job = {**job, "payload": {"channel": "preview"}}
    changed_authorization = authorize_command_job(
        store,
        changed_job,
        schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
    )
    assert consume_local_command_approval(store, changed_authorization) is False
    assert consume_local_command_approval(store, authorized) is True
    assert consume_local_command_approval(store, authorized) is False


def test_poll_is_network_silent_when_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store: pytest.fail("disabled queue attempted OAuth or network access"),
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["enabled"] is False
    assert status["state"] == "disabled"


def test_queue_rejects_ungranted_job_without_executing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    leased = _job(store, "guard.app.update")
    calls: list[tuple[str, str, dict[str, object]]] = []

    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, **_kwargs: {"sync_url": "https://hol.test/sync"},
    )

    def request(
        _auth: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append((method, path, payload))
        return {"item": leased} if path == "/lease" else {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", request)
    monkeypatch.setattr(
        command_queue,
        "_execute_job",
        lambda *_args, **_kwargs: pytest.fail("ungranted job reached its executor"),
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    result = next(payload for _method, path, payload in calls if path.endswith("/result"))
    assert result["status"] == "failed"
    assert result["failureCode"] == "command_operation_not_granted"
    assert store.list_events(event_name="cloud_command.rejected")


def test_cli_and_runtime_snapshot_surface_capability_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = _connected_store(tmp_path)
    guard_home = store.guard_home

    result = main(
        [
            "guard",
            "commands",
            "enable",
            "--guard-home",
            str(guard_home),
            "--operations",
            "read-only",
            "--json",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "enabled"
    assert payload["capability"]["enabled"] is True
    snapshot = build_runtime_snapshot(store=store, approval_center_url=None)
    capability = snapshot["cloud_command_capability"]
    assert isinstance(capability, dict)
    assert capability["enabled"] is True
    assert capability["pending_commands"] == []
