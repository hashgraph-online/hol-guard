from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import build_runtime_snapshot
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.native_command_envelope import CommandEnvelopeUnavailableError
from codex_plugin_scanner.guard.runtime import command_capability as command_capability_module
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import (
    COMMAND_CAPABILITY_STATE_KEY,
    COMMAND_LOCAL_APPROVALS_STATE_KEY,
    COMMAND_REPLAY_STATE_KEY,
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
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _capability_runtime(native_command_capability_runtime: Path) -> None:
    """Every capability verdict asserted here comes from the compiled runtime."""


def _connected_store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    machine_id = "machine-device-command-capability"
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        device_id=dpop.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id=machine_id,
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
        "deviceId": credentials["device_id"],
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


def test_capability_uses_distinct_machine_and_local_installation_bindings(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    assert credentials["machine_id"] != store.get_device_metadata()["installation_id"]

    status = _issue(store, "guard.packageShims.status")

    assert status["enabled"] is True


def test_capability_rejects_local_installation_binding_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    local_metadata = store.get_device_metadata()
    monkeypatch.setattr(
        store,
        "get_device_metadata",
        lambda: {**local_metadata, "installation_id": "unexpected-local-installation"},
    )

    with pytest.raises(CommandCapabilityError, match="cloud_device_binding_mismatch"):
        _issue(store, "guard.packageShims.status")


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

    assert classified == set(SUPPORTED_COMMAND_OPERATIONS) - {EXACT_CLOUD_REVIEW_OPERATION}
    assert EXACT_CLOUD_REVIEW_OPERATION not in classified
    assert not (set(READ_ONLY_COMMAND_OPERATIONS) & set(STATE_CHANGING_COMMAND_OPERATIONS))


def test_retired_cloud_review_operations_are_not_advertised_or_authorizable(tmp_path: Path) -> None:
    retired_operations = (
        "guard.approval.resolve",
        "guard.localRequests.snapshot",
        "guard.liveRequests.reassignQuarantined",
    )
    classified = (
        set(READ_ONLY_COMMAND_OPERATIONS)
        | set(LOCAL_CONFIRMATION_COMMAND_OPERATIONS)
        | set(STATE_CHANGING_COMMAND_OPERATIONS)
    )
    assert not (set(retired_operations) & set(SUPPORTED_COMMAND_OPERATIONS))
    assert not (set(retired_operations) & classified)

    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    for index, operation in enumerate(retired_operations):
        job = _job(store, job_id=f"retired-job-{index}")
        job["operation"] = operation
        with pytest.raises(CommandCapabilityError, match="command_operation_unsupported"):
            authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)


def test_signed_pre_cutover_capability_preserves_supported_operations(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    stored = store.get_sync_payload(COMMAND_CAPABILITY_STATE_KEY)
    assert isinstance(stored, dict)
    unsigned = {str(key): value for key, value in stored.items() if key not in {"keyId", "signature"}}
    unsigned["operations"] = ["guard.packageShims.status", "guard.approval.resolve"]
    migrated_capability = command_capability_module._signed_payload(store, unsigned, create_key=False)
    store.set_sync_payload(
        COMMAND_CAPABILITY_STATE_KEY,
        migrated_capability,
        datetime.now(timezone.utc).isoformat(),
    )

    status = command_capability_status(store)

    assert status["enabled"] is True
    assert status["capability_valid"] is True
    assert status["operations"] == ["guard.packageShims.status"]
    assert command_queue.command_queue_enabled(store, environ={}) is True


def test_policy_memory_capability_requires_its_own_local_confirmation(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.review.syncPolicyMemory")

    authorized = authorize_command_job(
        store,
        _job(store, "guard.review.syncPolicyMemory", payload={"decisionMemoryBundle": {}}),
        schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
    )

    assert authorized.requires_local_approval is True


def test_policy_memory_capability_cannot_be_combined_with_routine_operations(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)

    with pytest.raises(CommandCapabilityError, match="policy_memory_capability_must_be_isolated"):
        issue_command_capability(
            store,
            operations=("guard.packageShims.status", "guard.review.syncPolicyMemory"),
            supported_operations=SUPPORTED_COMMAND_OPERATIONS,
        )


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


def test_an_identity_digest_does_not_ship_the_signing_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    register_pending_command(store, authorized, job)
    real = command_capability_module.native_command_envelope
    calls: list[tuple[str, str | None]] = []

    def recorded(**kwargs: object) -> dict[str, object]:
        calls.append((str(kwargs["action"]), kwargs["integrity_key_b64"]))  # type: ignore[arg-type]
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_envelope", recorded)

    assert approve_pending_command(store, "job-1")["approved"] is True

    digested = [key for action, key in calls if action == "digest"]
    signed = [key for action, key in calls if action == "sign"]
    assert digested and all(key is None for key in digested)
    assert signed and all(key is not None for key in signed)


def test_an_unanswered_runtime_refuses_an_approval_as_a_capability_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    register_pending_command(store, authorized, job)

    def unavailable(**_kwargs: object) -> dict[str, object]:
        raise CommandEnvelopeUnavailableError

    monkeypatch.setattr(command_capability_module, "native_command_envelope", unavailable)

    with pytest.raises(CommandCapabilityError, match=CommandEnvelopeUnavailableError.reason):
        approve_pending_command(store, "job-1")


def test_an_unanswered_runtime_never_reads_a_grant_as_unmatched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    register_pending_command(store, authorized, job)
    assert approve_pending_command(store, "job-1")["approved"] is True
    real = command_capability_module.native_command_envelope

    answering = [False]

    def unavailable_for_verify(**kwargs: object) -> dict[str, object]:
        if not answering[0] and kwargs.get("action") == "verify":
            raise CommandEnvelopeUnavailableError
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_envelope", unavailable_for_verify)

    # Walking past the unanswered grant would read as "no approval on file"
    # and spend the user's approval without running the job.
    with pytest.raises(CommandCapabilityError, match=CommandEnvelopeUnavailableError.reason):
        consume_local_command_approval(store, authorized)

    answering[0] = True
    assert consume_local_command_approval(store, authorized) is True


def test_pending_approval_rejects_nonportable_cloud_job_id(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job_id = "job-$(touch /opt/guard-test/unsafe)"
    job = _job(store, operation, job_id=job_id, payload={"channel": "stable"})
    with pytest.raises(CommandCapabilityError, match="command_id_invalid"):
        authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)


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


def test_an_approval_is_never_spent_against_a_digest_the_runtime_has_not_given(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One digest serves both the grant match and the replay row.

    The poll used to ask for it twice: once to find the grant it deletes, and
    again to write the replay row. A resident that stopped answering between
    the two failed the job with the user's approval already gone, so the next
    attempt asked them to approve it a second time.
    """

    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    leased = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, leased, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    register_pending_command(store, authorized, leased)
    assert approve_pending_command(store, "job-1")["approved"] is True

    real = command_capability_module.native_command_envelope
    digests = [0]

    def one_digest_only(**kwargs: object) -> dict[str, object]:
        if kwargs.get("action") == "digest":
            digests[0] += 1
            if digests[0] > 1:
                raise CommandEnvelopeUnavailableError
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_envelope", one_digest_only)
    calls: list[tuple[str, dict[str, object]]] = []

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
        calls.append((path, payload))
        return {"item": leased} if path == "/lease" else {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", request)
    monkeypatch.setattr(command_queue, "_execute_job", lambda *_args, **_kwargs: {"data": {"ok": True}})

    command_queue.poll_command_queue_once(store, _context(tmp_path))

    result = next(payload for path, payload in calls if path.endswith("/result"))
    assert result["status"] == "succeeded"
    assert digests[0] == 1
    grants = store.get_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY)
    assert isinstance(grants, dict) and grants["items"] == []
    replay = store.get_sync_payload(COMMAND_REPLAY_STATE_KEY)
    assert isinstance(replay, dict)
    assert [item["jobId"] for item in replay["items"]] == ["job-1"]
