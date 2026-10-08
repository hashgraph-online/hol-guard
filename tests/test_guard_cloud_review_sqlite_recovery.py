from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import sqlite_cloud_review_recovery as recovery
from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.review_event_wake import review_event_wake_signal
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_native_workspace_review import (
    NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def _prepare(tmp_path: Path) -> GuardStore:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store, password="cloud-review-native-test-pass")
    add_review_request(store, review_request("recover-pending"))
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into guard_exact_cloud_review_receipts values (?, ?, ?)",
            ("consumed-receipt", "resolved-request", datetime.now(timezone.utc).isoformat()),
        )
    return store


def _native_receipt(request_id: str) -> dict[str, object]:
    fields = (
        "claim_id",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "scope_binding",
        "request_binding",
        "action_binding",
        "intent_binding",
        "revision_binding",
        "policy_binding",
        "retry_scope_binding",
        "request_snapshot_digest",
        "authority_record_digest",
        "envelope_digest",
    )
    return {
        **{field: hashlib.sha256(field.encode()).hexdigest() for field in fields},
        "request_id": request_id,
        "decision": "allow",
        "status": "verified",
        "replayed": False,
    }


def _recover(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)
    monkeypatch.setattr(store_connection_schema, "restore_readable_sqlite_store", lambda **_kwargs: False)
    assert store._recover_fatal_sqlite_store(sqlite3.DatabaseError("database disk image is malformed"))


def test_recovery_preserves_identity_consent_pending_events_and_replay_barrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _prepare(tmp_path)
    identity = store.get_or_create_installation_id()
    capability = store.get_sync_payload("guard_exact_cloud_review_capability")
    now = datetime.now(timezone.utc).isoformat()
    before = store.list_ready_review_events(now=now, limit=100)
    signal = review_event_wake_signal(store.path)
    generation = signal.generation()
    _recover(store, monkeypatch)
    assert signal.generation() > generation
    restarted = GuardStore(store.guard_home)
    assert restarted.get_or_create_installation_id() == identity
    assert restarted.get_sync_payload("guard_exact_cloud_review_capability") == capability
    assert exact_cloud_review_status(restarted)["enabled"] is True
    assert restarted.has_exact_cloud_review_receipt("consumed-receipt")
    pending_request = restarted.get_approval_request("recover-pending")
    assert pending_request is not None
    assert pending_request["status"] == "pending"
    assert restarted.list_ready_review_events(now=now, limit=100) == before
    proof = remote_approval(restarted, "recover-pending", receipt_id="after-recovery")
    result = apply_exact_cloud_review(restarted, remote_approval=proof, expected_harness="codex")
    assert result.resolved_request["status"] == "resolved"


def test_recovery_preserves_bound_native_receipt_for_lost_ack_and_skips_corrupt_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _prepare(tmp_path)
    request = store.get_approval_request("recover-pending")
    assert request is not None
    receipt = _native_receipt("recover-pending")
    assert (
        store.resolve_native_workspace_review_request(
            "recover-pending",
            resolution_action="allow",
            expected_request=request,
            resolved_at="2026-09-27T00:00:00+00:00",
            native_replayed=False,
            native_receipt=receipt,
        )["resolved"]
        is True
    )
    for request_id in ("cross-request", "corrupt-request"):
        add_review_request(store, review_request(request_id))
        other = store.get_approval_request(request_id)
        assert other is not None
        assert (
            store.resolve_native_workspace_review_request(
                request_id,
                resolution_action="allow",
                expected_request=other,
                resolved_at="2026-09-27T00:00:00+00:00",
                native_replayed=False,
                native_receipt=_native_receipt(request_id),
            )["resolved"]
            is True
        )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            (
                json.dumps({**receipt, "request_id": "recover-pending"}),
                NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "cross-request",
            ),
        )
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            (
                "{malformed",
                NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "corrupt-request",
            ),
        )
    _recover(store, monkeypatch)
    restarted = GuardStore(store.guard_home)
    assert restarted.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "recover-pending") == receipt
    assert restarted.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "cross-request") is None
    assert restarted.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "corrupt-request") is None

    replay = {**receipt, "status": "replayed", "replayed": True}
    resolved = restarted.get_approval_request("recover-pending")
    assert resolved is not None
    result = restarted.resolve_native_workspace_review_request(
        "recover-pending",
        resolution_action="allow",
        expected_request=resolved,
        resolved_at="2026-09-27T00:01:00+00:00",
        native_replayed=True,
        native_receipt=replay,
    )
    assert result["resolved"] is True and result["replayed"] is True


def test_recovery_does_not_resurrect_revoked_consent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _prepare(tmp_path)
    disable_exact_cloud_review(store)
    revocation = store.get_sync_payload("guard_exact_cloud_review_revocation")
    _recover(store, monkeypatch)
    assert exact_cloud_review_status(store)["enabled"] is False
    assert store.get_sync_payload("guard_exact_cloud_review_revocation") == revocation
    assert store.has_exact_cloud_review_receipt("consumed-receipt")


@pytest.mark.parametrize(
    "table", ["sync_state", "guard_exact_cloud_review_receipts", "guard_review_outbox_request_sequences"]
)
def test_incomplete_recovery_never_restores_authority(tmp_path: Path, table: str) -> None:
    store = _prepare(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute(f'drop table "{table}"')
    destination = GuardStore(tmp_path / "new")
    assert recovery.salvage_cloud_review_state(source=store.path, destination=destination.path) is False
    assert destination.get_sync_payload("oauth_local_credentials") is None
    assert destination.get_sync_payload("guard_exact_cloud_review_capability") is None
    assert destination.get_approval_request("recover-pending") is None


def test_partial_replay_copy_rolls_back_everything(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _prepare(tmp_path)
    destination = GuardStore(tmp_path / "new")
    identity = destination.get_or_create_installation_id()
    copy = recovery._copy_complete_table

    def fail_after_receipts(src: sqlite3.Connection, dst: sqlite3.Connection, table: str) -> None:
        copy(src, dst, table)
        if table == "guard_exact_cloud_review_receipts":
            raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(recovery, "_copy_complete_table", fail_after_receipts)
    assert not recovery.salvage_cloud_review_state(source=source.path, destination=destination.path)
    assert destination.get_or_create_installation_id() == identity
    assert destination.get_sync_payload("oauth_local_credentials") is None
    assert not destination.has_exact_cloud_review_receipt("consumed-receipt")


def test_recovery_refuses_nonempty_destination(tmp_path: Path) -> None:
    source = _prepare(tmp_path)
    destination = connected_exact_review_store(tmp_path / "different")
    identity = destination.get_or_create_installation_id()
    assert not recovery.salvage_cloud_review_state(source=source.path, destination=destination.path)
    assert destination.get_or_create_installation_id() == identity
    assert destination.get_sync_payload("guard_exact_cloud_review_capability") is None


def test_committed_connection_changes_wake_delivery_but_unrelated_state_does_not(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    signal = review_event_wake_signal(store.path)
    payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(payload, dict)
    generation = signal.generation()
    store.set_sync_payload("oauth_local_credentials", payload, datetime.now(timezone.utc).isoformat())
    assert signal.generation() > generation
    generation = signal.generation()
    store.set_sync_payload("unrelated-sync-counter", {"count": 1}, datetime.now(timezone.utc).isoformat())
    assert signal.generation() == generation


@pytest.mark.parametrize("missing_column", ["guard_version", "dedupe_count", "action_envelope_json"])
def test_prior_schema_only_defaults_known_presentation_columns(
    tmp_path: Path, missing_column: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _prepare(tmp_path)
    with sqlite3.connect(source.path) as connection:
        triggers = connection.execute(
            "select name from sqlite_master where type = 'trigger' and tbl_name = 'approval_requests'"
        ).fetchall()
        for (name,) in triggers:
            connection.execute('drop trigger "' + name.replace('"', '""') + '"')
        connection.execute(f'alter table approval_requests drop column "{missing_column}"')
    _recover(source, monkeypatch)
    destination = GuardStore(source.guard_home)
    assert source._last_sqlite_recovery_details is not None
    recovered = source._last_sqlite_recovery_details["cloud_review"]
    assert recovered is (missing_column != "action_envelope_json")
    if recovered:
        assert exact_cloud_review_status(destination)["enabled"] is True
        assert destination.has_exact_cloud_review_receipt("consumed-receipt")
        request = destination.get_approval_request("recover-pending")
        assert request is not None
        assert request[missing_column] == (1 if missing_column == "dedupe_count" else None)
    else:
        assert destination.get_sync_payload("guard_exact_cloud_review_capability") is None


def test_independent_cli_recovery_failure_does_not_discard_complete_review_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _prepare(tmp_path)
    monkeypatch.setattr(store_connection_schema, "salvage_local_cli_state", lambda **_kwargs: False)
    _recover(store, monkeypatch)
    assert exact_cloud_review_status(store)["enabled"] is True
    assert store._last_sqlite_recovery_details == {"cloud_review": True, "local_cli": False}
    assert not store._recover_fatal_sqlite_store(ValueError("not a storage failure"))
    assert store._last_sqlite_recovery == "skipped"
    assert store._last_sqlite_recovery_details is None


def test_partial_cloud_salvage_persists_recovery_health_without_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(recovery, "salvage_cloud_review_state", lambda **_kwargs: False)
    monkeypatch.setattr(store_connection_schema, "salvage_local_cli_state", lambda **_kwargs: True)
    recorded_now: list[object] = []
    original_persist = recovery.persist_cloud_review_recovery_health

    def persist_and_record(store: object, *, cloud_review: bool, local_cli: bool, now: str) -> None:
        recorded_now.append(now)
        original_persist(store, cloud_review=cloud_review, local_cli=local_cli, now=now)

    monkeypatch.setattr(recovery, "persist_cloud_review_recovery_health", persist_and_record)
    _recover(store, monkeypatch)
    assert recorded_now
    assert all(isinstance(value, str) for value in recorded_now)
    assert store._last_sqlite_recovery_details == {"cloud_review": False, "local_cli": True}
    assert store.get_sync_payload("oauth_local_credentials") is None
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    health = recovery.read_cloud_review_recovery_health(store)
    assert health is not None
    assert health["reason"] == "cloud_review_salvage_failed"
    assert health["repair"] == "authenticated_current_binding"
    assert health["summary"] == recovery.PARTIAL_CLOUD_RECOVERY_DETAIL
    store.set_sync_payload(
        recovery.RECOVERY_HEALTH_STATE_KEY,
        {**health, "summary": "do not display stored text"},
        "2026-10-04T05:00:00+00:00",
    )
    assert recovery.read_cloud_review_recovery_health(store) == health
    store.set_sync_payload(
        recovery.RECOVERY_HEALTH_STATE_KEY,
        {**health, "reason": "cloud_review_restored"},
        "2026-10-04T05:00:01+00:00",
    )
    assert recovery.read_cloud_review_recovery_health(store) is None
    store.set_sync_payload(recovery.RECOVERY_HEALTH_STATE_KEY, health, "2026-10-04T05:00:02+00:00")
    reopened = GuardStore(store.guard_home)
    assert recovery.read_cloud_review_recovery_health(reopened) == health
    from codex_plugin_scanner.guard.approvals import _build_runtime_cloud_context

    context = _build_runtime_cloud_context(reopened, None)
    assert context["cloud_state_detail"] == recovery.PARTIAL_CLOUD_RECOVERY_DETAIL
    assert context["cloud_pairing_state"]["detail"] == recovery.PARTIAL_CLOUD_RECOVERY_DETAIL
    assert context["cloud_review_recovery"] == health
    assert context["cloud_review_recovery_repair"] == {
        "reason": "oauth_binding_missing",
        "status": "authentication_required",
    }


def test_incomplete_local_recovery_is_not_confirmed_as_cloud_repair() -> None:
    class _Store:
        def __init__(self) -> None:
            self.payloads: dict[str, object] = {
                recovery.RECOVERY_HEALTH_STATE_KEY: recovery.cloud_review_recovery_health(
                    cloud_review=False,
                    local_cli=False,
                )
            }

        def get_sync_payload(self, key: str) -> object:
            return self.payloads.get(key)

        def set_sync_payload(self, key: str, payload: object, now: str) -> None:
            del now
            self.payloads[key] = payload

        def get_review_event_oauth_binding(self) -> dict[str, str] | None:
            raise AssertionError("incomplete recovery must not read OAuth")

    store = _Store()
    health = store.payloads[recovery.RECOVERY_HEALTH_STATE_KEY]
    assert isinstance(health, dict)
    assert health["summary"] == recovery.INCOMPLETE_CLOUD_RECOVERY_DETAIL
    assert "Local protection is working" not in str(health["summary"])
    result = recovery.complete_authenticated_current_binding_repair(store, now="2026-10-04T05:00:00+00:00")
    assert result == {"status": "recovery_incomplete", "reason": "local_recovery_incomplete"}
    assert recovery.read_cloud_review_recovery_repair(store) == result
    assert recovery.REPAIR_ATTEMPT_STATE_KEY not in store.payloads
    recovery.note_authenticated_cloud_review_round_trip(store, now="2026-10-04T05:00:02+00:00")
    restored = recovery.read_cloud_review_recovery_health(store)
    assert restored is not None
    assert restored["reason"] == "cloud_review_restored"
    assert restored["localCli"] is False
    assert recovery.read_cloud_review_recovery_repair(store) == {
        "status": "not_required",
        "reason": "no_pending_repair",
    }
    assert recovery.REPAIR_ATTEMPT_STATE_KEY not in store.payloads


def test_authenticated_current_binding_repair_does_not_create_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(recovery, "salvage_cloud_review_state", lambda **_kwargs: False)
    monkeypatch.setattr(store_connection_schema, "salvage_local_cli_state", lambda **_kwargs: True)
    _recover(store, monkeypatch)
    installation_id = "11111111-1111-4111-8111-111111111111"
    workspace_id = "22222222-2222-4222-8222-222222222222"
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into guard_exact_cloud_review_receipts values (?, ?, ?)",
            ("consumed-receipt", "resolved-request", "2026-10-04T05:00:00+00:00"),
        )
    store.set_sync_payload(
        "guard_exact_cloud_review_revocation",
        {"marker": "keep"},
        "2026-10-04T05:00:00+00:00",
    )
    waiting = recovery.complete_authenticated_current_binding_repair(store, now="2026-10-04T05:01:00+00:00")
    assert waiting == {"status": "authentication_required", "reason": "oauth_binding_missing"}
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    store.set_sync_payload(
        "oauth_local_credentials",
        {
            "grant_id": "grant-1",
            "workspace_id": workspace_id,
            "machine_id": "machine-1",
            "installation_id": "33333333-3333-4333-8333-333333333333",
        },
        "2026-10-04T05:02:00+00:00",
    )
    with store._connect() as connection:
        updated = connection.execute(
            "update guard_devices set installation_id = ? where device_key = 'local-device'",
            (installation_id,),
        )
        assert updated.rowcount == 1
    mismatch = recovery.complete_authenticated_current_binding_repair(store, now="2026-10-04T05:03:00+00:00")
    assert mismatch == {"status": "binding_mismatch", "reason": "installation_disagrees"}
    assert store.get_sync_payload(recovery.REPAIR_ATTEMPT_STATE_KEY) is None
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "grant-1", "workspace_id": workspace_id, "machine_id": "machine-1"},
        "2026-10-04T05:04:00+00:00",
    )
    confirmed = recovery.complete_authenticated_current_binding_repair(store, now="2026-10-04T05:05:00+00:00")
    assert confirmed == {"status": "completed", "reason": "current_binding_confirmed"}
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    assert store.get_sync_payload("guard_exact_cloud_review_revocation") == {"marker": "keep"}
    with sqlite3.connect(store.path) as connection:
        kept = connection.execute(
            "select request_id from guard_exact_cloud_review_receipts where receipt_id = ?",
            ("consumed-receipt",),
        ).fetchone()
    assert kept == ("resolved-request",)
    repeated = recovery.complete_authenticated_current_binding_repair(store, now="2026-10-04T05:06:00+00:00")
    assert repeated == confirmed
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    reopened = GuardStore(store.guard_home)
    monkeypatch.setattr(
        reopened,
        "get_oauth_local_credential_health",
        lambda: {"configured": False, "state": "not_configured"},
    )
    monkeypatch.setattr(reopened, "get_oauth_local_credentials", lambda **_kwargs: None)
    from codex_plugin_scanner.guard.approvals import _build_runtime_cloud_context

    context = _build_runtime_cloud_context(reopened, None)
    assert context["cloud_state_detail"] != recovery.PARTIAL_CLOUD_RECOVERY_DETAIL
    assert context["cloud_review_recovery_repair"] == {
        "reason": "current_binding_confirmed",
        "status": "completed",
    }
    assert reopened.get_sync_payload("guard_exact_cloud_review_capability") is None


def _request_sequence(store: GuardStore, request_id: str) -> int:
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
            (request_id,),
        ).fetchone()
    assert row is not None
    return int(row[0])


def test_cli_status_names_partial_cloud_recovery_instead_of_local_only(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.product import _build_cloud_context

    untouched = GuardStore(tmp_path / "local")
    local = _build_cloud_context(untouched)
    assert "Guard Cloud is optional" in str(local["cloud_state_detail"])
    assert local["cloud_review_recovery"] is None
    assert local["cloud_review_recovery_repair"] == {
        "status": "not_required",
        "reason": "no_pending_repair",
    }

    recovered = GuardStore(tmp_path / "recovered")
    recovered.set_sync_payload(
        recovery.RECOVERY_HEALTH_STATE_KEY,
        recovery.cloud_review_recovery_health(cloud_review=False, local_cli=True),
        "2026-10-04T05:00:00+00:00",
    )
    status = _build_cloud_context(recovered)
    assert status["cloud_state_detail"] == recovery.PARTIAL_CLOUD_RECOVERY_DETAIL
    assert status["cloud_review_recovery"]["reason"] == "cloud_review_salvage_failed"
    assert status["cloud_review_recovery"]["repair"] == "authenticated_current_binding"
    assert status["cloud_review_recovery_repair"] == {
        "status": "authentication_required",
        "reason": "oauth_binding_missing",
    }
    assert status["cloud_review_recovery"]["cloudReview"] is False
    assert recovered.get_sync_payload("guard_exact_cloud_review_capability") is None
    assert recovered.get_sync_payload(recovery.REPAIR_ATTEMPT_STATE_KEY) is None

    incomplete = GuardStore(tmp_path / "incomplete")
    incomplete.set_sync_payload(
        recovery.RECOVERY_HEALTH_STATE_KEY,
        recovery.cloud_review_recovery_health(cloud_review=False, local_cli=False),
        "2026-10-04T05:00:00+00:00",
    )
    incomplete_status = _build_cloud_context(incomplete)
    assert incomplete_status["cloud_state_detail"] == recovery.INCOMPLETE_CLOUD_RECOVERY_DETAIL
    assert "Local protection is working" not in str(incomplete_status["cloud_state_detail"])


def test_cli_status_does_not_record_a_matching_binding_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli.product import _build_cloud_context

    store = GuardStore(tmp_path / "status")
    store.set_sync_payload(
        recovery.RECOVERY_HEALTH_STATE_KEY,
        recovery.cloud_review_recovery_health(cloud_review=False, local_cli=True),
        "2026-10-04T05:00:00+00:00",
    )
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "grant-1", "workspace_id": "22222222-2222-4222-8222-222222222222", "machine_id": "machine-1"},
        "2026-10-04T05:00:00+00:00",
    )

    def refuse_completion(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("status must not record a Cloud repair")

    monkeypatch.setattr(recovery, "complete_authenticated_current_binding_repair", refuse_completion)
    status = _build_cloud_context(store)
    assert status["cloud_review_recovery_repair"]["status"] != "completed"
    assert store.get_sync_payload(recovery.REPAIR_ATTEMPT_STATE_KEY) is None


def test_upgrade_and_harness_restart_keep_consumed_revoked_and_replay_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schema upgrade and corrupt salvage must not reapply a consumed decision."""

    from codex_plugin_scanner.guard.runtime import command_queue
    from codex_plugin_scanner.guard.runtime.command_capability import COMMAND_REPLAY_STATE_KEY
    from codex_plugin_scanner.guard.store_review_event_outbox_schema import (
        REVIEW_EVENT_OUTBOX_MIGRATION_VERSION,
    )
    from tests.guard_cloud_review_hardening_support import exact_job_store, harness_context

    request_id = "upgrade-recover"
    receipt_id = f"{request_id}-receipt"
    store, job = exact_job_store(tmp_path, request_id=request_id)

    def transport(
        _auth: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        del method, payload
        if path == "/lease":
            return {"item": job, "protocolVersion": 2}
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_exact_json_request", transport)
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {"access_token": "token", "sync_url": "https://guard.example"},
    )
    assert command_queue.poll_command_queue_once(store, harness_context(tmp_path))["state"] == "idle"
    assert len(store.list_events(event_name="cloud_review.exact_used")) == 1
    assert store.has_exact_cloud_review_receipt(receipt_id)
    replay = store.get_sync_payload(COMMAND_REPLAY_STATE_KEY)
    assert isinstance(replay, dict) and replay.get("items")

    with sqlite3.connect(store.path) as connection:
        updated = connection.execute(
            "update guard_review_outbox_request_sequences set last_sequence = 7 where local_request_id = ?",
            (request_id,),
        )
        assert updated.rowcount == 1
        triggers = connection.execute(
            "select name from sqlite_master where type = 'trigger' and "
            "(tbl_name = 'guard_review_outbox_request_sequences' or name like 'guard_review_outbox_after_%')"
        ).fetchall()
        for (name,) in triggers:
            connection.execute('drop trigger "' + str(name).replace('"', '""') + '"')
        connection.execute("alter table guard_review_outbox_request_sequences drop column oauth_source")
        connection.execute(
            "delete from schema_migrations where version = ?",
            (REVIEW_EVENT_OUTBOX_MIGRATION_VERSION,),
        )

    upgraded = GuardStore(store.guard_home)
    assert _request_sequence(upgraded, request_id) == 7
    with sqlite3.connect(upgraded.path) as connection:
        columns = {
            str(row[1]) for row in connection.execute("pragma table_info(guard_review_outbox_request_sequences)")
        }
    assert "oauth_source" in columns
    assert upgraded.get_sync_payload(COMMAND_REPLAY_STATE_KEY) == replay
    assert upgraded.has_exact_cloud_review_receipt(receipt_id)

    _recover(upgraded, monkeypatch)
    recovered = GuardStore(upgraded.guard_home)
    assert _request_sequence(recovered, request_id) == 7
    assert recovered.get_sync_payload(COMMAND_REPLAY_STATE_KEY) == replay
    assert recovered.has_exact_cloud_review_receipt(receipt_id)
    resolved = recovered.get_approval_request(request_id)
    assert resolved is not None and resolved["status"] == "resolved"
    assert len(recovered.list_events(event_name="cloud_review.exact_used")) == 0

    assert command_queue.poll_command_queue_once(recovered, harness_context(tmp_path))["state"] == "idle"
    assert len(recovered.list_events(event_name="cloud_review.exact_used")) == 0
    assert _request_sequence(recovered, request_id) == 7
    assert recovered.get_sync_payload(COMMAND_REPLAY_STATE_KEY) == replay
    assert recovered.has_exact_cloud_review_receipt(receipt_id)
    still_resolved = recovered.get_approval_request(request_id)
    assert still_resolved is not None and still_resolved["status"] == "resolved"

    disable_exact_cloud_review(recovered)
    revocation = recovered.get_sync_payload("guard_exact_cloud_review_revocation")
    assert isinstance(revocation, dict) and revocation.get("revokedAt")
    _recover(recovered, monkeypatch)
    revoked = GuardStore(recovered.guard_home)
    assert revoked.get_sync_payload("guard_exact_cloud_review_revocation") == revocation
    assert revoked.get_sync_payload("guard_exact_cloud_review_capability") is None
    assert exact_cloud_review_status(revoked)["enabled"] is False
    assert _request_sequence(revoked, request_id) == 7
    assert revoked.get_sync_payload(COMMAND_REPLAY_STATE_KEY) == replay
    assert revoked.has_exact_cloud_review_receipt(receipt_id)
    assert len(revoked.list_events(event_name="cloud_review.exact_used")) == 0
