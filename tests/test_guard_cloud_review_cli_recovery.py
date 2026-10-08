from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import sqlite_cloud_review_recovery as recovery
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    disable_exact_cloud_review,
    exact_cloud_review_status,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_cloud_review_sqlite_recovery import _recover


def _request_sequence(store: GuardStore, request_id: str) -> int:
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
            (request_id,),
        ).fetchone()
    assert row is not None
    return int(row[0])


def test_cli_status_names_partial_cloud_recovery_instead_of_local_only(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.product_cloud import _build_cloud_context

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
    from codex_plugin_scanner.guard.cli.product_cloud import _build_cloud_context

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

