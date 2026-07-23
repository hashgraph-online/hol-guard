from __future__ import annotations

import sqlite3

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import live_request_sync
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_live_request_outbox import (
    live_request_oauth_subject_hash,
    seed_live_request_outbox,
)

_NOW = "2026-07-11T12:00:00+00:00"
_OUTBOX_TABLE = "guard" + "_live_request_outbox"
_SUBJECT_HASH = str(live_request_oauth_subject_hash("grant-1"))
_INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"


def _delivery_binding(workspace_id: str = "workspace-1") -> dict[str, str]:
    return {
        "oauth_subject_hash": _SUBJECT_HASH,
        "workspace_id": workspace_id,
        "machine_id": "machine-1",
        "machine_installation_id": _INSTALLATION_ID,
    }


def _current_delivery_binding(
    store: GuardStore,
    *,
    workspace_id: str | None = None,
) -> dict[str, str]:
    binding = store.get_live_request_oauth_binding()
    assert binding is not None
    delivery_binding = {
        key: binding[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    if workspace_id is not None:
        delivery_binding["workspace_id"] = workspace_id
    return delivery_binding


def _oauth_state(
    workspace_id: str,
    *,
    grant_id: str = "grant-1",
    machine_id: str = "machine-1",
) -> dict[str, str]:
    return {
        "grant_id": grant_id,
        "machine_id": machine_id,
        "workspace_id": workspace_id,
    }


def _sync_auth(
    store: GuardStore,
    *,
    workspace_id: str = "workspace-1",
    grant_id: str = "grant-1",
    machine_id: str = "machine-1",
) -> dict[str, str]:
    state_key = (
        "oauth_local_credentials"
        if store.guard_source == "default"
        else f"oauth_local_credentials:{store.guard_source}"
    )
    store.set_sync_payload(
        state_key,
        _oauth_state(workspace_id, grant_id=grant_id, machine_id=machine_id),
        _NOW,
    )
    binding = store.get_live_request_oauth_binding()
    assert binding is not None
    return binding


def _request(
    request_id: str,
    *,
    summary: str = "Review test action",
    action_identity: str | None = None,
    queue_group_id: str | None = None,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Test action",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/tmp/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        action_identity=action_identity or request_id,
        queue_group_id=queue_group_id or request_id,
        trigger_summary=summary,
        last_seen_at=_NOW,
    )


def test_approval_insert_and_resolution_share_transactional_outbox(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")

    request_id = store.add_approval_request(_request("request-1"), _NOW)
    pending = store.list_ready_live_request_outbox(now=_NOW, limit=10)

    assert request_id == "request-1"
    assert len(pending) == 1
    assert pending[0]["local_request_id"] == request_id
    first_sequence = int(pending[0]["sequence"])

    store.resolve_approval_request(
        request_id,
        resolution_action="approve",
        resolution_scope="artifact",
        reason="approved",
        resolved_at="2026-07-11T12:00:00.100000+00:00",
    )
    resolved = store.list_ready_live_request_outbox(
        now="2026-07-11T12:00:01+00:00",
        limit=10,
    )

    assert len(resolved) == 1
    assert int(resolved[0]["sequence"]) > first_sequence
    assert store.get_approval_request(request_id)["status"] == "resolved"


def test_acknowledging_inflight_sequence_preserves_newer_mutation(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    selected = store.list_ready_live_request_outbox(now=_NOW, limit=1)
    old_sequence = int(selected[0]["sequence"])

    store.add_approval_request(
        _request("request-1", summary="Updated review summary"),
        "2026-07-11T12:00:00.050000+00:00",
    )
    assert store.acknowledge_live_request_outbox([old_sequence], **_delivery_binding()) == 0

    remaining = store.list_ready_live_request_outbox(
        now="2026-07-11T12:00:01+00:00",
        limit=10,
    )
    assert len(remaining) == 1
    assert int(remaining[0]["sequence"]) > old_sequence


def test_outbox_ownership_is_not_reassigned_after_workspace_switch(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)

    assert store.claim_unowned_live_request_outbox(**_delivery_binding("workspace-a")) == 1
    assert (
        len(
            store.list_ready_live_request_outbox(
                now=_NOW,
                limit=10,
                **_delivery_binding("workspace-a"),
            )
        )
        == 1
    )
    assert (
        store.list_ready_live_request_outbox(
            now=_NOW,
            limit=10,
            **_delivery_binding("workspace-b"),
        )
        == []
    )

    store.add_approval_request(
        _request("request-1", summary="Updated review summary"),
        "2026-07-11T12:00:00.050000+00:00",
    )
    assert store.claim_unowned_live_request_outbox(**_delivery_binding("workspace-b")) == 0
    assert (
        len(
            store.list_ready_live_request_outbox(
                now="2026-07-11T12:00:01+00:00",
                limit=10,
                **_delivery_binding("workspace-a"),
            )
        )
        == 1
    )
    assert (
        store.live_request_outbox_status(
            now=_NOW,
            workspace_id="workspace-a",
        )["depth"]
        == 1
    )
    assert (
        store.live_request_outbox_status(
            now=_NOW,
            workspace_id="workspace-b",
        )["depth"]
        == 0
    )


def test_simultaneous_sources_keep_dedupe_and_outbox_ownership_separate(tmp_path) -> None:
    guard_home = tmp_path / "guard"
    default_store = GuardStore(guard_home)
    staging_store = GuardStore(guard_home, source="staging")
    default_store.set_sync_payload(
        "oauth_local_credentials",
        _oauth_state("workspace-default"),
        _NOW,
    )
    staging_store.set_sync_payload(
        "oauth_local_credentials:staging",
        _oauth_state("workspace-staging"),
        _NOW,
    )

    default_id = default_store.add_approval_request(
        _request("request-default", action_identity="shared-action", queue_group_id="shared-group"),
        _NOW,
    )
    staging_id = staging_store.add_approval_request(
        _request("request-staging", action_identity="shared-action", queue_group_id="shared-group"),
        _NOW,
    )

    assert default_id == "request-default"
    assert staging_id == "request-staging"
    default_rows = default_store.list_ready_live_request_outbox(
        now=_NOW,
        limit=10,
        **_current_delivery_binding(default_store),
    )
    staging_rows = staging_store.list_ready_live_request_outbox(
        now=_NOW,
        limit=10,
        **_current_delivery_binding(staging_store),
    )
    assert [row["local_request_id"] for row in default_rows] == ["request-default"]
    assert [row["local_request_id"] for row in staging_rows] == ["request-staging"]
    assert default_rows[0]["oauth_source"] == "default"
    assert staging_rows[0]["oauth_source"] == "staging"
    assert default_rows[0]["oauth_subject_hash"] == _SUBJECT_HASH
    assert staging_rows[0]["oauth_subject_hash"] == _SUBJECT_HASH
    assert default_rows[0]["machine_id"] == "machine-1"
    assert staging_rows[0]["machine_id"] == "machine-1"
    assert default_rows[0]["machine_installation_id"] == default_store.get_or_create_installation_id()
    assert staging_rows[0]["machine_installation_id"] == staging_store.get_or_create_installation_id()
    with default_store._connect() as connection:
        trigger_rows = connection.execute(
            """
            select sql from sqlite_master
            where type = 'trigger' and name like 'guard%request_outbox%'
            """
        ).fetchall()
    assert trigger_rows
    assert all("oauth_local_credentials" not in str(row["sql"]) for row in trigger_rows)
    with staging_store._connect() as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "update approval_requests set oauth_source = 'default' where request_id = ?",
            ("request-staging",),
        )

    staging_sequence = int(staging_rows[0]["sequence"])
    staging_binding = {
        key: str(staging_rows[0][key])
        for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    assert default_store.acknowledge_live_request_outbox([staging_sequence], **staging_binding) == 0
    assert (
        default_store.retry_live_request_outbox(
            [staging_sequence],
            now=_NOW,
            error="offline",
            **staging_binding,
        )
        == 0
    )
    assert (
        len(
            staging_store.list_ready_live_request_outbox(
                now=_NOW,
                limit=10,
                **_current_delivery_binding(staging_store),
            )
        )
        == 1
    )


def test_seeded_rows_are_source_scoped_and_require_explicit_identity_claim(tmp_path) -> None:
    guard_home = tmp_path / "guard"
    default_store = GuardStore(guard_home)
    staging_store = GuardStore(guard_home, source="staging")
    default_store.set_sync_payload(
        "oauth_local_credentials",
        _oauth_state("workspace-default"),
        _NOW,
    )
    staging_store.set_sync_payload(
        "oauth_local_credentials:staging",
        _oauth_state("workspace-staging"),
        _NOW,
    )
    default_store.add_approval_request(_request("request-default"), _NOW)
    staging_store.add_approval_request(_request("request-staging"), _NOW)

    seed_key = "guard" + "_live_request_outbox_seeded_v1"
    with default_store._connect() as connection:
        connection.execute(f"delete from {_OUTBOX_TABLE}")
        connection.execute("delete from sync_state where state_key = ?", (seed_key,))
        seed_live_request_outbox(connection, _NOW)
        rows = connection.execute(
            f"""
            select local_request_id, oauth_source, oauth_subject_hash, workspace_id,
                   machine_id, machine_installation_id
            from {_OUTBOX_TABLE}
            order by local_request_id
            """
        ).fetchall()

    assert [(row["local_request_id"], row["oauth_source"]) for row in rows] == [
        ("request-default", "default"),
        ("request-staging", "staging"),
    ]
    assert all(
        all(row[key] is None for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id"))
        for row in rows
    )
    assert default_store.claim_unowned_live_request_outbox(**_current_delivery_binding(default_store)) == 1
    assert staging_store.claim_unowned_live_request_outbox(**_current_delivery_binding(staging_store)) == 1
    assert [
        row["local_request_id"]
        for row in default_store.list_ready_live_request_outbox(
            now=_NOW,
            limit=10,
            **_current_delivery_binding(default_store),
        )
    ] == ["request-default"]
    assert [
        row["local_request_id"]
        for row in staging_store.list_ready_live_request_outbox(
            now=_NOW,
            limit=10,
            **_current_delivery_binding(staging_store),
        )
    ] == ["request-staging"]


def test_source_reconnect_does_not_reassign_events_from_previous_workspace(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard", source="staging")
    store.set_sync_payload(
        "oauth_local_credentials:staging",
        _oauth_state("workspace-old"),
        _NOW,
    )
    store.add_approval_request(_request("request-old"), _NOW)

    store.set_sync_payload(
        "oauth_local_credentials:staging",
        _oauth_state("workspace-new"),
        "2026-07-11T12:00:01+00:00",
    )
    store.add_approval_request(_request("request-new"), "2026-07-11T12:00:01+00:00")

    assert store.claim_unowned_live_request_outbox(**_delivery_binding("workspace-new")) == 0
    assert [
        row["local_request_id"]
        for row in store.list_ready_live_request_outbox(
            now="2026-07-11T12:00:02+00:00",
            limit=10,
            **_current_delivery_binding(store, workspace_id="workspace-old"),
        )
    ] == ["request-old"]
    assert [
        row["local_request_id"]
        for row in store.list_ready_live_request_outbox(
            now="2026-07-11T12:00:02+00:00",
            limit=10,
            **_current_delivery_binding(store),
        )
    ] == ["request-new"]
    status = store.live_request_outbox_status(
        now="2026-07-11T12:00:02+00:00",
        workspace_id="workspace-new",
    )
    assert status["oauth_source"] == "staging"
    assert status["binding_state"] == "workspace_mismatch"
    assert status["binding_hint"]
    assert status["depth"] == 1
    assert status["other_workspace_depth"] == 1


def test_account_identity_change_never_uploads_prior_subject_events(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard", source="staging")
    store.set_sync_payload(
        "oauth_local_credentials:staging",
        _oauth_state("workspace-shared", grant_id="grant-old"),
        _NOW,
    )
    store.add_approval_request(_request("request-old-subject"), _NOW)
    store.set_sync_payload(
        "oauth_local_credentials:staging",
        _oauth_state("workspace-shared", grant_id="grant-new"),
        "2026-07-11T12:00:01+00:00",
    )
    store.add_approval_request(_request("request-new-subject"), "2026-07-11T12:00:01+00:00")
    posted: list[str] = []

    def post_events(*_args, **kwargs):
        events = kwargs["events"]
        posted.extend(str(event["localRequestId"]) for event in events)
        return {"accepted": len(events), "rejected": 0}

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)
    current_binding = {
        "oauth_source": "staging",
        "oauth_subject_hash": str(live_request_oauth_subject_hash("grant-new")),
        "workspace_id": "workspace-shared",
        "machine_id": "machine-1",
        "machine_installation_id": store.get_or_create_installation_id(),
    }

    result = live_request_sync.sync_live_requests_once(store, current_binding)

    assert result["synced"] == 1
    assert posted == ["request-new-subject"]
    remaining = store.list_ready_live_request_outbox(
        now="2026-07-11T12:00:02+00:00",
        limit=10,
    )
    assert [row["local_request_id"] for row in remaining] == ["request-old-subject"]
    status = store.live_request_outbox_status(
        now="2026-07-11T12:00:02+00:00",
        **{key: value for key, value in current_binding.items() if key != "oauth_source"},
    )
    assert status["identity_mismatch_depth"] == 1
    assert status["binding_state"] == "identity_mismatch"


def test_sync_rejects_stale_identity_before_claim_or_upload(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    current_auth = _sync_auth(store)
    store.add_approval_request(_request("request-current"), _NOW)

    def unexpected_post(*_args, **_kwargs):
        raise AssertionError("stale identity reached the upload boundary")

    monkeypatch.setattr(live_request_sync, "_post_sync_events", unexpected_post)

    with pytest.raises(RuntimeError, match="matching source, OAuth subject"):
        live_request_sync.sync_live_requests_once(
            store,
            {**current_auth, "machine_id": "stale-machine"},
        )

    rows = store.list_ready_live_request_outbox(
        now=_NOW,
        limit=10,
        **_current_delivery_binding(store),
    )
    assert [row["local_request_id"] for row in rows] == ["request-current"]


def _replace_outbox_with_legacy_row(
    store: GuardStore,
    *,
    request_id: str,
    workspace_id: str,
) -> None:
    with store._connect() as connection:
        connection.execute("drop trigger if exists guard_approval_oauth_source_immutable")
        connection.execute(f"drop trigger if exists {_OUTBOX_TABLE}_after_insert")
        connection.execute(f"drop trigger if exists {_OUTBOX_TABLE}_after_update")
        connection.execute(f"drop table {_OUTBOX_TABLE}")
        connection.execute(
            f"""
            create table {_OUTBOX_TABLE} (
              sequence integer primary key autoincrement,
              local_request_id text not null,
              changed_at text not null,
              workspace_id text,
              attempt_count integer not null default 0,
              next_attempt_at text,
              last_error text
            )
            """
        )
        connection.execute(
            f"""
            insert into {_OUTBOX_TABLE} (local_request_id, changed_at, workspace_id)
            values (?, ?, ?)
            """,
            (request_id, _NOW, workspace_id),
        )
        connection.execute(
            "update approval_requests set oauth_source = null where request_id = ?",
            (request_id,),
        )


def test_ambiguous_legacy_outbox_rows_remain_quarantined(tmp_path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        "oauth_local_credentials",
        _oauth_state("workspace-default"),
        _NOW,
    )
    store.set_sync_payload(
        "oauth_local_credentials:staging",
        _oauth_state("workspace-staging"),
        _NOW,
    )
    store.add_approval_request(_request("request-legacy"), _NOW)
    _replace_outbox_with_legacy_row(
        store,
        request_id="request-legacy",
        workspace_id="workspace-previously-assumed",
    )

    default_store = GuardStore(guard_home)
    staging_store = GuardStore(guard_home, source="staging")

    assert default_store.claim_unowned_live_request_outbox(**_delivery_binding("workspace-default")) == 0
    assert staging_store.claim_unowned_live_request_outbox(**_delivery_binding("workspace-staging")) == 0
    assert default_store.list_ready_live_request_outbox(now=_NOW, limit=10) == []
    assert staging_store.list_ready_live_request_outbox(now=_NOW, limit=10) == []
    status = default_store.live_request_outbox_status(now=_NOW, workspace_id="workspace-default")
    assert status["binding_state"] == "legacy_ambiguous"
    assert status["binding_hint"]
    assert status["legacy_unbound_depth"] == 1
    with default_store._connect() as connection:
        row = connection.execute(f"select oauth_source, workspace_id from {_OUTBOX_TABLE}").fetchone()
    assert row is not None
    assert row["oauth_source"] is None
    assert row["workspace_id"] is None


def test_legacy_outbox_reassignment_requires_exact_operator_confirmation(tmp_path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        "oauth_local_credentials",
        _oauth_state("workspace-default"),
        _NOW,
    )
    store.add_approval_request(_request("request-legacy"), _NOW)
    _replace_outbox_with_legacy_row(
        store,
        request_id="request-legacy",
        workspace_id="workspace-previously-assumed",
    )

    migrated_store = GuardStore(guard_home)

    assert migrated_store.claim_unowned_live_request_outbox(**_delivery_binding("workspace-default")) == 0
    with pytest.raises(ValueError, match="approved source"):
        migrated_store.reassign_quarantined_live_request_outbox(
            approved_source="Default",
            approved_workspace_id="workspace-default",
        )
    with pytest.raises(ValueError, match="approved workspace"):
        migrated_store.reassign_quarantined_live_request_outbox(
            approved_source="default",
            approved_workspace_id="workspace-wrong",
        )
    assert (
        migrated_store.reassign_quarantined_live_request_outbox(
            approved_source="default",
            approved_workspace_id="workspace-default",
        )
        == 1
    )
    rows = migrated_store.list_ready_live_request_outbox(
        now=_NOW,
        limit=10,
        **_current_delivery_binding(migrated_store),
    )
    assert len(rows) == 1
    assert rows[0]["oauth_source"] == "default"
    assert migrated_store.get_approval_request("request-legacy")["oauth_source"] == "default"


def test_newer_mutation_preserves_retry_backoff(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    selected = store.list_ready_live_request_outbox(now=_NOW, limit=1)
    old_sequence = int(selected[0]["sequence"])
    store.claim_unowned_live_request_outbox(**_delivery_binding())
    store.retry_live_request_outbox(
        [old_sequence],
        now=_NOW,
        error="offline",
        **_delivery_binding(),
    )

    store.add_approval_request(
        _request("request-1", summary="Updated review summary"),
        "2026-07-11T12:00:00.050000+00:00",
    )

    assert store.list_ready_live_request_outbox(now=_NOW, limit=1) == []
    retried = store.list_ready_live_request_outbox(
        now="2026-07-11T12:00:01+00:00",
        limit=1,
    )
    assert len(retried) == 1
    assert int(retried[0]["sequence"]) > old_sequence
    assert retried[0]["attempt_count"] == 1


def test_explicit_request_deletion_is_not_blocked_by_pending_outbox(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)

    with store._connect() as connection:
        connection.execute(
            "delete from approval_requests where request_id = ?",
            ("request-1",),
        )

    assert store.get_approval_request("request-1") is None


def test_successful_sync_deletes_only_acknowledged_outbox_rows(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    posted: list[list[dict[str, object]]] = []

    def post_events(*_args, **kwargs):
        events = kwargs["events"]
        posted.append(events)
        return {"accepted": len(events), "rejected": 0, "cursor": "cloud-cursor"}

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    auth = _sync_auth(store)
    first = live_request_sync.sync_live_requests_once(store, auth)
    second = live_request_sync.sync_live_requests_once(store, auth)

    assert first["synced"] == 1
    assert first["outbox"]["depth"] == 0
    assert second["synced"] == 0
    assert len(posted) == 1
    assert posted[0][0]["localRequestId"] == "request-1"


def test_each_source_syncs_only_its_events_and_uses_independent_state(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard"
    default_store = GuardStore(guard_home)
    staging_store = GuardStore(guard_home, source="staging")
    default_store.add_approval_request(_request("request-default"), _NOW)
    staging_store.add_approval_request(_request("request-staging"), _NOW)
    staging_store.add_approval_request(
        _request("request-staging-second"),
        "2026-07-11T12:00:01+00:00",
    )
    posted: list[tuple[str, list[str]]] = []

    def post_events(*_args, **kwargs):
        events = kwargs["events"]
        posted.append(
            (
                kwargs["workspace_id"],
                [str(event["localRequestId"]) for event in events],
            )
        )
        return {"accepted": len(events), "rejected": 0, "cursor": None}

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    default_result = live_request_sync.sync_live_requests_once(default_store, _sync_auth(default_store))
    staging_result = live_request_sync.sync_live_requests_once(
        staging_store,
        _sync_auth(staging_store, workspace_id="workspace-staging"),
    )

    assert default_result["synced"] == 1
    assert staging_result["synced"] == 2
    assert posted == [
        ("workspace-1", ["request-default"]),
        ("workspace-staging", ["request-staging-second"]),
        ("workspace-staging", ["request-staging"]),
    ]
    default_sync_key = live_request_sync.LIVE_REQUEST_SYNC_STATE_KEY
    assert default_store.get_sync_payload(default_sync_key)["synced_count"] == 1
    assert staging_store.get_sync_payload(f"{default_sync_key}:staging")["synced_count"] == 2
    assert staging_store.get_sync_payload(default_sync_key)["synced_count"] == 1


def test_resolution_during_send_preserves_newer_outbox_event(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    resolved_during_send = False

    def resolve_while_posting(*_args, **kwargs):
        nonlocal resolved_during_send
        if not resolved_during_send:
            resolved_during_send = True
            store.resolve_approval_request(
                "request-1",
                resolution_action="approve",
                resolution_scope="artifact",
                reason="approved",
                resolved_at="2026-07-11T12:00:00.100000+00:00",
            )
        return {
            "accepted": len(kwargs["events"]),
            "rejected": 0,
            "cursor": "cloud-cursor",
        }

    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        resolve_while_posting,
    )

    result = live_request_sync.sync_live_requests_once(store, _sync_auth(store))

    assert result["synced"] == 2
    assert result["outbox"]["depth"] == 0
    assert store.get_approval_request("request-1")["status"] == "resolved"


def test_rejected_batch_remains_durable_and_is_backed_off(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        lambda *_args, **_kwargs: {
            "accepted": 0,
            "rejected": 1,
            "errors": ["policy"],
        },
    )

    result = live_request_sync.sync_live_requests_once(store, _sync_auth(store))

    assert result["rejected"] == 1
    status = store.live_request_outbox_status(now=_NOW)
    assert status["depth"] == 1
    assert status["max_attempt_count"] == 1
    assert store.list_ready_live_request_outbox(now=_NOW, limit=10) == []


def test_partial_acknowledgement_retries_only_rejected_event(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-accepted"), "2026-07-11T18:00:00+00:00")
    store.add_approval_request(_request("request-rejected"), _NOW)
    monkeypatch.setattr(live_request_sync, "LIVE_REQUEST_SYNC_BATCH_SIZE", 2)

    def post_events(*_args, **kwargs):
        return {
            "accepted": 1,
            "rejected": 1,
            "perEventResults": [
                {
                    "index": index,
                    "accepted": event["localRequestId"] == "request-accepted",
                }
                for index, event in enumerate(kwargs["events"])
            ],
        }

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    result = live_request_sync.sync_live_requests_once(store, _sync_auth(store))

    assert result["synced"] == 1
    assert result["rejected"] == 1
    rows = store.list_ready_live_request_outbox(now="9999-12-31T23:59:59+00:00", limit=10)
    assert [row["local_request_id"] for row in rows] == ["request-rejected"]
    assert rows[0]["attempt_count"] == 1


def test_partial_acknowledgement_preserves_sanitized_cloud_retry_reason(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-rejected"), _NOW)
    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        lambda *_args, **_kwargs: {
            "accepted": 0,
            "rejected": 1,
            "perEventResults": [
                {
                    "index": 0,
                    "accepted": False,
                    "code": "oauth_subject_mismatch",
                    "error": "binding rejected",
                }
            ],
        },
    )

    result = live_request_sync.sync_live_requests_once(store, _sync_auth(store))

    assert result["rejected"] == 1
    assert result["errors"] == [
        "1 live request events require retry. Cloud reported: oauth_subject_mismatch: binding rejected."
    ]
    state = store.get_sync_payload("guard_live_request_sync_state")
    assert isinstance(state, dict)
    assert state["last_error"] == result["errors"][0]


def test_terminal_rejections_are_acknowledged_while_transient_rejection_retries(
    tmp_path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-stale"), _NOW)
    store.add_approval_request(_request("request-transient"), "2026-07-11T18:00:00+00:00")
    store.add_approval_request(_request("request-decision-queued"), "2026-07-11T19:00:00+00:00")
    monkeypatch.setattr(live_request_sync, "LIVE_REQUEST_SYNC_BATCH_SIZE", 3)

    def post_events(*_args, **kwargs):
        terminal_errors = {
            "request-decision-queued": "decision_queued",
            "request-stale": "stale_sequence",
        }
        return {
            "accepted": 0,
            "rejected": 3,
            "perEventResults": [
                {
                    "index": index,
                    "accepted": False,
                    "error": terminal_errors.get(
                        event["localRequestId"],
                        "temporary failure",
                    ),
                }
                for index, event in enumerate(kwargs["events"])
            ],
        }

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    live_request_sync.sync_live_requests_once(store, _sync_auth(store))

    rows = store.list_ready_live_request_outbox(
        now="9999-12-31T23:59:59+00:00",
        limit=10,
    )
    assert [row["local_request_id"] for row in rows] == ["request-transient"]
    assert rows[0]["attempt_count"] == 1


def test_newest_outbox_event_preempts_historical_backlog(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("historical"), _NOW)
    store.add_approval_request(_request("new"), "2026-07-11T18:00:00+00:00")

    rows = store.list_ready_live_request_outbox(
        now="9999-12-31T23:59:59+00:00",
        limit=1,
        newest_first=True,
    )

    assert [row["local_request_id"] for row in rows] == ["new"]


def test_sync_reserves_every_tenth_slot_for_oldest_ready_event(
    tmp_path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    for index in range(11):
        store.add_approval_request(
            _request(f"request-{index:02d}"),
            f"2026-07-11T12:{index:02d}:00+00:00",
        )
    sent: list[str] = []

    def post_events(*_args, **kwargs):
        sent.append(kwargs["events"][0]["localRequestId"])
        return {
            "accepted": 1,
            "rejected": 0,
            "perEventResults": [{"index": 0, "accepted": True}],
        }

    monkeypatch.setattr(live_request_sync, "LIVE_REQUEST_SYNC_MAX_BATCHES", 10)
    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    live_request_sync.sync_live_requests_once(store, _sync_auth(store))

    assert sent[:9] == [f"request-{index:02d}" for index in range(10, 1, -1)]
    assert sent[9] == "request-00"


def test_transient_newest_failures_do_not_reset_oldest_fairness_slot(
    tmp_path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    for index in range(11):
        store.add_approval_request(
            _request(f"request-{index:02d}"),
            f"2026-07-11T12:{index:02d}:00+00:00",
        )

    def post_events(*_args, **kwargs):
        request_id = kwargs["events"][0]["localRequestId"]
        accepted = request_id == "request-00"
        return {
            "accepted": int(accepted),
            "rejected": int(not accepted),
            "perEventResults": [
                {
                    "index": 0,
                    "accepted": accepted,
                    "error": None if accepted else "temporary_failure",
                },
            ],
        }

    monkeypatch.setattr(live_request_sync, "LIVE_REQUEST_SYNC_MAX_BATCHES", 10)
    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    live_request_sync.sync_live_requests_once(store, _sync_auth(store))

    rows = store.list_ready_live_request_outbox(
        now="9999-12-31T23:59:59+00:00",
        limit=20,
    )
    assert "request-00" not in {row["local_request_id"] for row in rows}


def test_worker_safety_interval_is_subsecond() -> None:
    assert live_request_sync.DEFAULT_POLL_INTERVAL_SECONDS <= 0.1
    assert live_request_sync.LIVE_REQUEST_SYNC_BATCH_SIZE == 1
