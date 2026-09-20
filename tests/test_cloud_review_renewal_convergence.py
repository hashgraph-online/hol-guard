"""Real signed consent renewal preserves request identity and durable history.

Only clocks and the worker-refresh observation are controlled. Credentials and
review signing keys are synthetic; Store, signing, verification, local password
approval, requeue and exact application execute normally. This is local SQL
evidence, not an OAuth ceremony, remote delivery or installed continuation run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_exact_cloud_review as exact_store
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, update_settings
from codex_plugin_scanner.guard.daemon import cloud_review_settings as settings
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.runtime import cloud_review_status as status_module
from codex_plugin_scanner.guard.runtime import exact_cloud_review as exact
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[GuardStore, list[datetime], datetime]:
    store = connected_exact_review_store(tmp_path)
    clock = [datetime.now(timezone.utc)]

    class ControlledDateTime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> ControlledDateTime:
            return cls.fromtimestamp(clock[0].timestamp(), tz=tz)

    for module in (exact, exact_store, settings, status_module):
        monkeypatch.setattr(module, "datetime", ControlledDateTime)
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id="synthetic:retained-policy"),
        clock[0].isoformat(),
    )
    exact.enable_exact_cloud_review(store, ttl_seconds=60)
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": "synthetic-renewal-password",
            "confirm_password": "synthetic-renewal-password",
        },
    )
    return store, clock, clock[0] + timedelta(seconds=60)


def _renewal_payload(**changes: object) -> dict[str, object]:
    return {
        "action": "renew_consent",
        "confirm": "cloud-review.renew_consent",
        "workspace_id": "workspace-1",
        "source": "default",
        "approval_password": "synthetic-renewal-password",
        **changes,
    }


def _request(store: GuardStore, request_id: str) -> dict[str, object]:
    row = store.get_approval_request(request_id)
    assert isinstance(row, dict)
    return row


def _claim(store: GuardStore, request_id: str) -> dict[str, object]:
    return build_local_review_request_claim(
        request_row=_request(store, request_id),
        oauth=exact._oauth_metadata(store),
        store=store,
    )


def _durable_state(store: GuardStore) -> dict[str, tuple[tuple[object, ...], ...]]:
    # These durable authority/history tables exclude diagnostic rejection events.
    tables = (
        "approval_requests",
        "guard_exact_cloud_review_receipts",
        "guard_local_once_approvals",
        "policy_decisions",
        "guard_review_outbox_events",
        "guard_review_outbox_request_sequences",
    )
    with store._connect() as connection:
        return {
            table: tuple(tuple(row) for row in connection.execute(f"select * from {table} order by rowid"))
            for table in tables
        }


def test_explicit_renewal_requeues_current_pending_and_preserves_resolved_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, clock, expiry = _setup(tmp_path, monkeypatch)
    for request_id in ("renewal-resolved", "renewal-pending"):
        add_review_request(store, review_request(request_id))
    alternate = GuardStore(store.guard_home, source="alternate")
    add_review_request(alternate, review_request("renewal-other-source"))
    other_before = _request(alternate, "renewal-other-source")
    policy_before = store.list_policy_decisions()
    assert len(policy_before) == 1
    credentials_before = store.get_oauth_local_credentials(allow_primary=False)
    capability_before = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    pending_claim = _claim(store, "renewal-pending")
    old_pending = remote_approval(store, "renewal-pending", receipt_id="renewal-old-pending")
    applied = remote_approval(store, "renewal-resolved", receipt_id="renewal-old-applied")
    exact.apply_exact_cloud_review(store, remote_approval=applied)
    resolved_before = _request(store, "renewal-resolved")
    assert resolved_before["status"] == "resolved"
    prior_request = review_request("renewal-resolved")
    authority = store.resolve_policy_decision_lookup(
        harness=prior_request.harness,
        artifact_id=prior_request.artifact_id,
        artifact_hash=prior_request.artifact_hash,
        workspace=prior_request.workspace,
        publisher=prior_request.publisher,
        now=clock[0].isoformat(),
        consume_one_shot=False,
    )["decision"]
    assert isinstance(authority, dict) and authority["source"] == "approval-gate-once"
    assert store.claim_approval_reuse_decision(authority, now=clock[0].isoformat()) is True
    with store._connect() as connection:
        consumed_once = tuple(
            connection.execute(
                "select * from guard_local_once_approvals where request_id = ?",
                ("renewal-resolved",),
            ).fetchone()
        )
    assert consumed_once

    clock[0] = expiry - timedelta(microseconds=1)
    assert settings.cloud_review_settings_status(store)["enabled"] is True
    for moment in (expiry, expiry + timedelta(microseconds=1)):
        clock[0] = moment
        current = settings.cloud_review_settings_status(store)
        assert current["reason"] == "cloud_review_capability_expired"
        assert current["consent_expired"] is True and current["connected"] is True
        assert current["disconnected"] is False
        assert current["recovery_action"] == "hol-guard cloud-review enable --renew"
    before = _durable_state(store)
    with pytest.raises(exact.ExactCloudReviewError, match=r"^cloud_review_capability_expired$"):
        exact.apply_exact_cloud_review(store, remote_approval=old_pending)
    assert _durable_state(store) == before
    assert store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == capability_before

    refreshes: list[bool] = []

    def unavailable_workers() -> dict[str, object]:
        refreshes.append(True)
        return {"running": False, "sync_running": False}

    renewed = settings.change_cloud_review_settings(store, _renewal_payload(), refresh_workers=unavailable_workers)
    assert refreshes == [True]
    assert renewed["pending_requests_requeued"] == 1
    assert renewed["held_events_recovered"] == 0
    assert renewed["consent_enabled"] is True and renewed["connected"] is True
    assert renewed["delivery_ready"] is False  # A saved renewal does not prove a running worker.
    assert renewed["activation_error"] == "worker_refresh_failed"
    assert (renewed["workspace_id"], renewed["source"]) == ("workspace-1", "default")
    assert store.get_oauth_local_credentials(allow_primary=False) == credentials_before
    capability_after = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    assert isinstance(capability_before, dict) and isinstance(capability_after, dict)
    assert capability_after["nonce"] != capability_before["nonce"]
    assert len(store.list_events(event_name="cloud_review.exact_capability_issued")) == 2

    reopened = GuardStore(store.guard_home)
    status = settings.cloud_review_settings_status(reopened)
    assert status["consent_enabled"] is True and status["disconnected"] is False
    assert status["delivery_ready"] is False
    assert status["activation_error"] == "worker_refresh_failed"
    assert _request(reopened, "renewal-resolved") == resolved_before
    with reopened._connect() as connection:
        assert (
            tuple(
                connection.execute(
                    "select * from guard_local_once_approvals where request_id = ?",
                    ("renewal-resolved",),
                ).fetchone()
            )
            == consumed_once
        )
    assert _request(alternate, "renewal-other-source") == other_before
    assert reopened.list_policy_decisions() == policy_before
    with reopened._connect() as connection:
        requeued = connection.execute(
            "select local_request_id, oauth_source, workspace_id from guard_review_outbox_events "
            "where event_type = 'review.request.snapshot_requeued'",
        ).fetchall()
    assert [tuple(row) for row in requeued] == [("renewal-pending", "default", "workspace-1")]
    new_claim = _claim(reopened, "renewal-pending")
    assert new_claim["claimHash"] == pending_claim["claimHash"]
    assert new_claim["localRequestId"] == pending_claim["localRequestId"]
    assert new_claim["exactReviewCapability"] != pending_claim["exactReviewCapability"]

    before = _durable_state(reopened)
    with pytest.raises(exact.ExactCloudReviewError, match=r"^remote_exact_capability_mismatch$"):
        exact.apply_exact_cloud_review(reopened, remote_approval=old_pending)
    with pytest.raises(exact.ExactCloudReviewError, match=r"^remote_exact_replayed$"):
        exact.apply_exact_cloud_review(reopened, remote_approval=applied)
    assert _durable_state(reopened) == before
    assert not reopened.has_exact_cloud_review_receipt("renewal-old-pending")
    fresh = remote_approval(reopened, "renewal-pending", receipt_id="renewal-fresh-pending")
    result = exact.apply_exact_cloud_review(reopened, remote_approval=fresh)
    assert result.request_id == "renewal-pending"
    assert reopened.has_exact_cloud_review_receipt("renewal-fresh-pending")
    assert _request(reopened, "renewal-resolved") == resolved_before
    assert reopened.list_policy_decisions() == policy_before
    final = GuardStore(store.guard_home)
    before = _durable_state(final)
    with pytest.raises(exact.ExactCloudReviewError, match=r"^remote_exact_replayed$"):
        exact.apply_exact_cloud_review(final, remote_approval=fresh)
    assert _durable_state(final) == before


@pytest.mark.parametrize(
    "changes",
    [
        {"workspace_id": "other-workspace"},
        {"source": "alternate"},
        {"approval_password": ""},
    ],
)
def test_expired_consent_renewal_requires_current_selection_and_local_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, object],
) -> None:
    store, clock, expiry = _setup(tmp_path, monkeypatch)
    add_review_request(store, review_request("renewal-gated-pending"))
    clock[0] = expiry
    before = _durable_state(store)
    capability = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)

    def must_not_refresh() -> dict[str, object]:
        pytest.fail("Rejected renewal must not refresh workers")

    expected = ApprovalGateError if "approval_password" in changes else settings.CloudReviewSettingsError
    with pytest.raises(expected) as rejected:
        settings.change_cloud_review_settings(store, _renewal_payload(**changes), refresh_workers=must_not_refresh)
    assert rejected.value.code == ("approval_gate_required" if "approval_password" in changes else "connection_changed")
    assert _durable_state(store) == before
    assert store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == capability
    assert len(store.list_events(event_name="cloud_review.exact_capability_issued")) == 1
