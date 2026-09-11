from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, update_settings
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.cloud_review_settings import (
    CloudReviewSettingsError,
    change_cloud_review_settings,
    cloud_review_settings_status,
)
from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.runtime.exact_cloud_review import _oauth_metadata
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def _payload(**changes: object) -> dict[str, object]:
    return {
        "action": "enable",
        "confirm": "cloud-review.enable",
        "workspace_id": "workspace-1",
        "source": "default",
        **changes,
    }


def _refresh() -> dict[str, object]:
    return {"running": True, "sync_running": True}


def test_dashboard_reports_real_consent_not_cloud_connection(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    initial = cloud_review_settings_status(store)
    assert initial["connected"] is True
    assert initial["enabled"] is False
    assert initial["reason"] == "cloud_review_capability_missing"
    assert not any(secret in repr(initial) for secret in ("refresh-token", "dpop_private_key", "access_token"))
    changed = change_cloud_review_settings(store, _payload(), refresh_workers=_refresh)
    assert changed["enabled"] is True
    restarted = GuardStore(store.guard_home)
    assert cloud_review_settings_status(restarted)["enabled"] is True
    disabled = change_cloud_review_settings(
        restarted, _payload(action="disable", confirm="cloud-review.disable"), refresh_workers=_refresh
    )
    assert disabled["enabled"] is False
    assert disabled["connected"] is True


def test_reauthorization_refreshes_existing_pending_request(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("old-pending"))
    before = build_local_review_request_claim(
        request_row=store.get_approval_request("old-pending"), oauth=_oauth_metadata(store), store=store
    )
    assert "exactReviewCapability" not in before
    changed = change_cloud_review_settings(store, _payload(), refresh_workers=_refresh)
    assert changed["pending_requests_requeued"] == 1
    after = build_local_review_request_claim(
        request_row=store.get_approval_request("old-pending"), oauth=_oauth_metadata(store), store=store
    )
    assert after["localRequestId"] == before["localRequestId"]
    assert after["claimHash"] == before["claimHash"]
    assert isinstance(after.get("exactReviewCapability"), dict)


def test_inline_recovery_requires_mfa_and_explicit_workspace_confirmation(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    update_settings(store.guard_home, {"enabled": True, "new_password": "test-pass", "confirm_password": "test-pass"})
    with pytest.raises(ApprovalGateError):
        change_cloud_review_settings(store, _payload(), refresh_workers=_refresh)
    assert cloud_review_settings_status(store)["enabled"] is False
    with pytest.raises(CloudReviewSettingsError, match="workspace changed"):
        change_cloud_review_settings(
            store, _payload(workspace_id="other-workspace", approval_password="test-pass"), refresh_workers=_refresh
        )
    assert cloud_review_settings_status(store)["enabled"] is False
    changed = change_cloud_review_settings(store, _payload(approval_password="test-pass"), refresh_workers=_refresh)
    assert changed["enabled"] is True


def test_held_requests_require_explicit_adoption(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    add_review_request(store, review_request("held-pending"))
    store = connected_exact_review_store(tmp_path)
    before = store.review_event_outbox_status(now=datetime.now(timezone.utc).isoformat())
    assert before["quarantined_depth"] > 0
    change_cloud_review_settings(store, _payload(), refresh_workers=_refresh)
    unchanged = store.review_event_outbox_status(now=datetime.now(timezone.utc).isoformat())
    assert unchanged["quarantined_depth"] == before["quarantined_depth"]
    changed = change_cloud_review_settings(store, _payload(include_held_requests=True), refresh_workers=_refresh)
    assert changed["held_events_recovered"] > 0
    assert changed["held_events"] == 0


def test_requeue_failure_reports_saved_consent_and_retryable_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)

    def fail(**_kwargs: object) -> int:
        raise sqlite3.OperationalError("database locked")

    monkeypatch.setattr(store, "requeue_pending_review_events", fail)
    changed = change_cloud_review_settings(store, _payload(), refresh_workers=_refresh)
    assert changed["enabled"] is True
    assert changed["activation_error"] == "pending_request_requeue_failed"


def test_dashboard_route_requires_local_origin_session_and_gate(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    update_settings(store.guard_home, {"enabled": True, "new_password": "test-pass", "confirm_password": "test-pass"})
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        url = f"http://127.0.0.1:{daemon.port}/v1/cloud-review"

        def send(headers: dict[str, str], payload: dict[str, object] | None = None) -> dict[str, object]:
            request = urllib.request.Request(
                url, data=json.dumps(payload).encode() if payload else None, headers=headers
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)

        with pytest.raises(urllib.error.HTTPError) as missing_session:
            send({}, _payload())
        assert missing_session.value.code == 401
        headers = {"X-Guard-Token": daemon._server.auth_token, "Content-Type": "application/json"}
        with pytest.raises(urllib.error.HTTPError) as remote_origin:
            send({**headers, "Origin": "https://hol.org"}, _payload())
        assert remote_origin.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as missing_proof:
            send(headers, _payload())
        assert missing_proof.value.code == 403
        assert send(headers)["enabled"] is False
        assert send(headers, _payload(approval_password="test-pass"))["enabled"] is True
        assert send(headers)["enabled"] is True
    finally:
        daemon.stop()
