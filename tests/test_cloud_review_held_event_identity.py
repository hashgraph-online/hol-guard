"""HGP-169: held and quarantined events cannot cross identity."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.daemon.cloud_review_settings import (
    change_cloud_review_settings,
    cloud_review_settings_status,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request
from tests.test_guard_cloud_review_settings import _payload, _refresh


def test_known_other_workspace_is_not_auto_recovered(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("foreign"))
    with store._connect() as connection:
        connection.execute(
            "update guard_review_outbox_events set workspace_id = 'other-workspace', "
            "binding_status = 'quarantined', quarantine_reason = 'identity_incomplete' "
            "where local_request_id = ?",
            ("foreign",),
        )
    status = cloud_review_settings_status(store)
    assert status["held_events"] == 0
    recovered = change_cloud_review_settings(store, _payload(include_held_requests=True), refresh_workers=_refresh)
    assert recovered["held_events_recovered"] == 0


def test_unbound_held_events_recover_only_with_explicit_consent(tmp_path: Path) -> None:
    add_review_request(GuardStore(tmp_path / "guard-home"), review_request("held"))
    store = connected_exact_review_store(tmp_path)
    before = store.count_recoverable_unbound_review_events()
    assert before == 1
    skipped = change_cloud_review_settings(store, _payload(include_held_requests=False), refresh_workers=_refresh)
    assert skipped["held_events_recovered"] == 0
    adopted = change_cloud_review_settings(store, _payload(include_held_requests=True), refresh_workers=_refresh)
    assert adopted["held_events_recovered"] == 1
    assert adopted["held_events"] == 0
    assert cloud_review_settings_status(store)["workspace_id"] == "workspace-1"
    now = datetime.now(timezone.utc).isoformat()
    outbox = store.review_event_outbox_status(now=now)
    assert outbox["quarantined_depth"] == 0
    assert outbox["depth"] == 2
    recovered = store.list_ready_review_events(now=now, limit=10)
    assert [row["local_request_id"] for row in recovered] == ["held", "held"]
