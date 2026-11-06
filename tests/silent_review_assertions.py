"""Shared checks for a silent review that is stored and not prompted."""

import sqlite3

from codex_plugin_scanner.guard.store import GuardStore


def assert_silent_review_recorded(store: GuardStore) -> None:
    pending = store.list_approval_requests(status="pending")
    assert len(pending) == 1
    assert pending[0]["policy_action"] in {"review", "require-reapproval"}
    with sqlite3.connect(store.path) as connection:
        outbox = connection.execute(
            "select count(*) from guard_review_outbox_events where event_type = 'review.request.created'"
        ).fetchone()
        events = [row[0] for row in connection.execute("select event_name from guard_events")]
    assert outbox is not None and int(outbox[0]) >= 1
    assert events.count("approval.created") >= 1
    assert "guard.protection.ask_once_shown" not in events
