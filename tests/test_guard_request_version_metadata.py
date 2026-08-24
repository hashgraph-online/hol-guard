from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.live_request_sync import _build_live_request_event
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_schema_statement,
    get_approval_request,
)


def _request(version: str) -> GuardApprovalRequest:
    request_id = uuid.uuid4().hex
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id="codex:tool:versioned",
        artifact_name="tool",
        artifact_hash="hash",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path="config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:4455/requests/{request_id}",
        launch_target="git status --short",
        guard_version=version,
        first_seen_guard_version=version,
        last_seen_guard_version=version,
    )


def test_deduplicated_request_preserves_first_and_updates_last_guard_version() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(approval_schema_statement())

    first_id = add_approval_request(connection, _request("2.2.0a129"), "2026-08-02T00:00:00Z")
    second_id = add_approval_request(connection, _request("2.2.0a130"), "2026-08-02T00:01:00Z")
    row = connection.execute(
        "select guard_version, first_seen_guard_version, last_seen_guard_version from approval_requests"
    ).fetchone()

    assert first_id == second_id
    assert tuple(row) == ("2.2.0a130", "2.2.0a129", "2.2.0a130")


def test_deduplicated_legacy_request_records_its_first_observed_guard_version() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(approval_schema_statement())
    request = _request("2.2.0a130")
    request_id = add_approval_request(connection, request, "2026-08-02T00:00:00Z")
    connection.execute(
        """
        update approval_requests
        set guard_version = null, first_seen_guard_version = null, last_seen_guard_version = null
        where request_id = ?
        """,
        (request_id,),
    )

    add_approval_request(connection, _request("2.2.0a131"), "2026-08-02T00:01:00Z")
    row = connection.execute(
        "select guard_version, first_seen_guard_version, last_seen_guard_version from approval_requests"
    ).fetchone()

    assert tuple(row) == ("2.2.0a131", "2.2.0a131", "2.2.0a131")


def test_live_request_event_sends_guard_version_metadata(tmp_path: Path) -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(approval_schema_statement())
    request = _request("2.2.0a129")
    request_id = add_approval_request(connection, request, "2026-08-02T00:00:00Z")
    updated = _request("2.2.0a130")
    add_approval_request(connection, updated, "2026-08-02T00:01:00Z")
    item = get_approval_request(connection, request_id)

    assert item is not None
    event = _build_live_request_event(
        item,
        oauth=None,
        redaction_level="full",
        store=GuardStore(tmp_path),
        event_sequence=1,
    )

    assert event is not None
    assert event["guardVersion"] == "2.2.0a130"
    assert event["firstSeenGuardVersion"] == "2.2.0a129"
    assert event["lastSeenGuardVersion"] == "2.2.0a130"


def test_schema_probe_rejects_store_missing_request_version_columns(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    assert store._schema_is_current() is True  # pyright: ignore[reportPrivateUsage]

    with sqlite3.connect(store.path) as connection:
        connection.execute("drop trigger guard_review_outbox_after_insert")
        connection.execute("drop trigger guard_review_outbox_after_update")
        connection.execute("alter table approval_requests drop column guard_version")

    assert store._schema_is_current() is False  # pyright: ignore[reportPrivateUsage]
