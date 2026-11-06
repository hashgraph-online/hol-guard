from __future__ import annotations

from codex_plugin_scanner.guard.store import GuardStore


def test_legacy_approval_store_adds_oauth_source_before_review_triggers(tmp_path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    with store._connect() as connection:
        connection.execute("drop trigger if exists guard_review_outbox_after_insert")
        connection.execute("drop trigger if exists guard_review_outbox_after_update")
        connection.execute("drop trigger if exists guard_approval_oauth_source_immutable")
        connection.execute("drop index if exists idx_approval_source_group_status")
        connection.execute("alter table approval_requests drop column oauth_source")

    reopened = GuardStore(guard_home)
    with reopened._connect() as connection:
        columns = {str(row["name"]) for row in connection.execute("pragma table_info(approval_requests)")}
        triggers = {
            str(row["name"])
            for row in connection.execute(
                "select name from sqlite_master where type = 'trigger' and name like 'guard_review_outbox_after_%'"
            )
        }

    assert "oauth_source" in columns
    assert triggers == {"guard_review_outbox_after_insert", "guard_review_outbox_after_update"}
