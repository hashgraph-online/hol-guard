"""Phase 25 — approval store dedup by normalized action identity and workspace.

T719: store collapses duplicate pending requests by normalized action identity + workspace.
T720: duplicate pending requests update one row instead of creating many rows.
T721: different workspaces still get separate approval requests.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_index_statements,
    approval_schema_statement,
    count_approval_requests,
    get_approval_request,
    list_approval_requests,
)


def _make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("pragma journal_mode=wal")
    conn.execute(approval_schema_statement())
    for stmt in approval_index_statements():
        conn.execute(stmt)
    return conn


def _make_request(
    *,
    harness: str = "codex",
    workspace: str | None = "ws-a",
    artifact_id: str | None = None,
    launch_target: str | None = None,
    action_envelope_json: dict[str, object] | None = None,
    watch_only: bool = False,
) -> GuardApprovalRequest:
    aid = artifact_id or f"codex:project:tool-{uuid.uuid4().hex[:8]}"
    rid = str(uuid.uuid4())
    return GuardApprovalRequest(
        request_id=rid,
        harness=harness,
        artifact_id=aid,
        artifact_name="tool",
        artifact_type="mcp_server",
        artifact_hash="abc123",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="session",
        changed_fields=frozenset(["args"]),
        source_scope="project",
        config_path="/repo/config.toml",
        workspace=workspace,
        launch_target=launch_target,
        transport="stdio",
        risk_summary="risk",
        risk_signals=[],
        artifact_label=None,
        source_label=None,
        trigger_summary=None,
        why_now=None,
        launch_summary=None,
        risk_headline=None,
        action_envelope_json=action_envelope_json,
        decision_v2_json=None,
        fallback_cli_command=None,
        scanner_evidence=(({"source": "observe_mode_inbox", "authoritative_action": "allow"},) if watch_only else ()),
        review_command=f"hol-guard review {rid}",
        approval_url=f"http://localhost:4455/approve/{rid}",
    )


class TestDuplicatePendingRequestCollapse:
    """T719-T720: Duplicate pending requests collapse to one row."""

    def test_expired_inconsistent_card_stays_expired_after_store_reopens(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path)
        first = _make_request(artifact_id="codex:project:mcp-review", launch_target="tool:get_file_info")
        old_id = store.add_approval_request(first, "2026-09-29T00:00:00Z")
        with store._connect() as connection:
            connection.execute(
                "update approval_requests set decision_v2_json = ? where request_id = ?",
                ("{invalid-json", old_id),
            )
        fresh = _make_request(artifact_id=first.artifact_id, launch_target=first.launch_target)
        fresh_id = store.add_approval_request(fresh, "2026-09-29T00:01:00Z")
        assert fresh_id != old_id

        reopened = GuardStore(tmp_path)
        with reopened._connect() as connection:
            old = connection.execute(
                "select status, reason from approval_requests where request_id = ?", (old_id,)
            ).fetchone()
            assert tuple(old) == ("expired", "superseded_by_fresh_review:" + fresh_id)
            assert count_approval_requests(connection, status="pending") == 1

    def test_corrupt_pending_authority_requires_a_new_host_attempt_and_request_id(self) -> None:
        conn = _make_conn()
        first = _make_request(artifact_id="codex:project:mcp-review", launch_target="tool:composio_search_tools")
        old_id = add_approval_request(conn, first, "2026-09-27T12:00:00Z")
        conn.execute(
            "update approval_requests set decision_v2_json = ? where request_id = ?",
            ('{"minimum_action":"invalid-action"}', old_id),
        )
        fresh = _make_request(artifact_id=first.artifact_id, launch_target=first.launch_target)
        fresh_id = add_approval_request(conn, fresh, "2026-09-27T12:01:00Z")
        assert fresh_id == fresh.request_id and fresh_id != old_id
        old = conn.execute(
            "select status, resolution_action, reason from approval_requests where request_id = ?",
            (old_id,),
        ).fetchone()
        assert tuple(old) == ("expired", None, "superseded_by_fresh_review:" + fresh_id)
        assert count_approval_requests(conn, status="pending") == 1
        current = list_approval_requests(conn)[0]
        assert current["request_id"] == fresh_id
        assert current["policy_action"] == "require-reapproval"
        assert get_approval_request(conn, old_id)["superseded_by_request_id"] == fresh_id
        conn.execute("update approval_requests set harness = 'claude' where request_id = ?", (fresh_id,))
        assert "superseded_by_request_id" not in get_approval_request(conn, old_id)

    def test_failed_fresh_insert_keeps_invalid_card_pending(self) -> None:
        import pytest

        conn = _make_conn()
        first = _make_request(artifact_id="codex:project:mcp-review", launch_target="tool:read")
        old_id = add_approval_request(conn, first, "2026-09-27T12:00:00Z")
        conn.execute("update approval_requests set policy_action = 'invalid' where request_id = ?", (old_id,))
        unrelated = _make_request(artifact_id="codex:project:other", launch_target="tool:other")
        add_approval_request(conn, unrelated, "2026-09-27T12:00:00Z")
        fresh = replace(
            _make_request(artifact_id=first.artifact_id, launch_target=first.launch_target),
            request_id=unrelated.request_id,
        )

        with pytest.raises(sqlite3.IntegrityError):
            add_approval_request(conn, fresh, "2026-09-27T12:01:00Z")
        conn.commit()
        old = conn.execute("select status, reason from approval_requests where request_id = ?", (old_id,)).fetchone()
        assert tuple(old) == ("pending", None)

    def test_invalid_old_request_cannot_be_repaired_using_the_same_id(self) -> None:
        import pytest

        conn = _make_conn()
        first = _make_request(artifact_id="codex:project:mcp-review", launch_target="tool:composio_search_tools")
        old_id = add_approval_request(conn, first, "2026-09-27T12:00:00Z")
        conn.execute("update approval_requests set policy_action = 'invalid' where request_id = ?", (old_id,))
        with pytest.raises(ValueError, match="fresh_review_request_id_required"):
            add_approval_request(conn, first, "2026-09-27T12:01:00Z")
        assert (
            conn.execute(
                "select policy_action from approval_requests where request_id = ?",
                (old_id,),
            ).fetchone()[0]
            == "invalid"
        )

    def test_newer_valid_duplicate_does_not_leave_inconsistent_old_card_pending(self) -> None:
        conn = _make_conn()
        first = _make_request(artifact_id="codex:project:mcp-review", launch_target="tool:read_text_file")
        old_id = add_approval_request(conn, first, "2026-09-27T12:00:00Z")
        newer_id = str(uuid.uuid4())
        columns = [row[1] for row in conn.execute("pragma table_info(approval_requests)") if row[1] != "request_id"]
        names = ", ".join(columns)
        conn.execute(
            f"insert into approval_requests (request_id, {names}) "
            f"select ?, {names} from approval_requests where request_id = ?",
            (newer_id, old_id),
        )
        conn.execute(
            "update approval_requests set created_at = ?, last_seen_at = ? where request_id = ?",
            ("2026-09-27T12:01:00Z", "2026-09-27T12:01:00Z", newer_id),
        )
        conn.execute(
            "update approval_requests set decision_v2_json = ? where request_id = ?",
            ("{invalid-json", old_id),
        )

        fresh = _make_request(artifact_id=first.artifact_id, launch_target=first.launch_target)
        assert add_approval_request(conn, fresh, "2026-09-27T12:02:00Z") == newer_id
        old = conn.execute(
            "select status, resolution_action, reason from approval_requests where request_id = ?", (old_id,)
        ).fetchone()
        assert tuple(old) == ("expired", None, "superseded_by_fresh_review:" + newer_id)
        assert count_approval_requests(conn, status="pending") == 1

    def test_second_identical_request_updates_existing_row(self) -> None:
        """T720: A second pending request for the same artifact+workspace+launch_target
        must update the existing row and not create a new one."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-abc"
        req1 = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run tool --flag")
        req2 = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run tool --flag")

        id1 = add_approval_request(conn, req1, "2026-01-01T00:00:00Z")
        id2 = add_approval_request(conn, req2, "2026-01-01T00:01:00Z")

        assert id1 == id2, "Second identical request must reuse the existing request_id"
        total = count_approval_requests(conn, status="pending")
        assert total == 1, f"Expected 1 pending row, got {total}"

    def test_transient_variation_collapses_to_same_row(self) -> None:
        """T719: Transient variation (UUID in args) must not create a new row."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-xyz"
        req1 = _make_request(
            artifact_id=artifact_id,
            workspace="ws-b",
            launch_target="run tool --request-id req-aaaaaaaaaaaa --flag",
        )
        req2 = _make_request(
            artifact_id=artifact_id,
            workspace="ws-b",
            launch_target="run tool --request-id req-bbbbbbbbbbbb --flag",
        )

        id1 = add_approval_request(conn, req1, "2026-01-01T00:00:00Z")
        id2 = add_approval_request(conn, req2, "2026-01-01T00:01:00Z")

        assert id1 == id2, "Same command with different transient request IDs must collapse to one row"
        total = count_approval_requests(conn, status="pending")
        assert total == 1, f"Expected 1 pending row after transient variation, got {total}"

    def test_actionable_request_dominates_a_later_watch_observation(self) -> None:
        conn = _make_conn()
        request_args = {
            "artifact_id": "codex:project:tool-actionable-first",
            "workspace": "ws-a",
            "launch_target": "git status",
        }

        actionable_id = add_approval_request(conn, _make_request(**request_args), "2026-01-01T00:00:00Z")
        watch_id = add_approval_request(
            conn,
            _make_request(**request_args, watch_only=True),
            "2026-01-01T00:01:00Z",
        )

        assert watch_id == actionable_id
        assert count_approval_requests(conn, exclude_watch_only=True) == 1

    def test_actionable_request_promotes_an_existing_watch_observation(self) -> None:
        conn = _make_conn()
        request_args = {
            "artifact_id": "codex:project:tool-watch-first",
            "workspace": "ws-a",
            "launch_target": "git diff --stat",
        }

        watch_id = add_approval_request(
            conn,
            _make_request(**request_args, watch_only=True),
            "2026-01-01T00:00:00Z",
        )
        actionable_id = add_approval_request(conn, _make_request(**request_args), "2026-01-01T00:01:00Z")

        assert actionable_id == watch_id
        assert count_approval_requests(conn, exclude_watch_only=True) == 1

    def test_repeated_watch_observations_stay_out_of_actionable_count(self) -> None:
        conn = _make_conn()
        request_args = {
            "artifact_id": "codex:project:tool-watch-only",
            "workspace": "ws-a",
            "launch_target": "git log -5 --oneline",
            "watch_only": True,
        }

        add_approval_request(conn, _make_request(**request_args), "2026-01-01T00:00:00Z")
        add_approval_request(conn, _make_request(**request_args), "2026-01-01T00:01:00Z")

        assert count_approval_requests(conn) == 1
        assert count_approval_requests(conn, exclude_watch_only=True) == 0


def test_watch_only_schema_migration_backfills_all_observations(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    unambiguous = _make_request(
        artifact_id="codex:project:watch-unambiguous",
        launch_target="git status",
        watch_only=True,
    )
    ambiguous = _make_request(
        artifact_id="codex:project:watch-ambiguous",
        launch_target="git diff --stat",
        watch_only=True,
    )
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        add_approval_request(connection, unambiguous, "2026-01-01T00:00:00Z")
        add_approval_request(connection, ambiguous, "2026-01-01T00:00:00Z")
        connection.execute(
            "update approval_requests set watch_only_observation = 0, dedupe_count = 2 where request_id = ?",
            (ambiguous.request_id,),
        )
        connection.execute(
            "update approval_requests set watch_only_observation = 0 where request_id = ?",
            (unambiguous.request_id,),
        )
        connection.execute("delete from schema_migrations where version = 23")

    migrated = GuardStore(guard_home)
    with sqlite3.connect(migrated.path) as connection:
        values = dict(
            connection.execute(
                "select request_id, watch_only_observation from approval_requests order by request_id"
            ).fetchall()
        )

    assert values[unambiguous.request_id] == 1
    assert values[ambiguous.request_id] == 1


class TestDifferentWorkspacesGetSeparateRows:
    """T721: Different workspaces must produce separate approval request rows."""

    def test_same_artifact_different_workspaces_creates_two_rows(self) -> None:
        """T721: Same artifact in different workspaces must each queue its own approval."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-shared"
        req_ws_a = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run tool")
        req_ws_b = _make_request(artifact_id=artifact_id, workspace="ws-b", launch_target="run tool")

        id_a = add_approval_request(conn, req_ws_a, "2026-01-01T00:00:00Z")
        id_b = add_approval_request(conn, req_ws_b, "2026-01-01T00:01:00Z")

        assert id_a != id_b, "Different workspaces must get separate request IDs"
        total = count_approval_requests(conn, status="pending")
        assert total == 2, f"Expected 2 pending rows for 2 workspaces, got {total}"

    def test_null_and_named_workspace_get_separate_rows(self) -> None:
        """T721b: Null workspace and a named workspace must be treated as different."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-null-ws"
        req_null = _make_request(artifact_id=artifact_id, workspace=None, launch_target="run tool")
        req_named = _make_request(artifact_id=artifact_id, workspace="ws-c", launch_target="run tool")

        id_null = add_approval_request(conn, req_null, "2026-01-01T00:00:00Z")
        id_named = add_approval_request(conn, req_named, "2026-01-01T00:01:00Z")

        assert id_null != id_named, "Null workspace and named workspace must get separate request IDs"
        pending = list_approval_requests(conn, status="pending")
        assert len(pending) == 2, f"Expected 2 pending rows, got {len(pending)}"

    def test_different_launch_targets_create_separate_rows(self) -> None:
        """T719b: Different commands for same artifact+workspace must queue separate approvals."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-multi"
        req_ls = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run ls /repo")
        req_rm = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run rm /tmp/file")

        id_ls = add_approval_request(conn, req_ls, "2026-01-01T00:00:00Z")
        id_rm = add_approval_request(conn, req_rm, "2026-01-01T00:01:00Z")

        assert id_ls != id_rm, "Different commands must not collapse into one approval row"
        total = count_approval_requests(conn, status="pending")
        assert total == 2, f"Expected 2 pending rows for different commands, got {total}"

    def test_different_mcp_arguments_do_not_collapse_into_one_row(self) -> None:
        conn = _make_conn()
        artifact_id = "codex:project:mcp-tool"
        base_envelope = {
            "action_type": "mcp_tool_call",
            "tool_name": "github",
            "mcp_server": "github",
            "mcp_tool": "get_file_contents",
        }
        req_safe = _make_request(
            artifact_id=artifact_id,
            workspace="ws-a",
            launch_target="github get_file_contents",
            action_envelope_json={
                **base_envelope,
                "raw_payload_redacted": {"owner": "hashgraph-online", "repo": "safe-repo", "path": "README.md"},
            },
        )
        req_sensitive = _make_request(
            artifact_id=artifact_id,
            workspace="ws-a",
            launch_target="github get_file_contents",
            action_envelope_json={
                **base_envelope,
                "raw_payload_redacted": {
                    "owner": "hashgraph-online",
                    "repo": "safe-repo",
                    "path": ".github/workflows/release.yml",
                },
            },
        )

        id_safe = add_approval_request(conn, req_safe, "2026-01-01T00:00:00Z")
        id_sensitive = add_approval_request(conn, req_sensitive, "2026-01-01T00:01:00Z")

        assert id_safe != id_sensitive
        total = count_approval_requests(conn, status="pending")
        assert total == 2, f"Expected 2 pending rows for distinct MCP arguments, got {total}"

    def test_identical_mcp_arguments_still_collapse_when_session_metadata_differs(self) -> None:
        conn = _make_conn()
        artifact_id = "codex:project:mcp-tool"
        base_envelope = {
            "action_type": "mcp_tool_call",
            "tool_name": "github",
            "mcp_server": "github",
            "mcp_tool": "get_file_contents",
        }
        req_first = _make_request(
            artifact_id=artifact_id,
            workspace="ws-a",
            launch_target="github get_file_contents",
            action_envelope_json={
                **base_envelope,
                "raw_payload_redacted": {
                    "owner": "hashgraph-online",
                    "repo": "safe-repo",
                    "path": "README.md",
                    "session_id": "session-1",
                    "turn_id": "turn-1",
                },
            },
        )
        req_second = _make_request(
            artifact_id=artifact_id,
            workspace="ws-a",
            launch_target="github get_file_contents",
            action_envelope_json={
                **base_envelope,
                "raw_payload_redacted": {
                    "owner": "hashgraph-online",
                    "repo": "safe-repo",
                    "path": "README.md",
                    "session_id": "session-2",
                    "turn_id": "turn-2",
                },
            },
        )

        id_first = add_approval_request(conn, req_first, "2026-01-01T00:00:00Z")
        id_second = add_approval_request(conn, req_second, "2026-01-01T00:01:00Z")

        assert id_first == id_second
        total = count_approval_requests(conn, status="pending")
        assert total == 1, f"Expected identical MCP actions to dedupe across session metadata, got {total}"


class TestLegacyNullIdentityKeyUpgradePath:
    """Regression: existing rows with NULL normalized_identity_key must still be deduped."""

    def test_legacy_null_row_is_updated_not_duplicated(self) -> None:
        """After upgrade, a pending row with NULL identity key must be reused for the same
        artifact+workspace instead of inserting a duplicate row."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-legacy"
        req_legacy = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run tool")
        first_id = add_approval_request(conn, req_legacy, "2026-01-01T00:00:00Z")

        conn.execute(
            "update approval_requests set normalized_identity_key = NULL where request_id = ?",
            (first_id,),
        )

        req_new = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run tool")
        second_id = add_approval_request(conn, req_new, "2026-01-01T00:01:00Z")

        assert first_id == second_id, "Legacy row with NULL identity key must be reused, not duplicated"
        total = count_approval_requests(conn, status="pending")
        assert total == 1, f"Expected 1 pending row after deduping legacy null row, got {total}"

    def test_legacy_null_row_different_command_not_collapsed(self) -> None:
        """Legacy NULL rows for different commands must NOT be collapsed even during upgrade path."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-multi"
        req_a = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run cmd-a")
        id_a = add_approval_request(conn, req_a, "2026-01-01T00:00:00Z")
        conn.execute(
            "update approval_requests set normalized_identity_key = NULL where request_id = ?",
            (id_a,),
        )

        req_b = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target="run cmd-b")
        id_b = add_approval_request(conn, req_b, "2026-01-01T00:01:00Z")

        assert id_a != id_b, "Different commands must each get their own pending row even when legacy row is NULL"
        total = count_approval_requests(conn, status="pending")
        assert total == 2, f"Expected 2 pending rows for different commands, got {total}"

    def test_legacy_null_launch_target_row_is_deduped(self) -> None:
        """Legacy rows with NULL launch_target AND NULL identity key must be deduped for the same artifact."""
        conn = _make_conn()
        artifact_id = "codex:project:tool-null-target"
        req_null = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target=None)
        first_id = add_approval_request(conn, req_null, "2026-01-01T00:00:00Z")

        conn.execute(
            "update approval_requests set normalized_identity_key = NULL where request_id = ?",
            (first_id,),
        )

        req_retry = _make_request(artifact_id=artifact_id, workspace="ws-a", launch_target=None)
        second_id = add_approval_request(conn, req_retry, "2026-01-01T00:01:00Z")

        assert first_id == second_id, "NULL-launch-target legacy row must be reused for the same artifact"
        total = count_approval_requests(conn, status="pending")
        assert total == 1, f"Expected 1 pending row for NULL launch_target dedup, got {total}"
