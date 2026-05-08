"""Phase 25 — approval store dedup by normalized action identity and workspace.

T719: store collapses duplicate pending requests by normalized action identity + workspace.
T720: duplicate pending requests update one row instead of creating many rows.
T721: different workspaces still get separate approval requests.
"""

from __future__ import annotations

import sqlite3
import uuid

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_index_statements,
    approval_schema_statement,
    count_approval_requests,
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
        action_envelope_json=None,
        decision_v2_json=None,
        fallback_cli_command=None,
        review_command=f"hol-guard review {rid}",
        approval_url=f"http://localhost:4455/approve/{rid}",
    )


class TestDuplicatePendingRequestCollapse:
    """T719-T720: Duplicate pending requests collapse to one row."""

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
