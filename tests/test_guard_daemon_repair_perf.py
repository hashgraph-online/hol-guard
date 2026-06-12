"""Tests for T740-T745: daemon repair, performance, docs smoke, and red-team smoke."""

from __future__ import annotations

import sqlite3
import time
import uuid

import pytest

from codex_plugin_scanner.guard.daemon import repair_approval_center_locator
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_index_statements,
    approval_schema_statement,
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
    artifact_id: str | None = None,
    workspace: str | None = "ws-a",
    launch_target: str | None = "run tool",
) -> GuardApprovalRequest:
    rid = str(uuid.uuid4())
    aid = artifact_id or f"codex:project:tool-{uuid.uuid4().hex[:8]}"
    return GuardApprovalRequest(
        request_id=rid,
        harness=harness,
        artifact_id=aid,
        artifact_name="tool",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/tmp/config.toml",
        workspace=workspace,
        launch_target=launch_target,
        review_command=f"hol-guard approvals approve {rid}",
        approval_url=f"http://127.0.0.1:5474/approvals/{rid}",
    )


class TestDaemonRepairPreservesPendingApprovals:
    """T740: stale locator repair does not lose pending approvals."""

    def test_repair_clears_locator_but_preserves_store(self, tmp_path) -> None:
        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home)

        req = _make_request()
        store.add_approval_request(req, "2026-01-01T00:00:00Z")

        locator_path = guard_home / "approval-center-locator.json"
        locator_path.parent.mkdir(parents=True, exist_ok=True)
        locator_path.write_text('{"pid": 9999999, "daemon_url": "http://127.0.0.1:9999"}', encoding="utf-8")

        result = repair_approval_center_locator(guard_home)

        assert result["repaired"] is True
        assert not locator_path.exists(), "Stale locator must be removed after repair"
        pending = store.list_approval_requests()
        assert len(pending) == 1, f"Pending approval must be preserved after repair, got {len(pending)}"
        assert pending[0]["request_id"] == req.request_id

    def test_repair_without_locator_is_idempotent(self, tmp_path) -> None:
        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home)
        store.add_approval_request(_make_request(), "2026-01-01T00:00:00Z")

        result = repair_approval_center_locator(guard_home)

        assert result["repaired"] is True
        assert len(store.list_approval_requests()) == 1


class TestNormalizedIdentityLookupPerformance:
    """T741: approval lookup by normalized identity stays under 50 ms with 100k approvals."""

    @pytest.mark.slow
    def test_lookup_by_identity_key_under_50ms_with_100k_rows(self) -> None:
        from codex_plugin_scanner.guard.store_approvals import _normalized_identity_key  # type: ignore[attr-defined]

        conn = _make_conn()
        harness = "codex"
        artifact_id = "codex:project:perf-tool"
        workspace = "ws-perf"
        launch_target = "run perf-tool"
        now = "2026-01-01T00:00:00Z"

        for _ in range(100_000):
            req = _make_request(
                harness=harness,
                artifact_id=f"codex:project:tool-{uuid.uuid4().hex[:8]}",
                workspace=workspace,
            )
            add_approval_request(conn, req, now)

        target = _make_request(
            harness=harness, artifact_id=artifact_id, workspace=workspace, launch_target=launch_target
        )
        add_approval_request(conn, target, now)
        identity_key = _normalized_identity_key(launch_target)

        start = time.monotonic()
        result = conn.execute(
            """
            select request_id from approval_requests
            where harness = ?
              and artifact_id = ?
              and workspace IS ?
              and normalized_identity_key = ?
              and status = 'pending'
            order by created_at desc
            limit 1
            """,
            (harness, artifact_id, workspace, identity_key),
        ).fetchone()
        elapsed_ms = (time.monotonic() - start) * 1000

        assert result is not None, "Target row must be found by identity key"
        assert elapsed_ms < 50, f"Identity-key lookup took {elapsed_ms:.1f}ms, expected < 50ms"


class TestDuplicatePendingCollapsePerformance:
    """T742: duplicate pending collapse stays under 100 ms with 100k approvals."""

    @pytest.mark.slow
    def test_dedup_insert_under_100ms_with_100k_rows(self) -> None:
        conn = _make_conn()
        harness = "codex"
        artifact_id = "codex:project:dedup-tool"
        workspace = "ws-dedup"
        launch_target = "run dedup-tool --flag"
        now = "2026-01-01T00:00:00Z"

        for _ in range(99_999):
            req = _make_request(
                harness=harness,
                artifact_id=f"codex:project:tool-{uuid.uuid4().hex[:8]}",
                workspace=workspace,
            )
            add_approval_request(conn, req, now)

        first = _make_request(
            harness=harness,
            artifact_id=artifact_id,
            workspace=workspace,
            launch_target=launch_target,
        )
        first_id = add_approval_request(conn, first, now)

        repeat = _make_request(
            harness=harness, artifact_id=artifact_id, workspace=workspace, launch_target=launch_target
        )
        start = time.monotonic()
        second_id = add_approval_request(conn, repeat, now)
        elapsed_ms = (time.monotonic() - start) * 1000

        assert first_id == second_id, "Duplicate must be collapsed"
        assert elapsed_ms < 100, f"Dedup insert took {elapsed_ms:.1f}ms, expected < 100ms"


class TestApproveOnceNoSecondPrompt:
    """T745: approve a canary once → retry immediately → no second prompt unless command changes."""

    def test_approved_canary_policy_resolves_to_allow(self, tmp_path) -> None:
        """After approving a canary artifact, policy lookup must return 'allow' immediately."""
        from codex_plugin_scanner.guard.models import PolicyDecision
        from codex_plugin_scanner.guard.store import GuardStore

        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home)
        artifact_id = "codex:project:canary-tool"
        artifact_hash_val = "hash-canary-v1"

        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash_val,
            ),
            "2026-01-01T00:00:00Z",
        )

        result = store.resolve_policy("codex", artifact_id, artifact_hash_val, workspace=None)
        assert result == "allow", f"Canary must resolve to 'allow' immediately after approval, got {result!r}"

    def test_changed_artifact_hash_reprompts(self, tmp_path) -> None:
        """Canary with a different hash (changed command) must not inherit prior approval."""
        from codex_plugin_scanner.guard.models import PolicyDecision
        from codex_plugin_scanner.guard.store import GuardStore

        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home)
        artifact_id = "codex:project:canary-tool"

        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id=artifact_id,
                artifact_hash="hash-canary-v1",
            ),
            "2026-01-01T00:00:00Z",
        )

        result = store.resolve_policy("codex", artifact_id, "hash-canary-v2-changed", workspace=None)
        assert result is None, f"Changed hash must not inherit prior approval, got {result!r}"


class TestReceiptAnalyticsIndexes:
    def test_guard_store_creates_receipt_indexes(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        with store._connect() as connection:
            rows = connection.execute(
                """
                select name from sqlite_master
                where type = 'index' and tbl_name = 'runtime_receipts'
                """
            ).fetchall()
        names = {str(row["name"]) for row in rows}
        assert "idx_receipts_harness_artifact" in names
        assert "idx_receipts_timestamp_harness" in names
