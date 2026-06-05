"""P5.1 receipt model field tests — diff_summary and approval_source.

Covers:
- diff_summary auto-computed from changed_capabilities when not provided
- diff_summary explicit value preserved when provided
- diff_summary is None when changed_capabilities is empty and not provided
- approval_source field preserved in store roundtrip
- approval_source values: policy, inline, approval_center, cli_command, None
- build_receipt helper passes diff_summary / approval_source through to GuardReceipt
- _build_diff_summary helper in consumer.service produces correct prose
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.consumer.service import _build_diff_summary
from codex_plugin_scanner.guard.mcp_tool_calls import _map_approval_source
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.receipts.manager import _auto_diff_summary, build_receipt
from codex_plugin_scanner.guard.store import GuardStore


def _make_store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


def _make_receipt(
    *,
    receipt_id: str | None = None,
    harness: str = "codex",
    artifact_id: str = "codex:project:tool",
    artifact_hash: str = "sha256:abc",
    policy_decision: str = "allow",
    capabilities_summary: str = "file-read",
    changed_capabilities: tuple[str, ...] = (),
    provenance_summary: str = "npm v1",
    diff_summary: str | None = None,
    approval_source: str | None = None,
    timestamp: str = "2025-01-01T00:00:00Z",
    approval_request_id: str | None = None,
) -> GuardReceipt:
    return GuardReceipt(
        receipt_id=receipt_id or str(uuid.uuid4()),
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_decision,
        capabilities_summary=capabilities_summary,
        changed_capabilities=changed_capabilities,
        provenance_summary=provenance_summary,
        diff_summary=diff_summary,
        approval_source=approval_source,
        timestamp=timestamp,
        approval_request_id=approval_request_id,
    )


class TestAutoDiffSummary:
    def test_single_change(self) -> None:
        result = _auto_diff_summary(["network"])
        assert result == "1 change(s): network"

    def test_three_changes(self) -> None:
        result = _auto_diff_summary(["network", "subprocess", "filesystem"])
        assert result == "3 change(s): network, subprocess, filesystem"

    def test_more_than_three_truncates(self) -> None:
        result = _auto_diff_summary(["a", "b", "c", "d"])
        assert result == "4 change(s): a, b, c ..."

    def test_two_changes(self) -> None:
        result = _auto_diff_summary(["removed", "hash_changed"])
        assert result == "2 change(s): removed, hash_changed"


class TestBuildDiffSummary:
    def test_unchanged_artifact_returns_none(self) -> None:
        diff: dict[str, object] = {"changed": False, "changed_fields": [], "current_hash": "abc"}
        assert _build_diff_summary(diff) is None

    def test_changed_no_fields_returns_generic(self) -> None:
        diff: dict[str, object] = {"changed": True, "changed_fields": [], "current_hash": "abc"}
        assert _build_diff_summary(diff) == "artifact changed"

    def test_changed_with_fields(self) -> None:
        diff: dict[str, object] = {
            "changed": True,
            "changed_fields": ["hash", "capability_delta"],
            "current_hash": "abc",
        }
        result = _build_diff_summary(diff)
        assert result == "2 change(s): hash, capability_delta"

    def test_changed_fields_not_list_returns_generic(self) -> None:
        diff: dict[str, object] = {"changed": True, "changed_fields": "not-a-list", "current_hash": "abc"}
        assert _build_diff_summary(diff) == "artifact changed"


class TestBuildReceiptDiffSummary:
    def test_auto_computes_diff_summary_from_changed_capabilities(self) -> None:
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:tool",
            artifact_hash="abc",
            policy_decision="allow",
            capabilities_summary="file-read",
            changed_capabilities=["network", "subprocess"],
            provenance_summary="npm v1",
            artifact_name="tool",
            source_scope="project",
        )
        assert receipt.diff_summary == "2 change(s): network, subprocess"

    def test_empty_changed_capabilities_no_auto_summary(self) -> None:
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:tool",
            artifact_hash="abc",
            policy_decision="allow",
            capabilities_summary="file-read",
            changed_capabilities=[],
            provenance_summary="npm v1",
            artifact_name="tool",
            source_scope="project",
        )
        assert receipt.diff_summary is None

    def test_explicit_diff_summary_overrides_auto(self) -> None:
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:tool",
            artifact_hash="abc",
            policy_decision="allow",
            capabilities_summary="file-read",
            changed_capabilities=["network"],
            provenance_summary="npm v1",
            artifact_name="tool",
            source_scope="project",
            diff_summary="custom summary",
        )
        assert receipt.diff_summary == "custom summary"

    @pytest.mark.parametrize("source", ["policy", "inline", "approval_center", "cli_command", None])
    def test_approval_source_values(self, source: str | None) -> None:
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:tool",
            artifact_hash="abc",
            policy_decision="allow",
            capabilities_summary="file-read",
            changed_capabilities=[],
            provenance_summary="npm v1",
            artifact_name="tool",
            source_scope="project",
            approval_source=source,
        )
        assert receipt.approval_source == source


class TestReceiptFieldRoundtrip:
    def test_diff_summary_persisted_and_retrieved(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        receipt = _make_receipt(receipt_id="r-ds-01", diff_summary="2 change(s): network, subprocess")
        store.add_receipt(receipt)

        result = store.get_receipt("r-ds-01")
        assert result is not None
        assert result["diff_summary"] == "2 change(s): network, subprocess"

    def test_approval_source_persisted_and_retrieved(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        receipt = _make_receipt(receipt_id="r-as-01", approval_source="approval_center")
        store.add_receipt(receipt)

        result = store.get_receipt("r-as-01")
        assert result is not None
        assert result["approval_source"] == "approval_center"

    def test_null_diff_summary_and_approval_source_preserved(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        receipt = _make_receipt(receipt_id="r-null-01", diff_summary=None, approval_source=None)
        store.add_receipt(receipt)

        result = store.get_receipt("r-null-01")
        assert result is not None
        assert result["diff_summary"] is None
        assert result["approval_source"] is None

    @pytest.mark.parametrize("approval_source", ["policy", "inline", "approval_center", "cli_command"])
    def test_all_approval_source_variants_roundtrip(self, tmp_path: Path, approval_source: str) -> None:
        store = _make_store(tmp_path)
        rid = f"r-{approval_source}"
        receipt = _make_receipt(receipt_id=rid, approval_source=approval_source)
        store.add_receipt(receipt)

        result = store.get_receipt(rid)
        assert result is not None
        assert result["approval_source"] == approval_source

    def test_diff_summary_in_list_receipts(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        receipt = _make_receipt(
            receipt_id="r-list-01",
            diff_summary="1 change(s): removed",
            approval_source="policy",
        )
        store.add_receipt(receipt)

        receipts = store.list_receipts(harness="codex", limit=10)
        assert len(receipts) == 1
        assert receipts[0]["diff_summary"] == "1 change(s): removed"
        assert receipts[0]["approval_source"] == "policy"

    def test_action_envelope_json_roundtrip(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
        envelope = GuardActionEnvelope(
            schema_version=1,
            action_id="action-01",
            harness="codex",
            event_name="PreToolUse",
            action_type="shell_command",
            workspace=None,
            workspace_hash=None,
            tool_name="bash",
            command="ls -la",
            prompt_excerpt=None,
            prompt_text=None,
            target_paths=(),
            network_hosts=(),
            mcp_server=None,
            mcp_tool=None,
            package_manager=None,
            package_name=None,
        )
        receipt = _make_receipt(receipt_id="r-env-01")
        store.add_receipt(receipt, action_envelope=envelope)

        result = store.get_receipt("r-env-01")
        assert result is not None
        assert result["action_envelope_json"] == envelope.to_dict()
        assert isinstance(result["envelope_redacted_json"], dict)
        assert result["envelope_redacted_json"]["command_length"] == len("ls -la")
        assert "command" not in result["envelope_redacted_json"]
        assert "package_name" not in result["envelope_redacted_json"]

        receipts = store.list_receipts(harness="codex", limit=10)
        assert len(receipts) == 1
        assert receipts[0]["action_envelope_json"] == envelope.to_dict()

    def test_approval_request_id_joins_envelope_from_approval_table(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        from codex_plugin_scanner.guard.models import GuardApprovalRequest
        from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
        envelope = GuardActionEnvelope(
            schema_version=1,
            action_id="action-02",
            harness="codex",
            event_name="PreToolUse",
            action_type="shell_command",
            workspace=None,
            workspace_hash=None,
            tool_name="bash",
            command="rm -rf node_modules",
            prompt_excerpt=None,
            prompt_text=None,
            target_paths=(),
            network_hosts=(),
            mcp_server=None,
            mcp_tool=None,
            package_manager=None,
            package_name=None,
        )
        request = GuardApprovalRequest(
            request_id="req-01",
            harness="codex",
            artifact_id="codex:project:bash",
            artifact_name="Bash",
            artifact_hash="sha256:abc",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("shell_command",),
            source_scope="project",
            config_path="/tmp",
            review_command="Review",
            approval_url="http://localhost/approvals/req-01",
            action_envelope_json=envelope.to_dict(),
        )
        store.add_approval_request(request, now="2025-01-01T00:00:00Z")
        receipt = _make_receipt(receipt_id="r-join-01", approval_request_id="req-01")
        store.add_receipt(receipt)

        result = store.get_receipt("r-join-01")
        assert result is not None
        assert result["approval_request_id"] == "req-01"
        assert result["action_envelope_json"] == envelope.to_dict()


class TestV5MigrationPreservesRowids:
    def test_v5_migration_preserves_rowids_and_envelopes(self, tmp_path: Path) -> None:
        db_path = tmp_path / "guard" / "guard.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        conn.execute(
            "create table schema_migrations ("
            "  version integer primary key,"
            "  applied_at text not null"
            ")"
        )
        conn.execute(
            """
            create table runtime_receipts (
              receipt_id text primary key,
              harness text not null,
              artifact_id text not null,
              artifact_hash text not null,
              policy_decision text not null,
              capabilities_summary text not null default '',
              changed_capabilities_json text not null,
              provenance_summary text not null,
              user_override text,
              artifact_name text,
              source_scope text,
              scanner_evidence_json text not null default '[]',
              timestamp text not null,
              diff_summary text,
              approval_source text,
              action_envelope_json text
            )
            """
        )
        conn.execute(
            "insert into schema_migrations (version, applied_at) values (4, '2025-01-01T00:00:00Z')"
        )
        conn.execute(
            """
            insert into runtime_receipts (
              rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              changed_capabilities_json, provenance_summary, timestamp, action_envelope_json
            ) values (10, 'r-10', 'codex', 'a', 'h', 'allow', '[]', 'npm', '2025-01-01T00:00:00Z', '{"command":"ls"}')
            """
        )
        conn.execute(
            """
            insert into runtime_receipts (
              rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              changed_capabilities_json, provenance_summary, timestamp, action_envelope_json
            ) values (25, 'r-25', 'codex', 'a', 'h', 'allow', '[]', 'npm', '2025-01-01T00:00:00Z', '{"command":"cat"}')
            """
        )
        conn.execute(
            """
            insert into runtime_receipts (
              rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              changed_capabilities_json, provenance_summary, timestamp
            ) values (50, 'r-50', 'codex', 'a', 'h', 'allow', '[]', 'npm', '2025-01-01T00:00:00Z')
            """
        )
        conn.commit()
        conn.close()

        store = GuardStore(tmp_path / "guard")
        rows = store.list_receipts_since_rowid(after_rowid=0, limit=10)
        rowids = {r["receipt_rowid"] for r in rows}
        assert rowids == {10, 25, 50}

        since_10 = store.list_receipts_since_rowid(after_rowid=10, limit=10)
        assert {r["receipt_rowid"] for r in since_10} == {25, 50}

        r10 = store.get_receipt("r-10")
        assert r10 is not None
        assert r10["action_envelope_json"] == {"command": "ls"}

        r50 = store.get_receipt("r-50")
        assert r50 is not None
        assert r50["action_envelope_json"] is None


class TestMapApprovalSource:
    @pytest.mark.parametrize("decision_source,expected", [
        ("inline-approved", "inline"),
        ("inline-denied", "inline"),
        ("native-approved", "inline"),
        ("claude-native-approved", "inline"),
        ("policy-allow", "policy"),
        ("policy-block", "policy"),
        ("policy_allow", "policy"),
        ("heuristic-allow", "policy"),
        ("heuristic_block", "policy"),
        ("auto-allow", "policy"),
        ("heuristic", "policy"),
        ("policy", "policy"),
        ("auto", "policy"),
        ("pre-tool-hook", "policy"),
        ("permission-request-hook", "policy"),
        ("pending-approval", "approval_center"),
        ("approval-center-allow", "approval_center"),
        ("unknown-source", "approval_center"),
    ])
    def test_decision_source_mapped_correctly(self, decision_source: str, expected: str) -> None:
        assert _map_approval_source(decision_source) == expected
