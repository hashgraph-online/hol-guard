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

import uuid
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.receipts.manager import build_receipt, _auto_diff_summary
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.consumer.service import _build_diff_summary
from codex_plugin_scanner.guard.mcp_tool_calls import _map_approval_source


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
        diff: dict[str, object] = {"changed": True, "changed_fields": ["hash", "capability_delta"], "current_hash": "abc"}
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


class TestMapApprovalSource:
    @pytest.mark.parametrize("decision_source,expected", [
        ("inline-approved", "inline"),
        ("inline-denied", "inline"),
        ("policy-allow", "policy"),
        ("policy-block", "policy"),
        ("policy_allow", "policy"),
        ("heuristic-allow", "policy"),
        ("heuristic_block", "policy"),
        ("auto-allow", "policy"),
        ("pending-approval", "approval_center"),
        ("approval-center-allow", "approval_center"),
        ("unknown-source", "approval_center"),
    ])
    def test_decision_source_mapped_correctly(self, decision_source: str, expected: str) -> None:
        assert _map_approval_source(decision_source) == expected
