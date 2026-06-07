"""Receipt persistence tests — P5.4.

Covers:
- add_receipt → list_receipts roundtrip (all fields preserved)
- add_receipt → get_receipt by ID
- Multiple receipts ordered by timestamp descending
- list_receipts limit parameter
- get_latest_receipt returns most-recent for a harness/artifact pair
- get_receipt returns None for unknown receipt ID
- record_diff → get_latest_diff roundtrip (all fields preserved)
- record_inventory_artifact → find_inventory_item (explain backing store)
- find_inventory_item returns None for unknown artifact
- receipt_decision_counts aggregation
"""

from __future__ import annotations

import uuid
from pathlib import Path

from codex_plugin_scanner.guard.models import GuardArtifact, GuardReceipt
from codex_plugin_scanner.guard.store import GuardStore


def _make_store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


def _make_receipt(
    *,
    receipt_id: str | None = None,
    harness: str = "codex",
    artifact_id: str = "codex:project:my_tool",
    artifact_hash: str = "sha256:abc123",
    policy_decision: str = "allow",
    capabilities_summary: str = "file-read, network",
    changed_capabilities: tuple[str, ...] = ("network",),
    provenance_summary: str = "npm pkg v1.0.0",
    user_override: str | None = None,
    artifact_name: str | None = "my_tool",
    source_scope: str | None = "artifact",
    scanner_evidence: tuple[dict[str, object], ...] = (),
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
        user_override=user_override,
        artifact_name=artifact_name,
        source_scope=source_scope,
        scanner_evidence=scanner_evidence,
        timestamp=timestamp,
    )


def _make_artifact(
    artifact_id: str = "codex:project:my_tool",
    harness: str = "codex",
    command: str = "python",
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name="my_tool",
        harness=harness,
        artifact_type="mcp_server",
        source_scope="project",
        config_path="/home/user/.codex/config.toml",
        command=command,
        args=("-m", "my_tool"),
        transport="stdio",
    )


class TestReceiptRoundtrip:
    def test_add_then_list_returns_receipt(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        receipt = _make_receipt(receipt_id="r-001")
        store.add_receipt(receipt)

        items = store.list_receipts()
        assert len(items) == 1
        item = items[0]
        assert item["receipt_id"] == "r-001"
        assert item["harness"] == "codex"
        assert item["artifact_id"] == "codex:project:my_tool"
        assert item["artifact_hash"] == "sha256:abc123"
        assert item["policy_decision"] == "allow"

    def test_add_then_get_by_id_returns_receipt(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        receipt = _make_receipt(receipt_id="r-002")
        store.add_receipt(receipt)

        result = store.get_receipt("r-002")
        assert result is not None
        assert result["receipt_id"] == "r-002"
        assert result["capabilities_summary"] == "file-read, network"
        assert result["changed_capabilities"] == ["network"]
        assert result["provenance_summary"] == "npm pkg v1.0.0"

    def test_get_receipt_returns_none_for_unknown_id(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        assert store.get_receipt("does-not-exist") is None

    def test_all_optional_fields_preserved(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        evidence = ({"check": "hash", "result": "ok"},)
        receipt = _make_receipt(
            receipt_id="r-003",
            user_override="publisher",
            artifact_name="my_tool",
            source_scope="publisher",
            scanner_evidence=evidence,
        )
        store.add_receipt(receipt)

        result = store.get_receipt("r-003")
        assert result is not None
        assert result["user_override"] == "publisher"
        assert result["artifact_name"] == "my_tool"
        assert result["source_scope"] == "publisher"
        assert result["scanner_evidence"] == [{"check": "hash", "result": "ok"}]

    def test_null_optional_fields_preserved(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        receipt = _make_receipt(
            receipt_id="r-004",
            user_override=None,
            artifact_name=None,
            source_scope=None,
        )
        store.add_receipt(receipt)

        result = store.get_receipt("r-004")
        assert result is not None
        assert result["user_override"] is None
        assert result["artifact_name"] is None
        assert result["source_scope"] is None


class TestReceiptOrdering:
    def test_list_receipts_ordered_by_timestamp_descending(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.add_receipt(_make_receipt(receipt_id="r-old", timestamp="2025-01-01T00:00:00Z"))
        store.add_receipt(_make_receipt(receipt_id="r-mid", timestamp="2025-06-01T00:00:00Z"))
        store.add_receipt(_make_receipt(receipt_id="r-new", timestamp="2025-12-01T00:00:00Z"))

        items = store.list_receipts()
        assert [item["receipt_id"] for item in items] == ["r-new", "r-mid", "r-old"]

    def test_list_receipts_limit_restricts_count(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        for i in range(5):
            store.add_receipt(_make_receipt(receipt_id=f"r-{i:03d}", timestamp=f"2025-01-{i+1:02d}T00:00:00Z"))

        items = store.list_receipts(limit=3)
        assert len(items) == 3

    def test_get_latest_receipt_returns_most_recent(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.add_receipt(_make_receipt(
            receipt_id="r-old",
            artifact_id="codex:project:my_tool",
            harness="codex",
            timestamp="2025-01-01T00:00:00Z",
            policy_decision="require-reapproval",
        ))
        store.add_receipt(_make_receipt(
            receipt_id="r-new",
            artifact_id="codex:project:my_tool",
            harness="codex",
            timestamp="2025-12-01T00:00:00Z",
            policy_decision="allow",
        ))

        latest = store.get_latest_receipt("codex", "codex:project:my_tool")
        assert latest is not None
        assert latest["receipt_id"] == "r-new"
        assert latest["policy_decision"] == "allow"

    def test_get_latest_receipt_returns_none_when_no_match(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        assert store.get_latest_receipt("codex", "codex:project:unknown") is None

    def test_get_latest_receipt_scoped_to_harness_artifact_pair(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.add_receipt(_make_receipt(
            receipt_id="r-codex",
            harness="codex",
            artifact_id="codex:project:tool_a",
            timestamp="2025-12-01T00:00:00Z",
        ))
        store.add_receipt(_make_receipt(
            receipt_id="r-claude",
            harness="claude",
            artifact_id="claude:project:tool_a",
            timestamp="2025-12-02T00:00:00Z",
        ))

        latest_codex = store.get_latest_receipt("codex", "codex:project:tool_a")
        latest_claude = store.get_latest_receipt("claude", "claude:project:tool_a")
        assert latest_codex is not None
        assert latest_codex["receipt_id"] == "r-codex"
        assert latest_claude is not None
        assert latest_claude["receipt_id"] == "r-claude"


class TestReceiptDecisionCounts:
    def test_counts_aggregate_by_policy_decision(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        for _ in range(3):
            store.add_receipt(_make_receipt(
                harness="codex",
                artifact_id="codex:project:my_tool",
                policy_decision="allow",
                timestamp="2025-01-01T00:00:00Z",
            ))
        store.add_receipt(_make_receipt(
            harness="codex",
            artifact_id="codex:project:my_tool",
            policy_decision="block",
            timestamp="2025-01-02T00:00:00Z",
        ))

        counts = store.receipt_decision_counts("codex", "codex:project:my_tool")
        assert counts.get("allow") == 3
        assert counts.get("block") == 1

    def test_counts_return_empty_for_unknown_artifact(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        counts = store.receipt_decision_counts("codex", "codex:project:unknown")
        assert counts == {}


class TestDiffPersistence:
    def test_record_diff_then_get_latest_roundtrip(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.record_diff(
            harness="codex",
            artifact_id="codex:project:my_tool",
            changed_fields=["command", "args"],
            previous_hash="sha256:old",
            current_hash="sha256:new",
            now="2025-01-01T00:00:00Z",
        )

        diff = store.get_latest_diff("codex", "codex:project:my_tool")
        assert diff is not None
        assert diff["harness"] == "codex"
        assert diff["artifact_id"] == "codex:project:my_tool"
        assert diff["changed_fields"] == ["command", "args"]
        assert diff["previous_hash"] == "sha256:old"
        assert diff["current_hash"] == "sha256:new"
        assert diff["recorded_at"] == "2025-01-01T00:00:00Z"

    def test_get_latest_diff_returns_most_recent(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.record_diff(
            harness="codex",
            artifact_id="codex:project:my_tool",
            changed_fields=["command"],
            previous_hash=None,
            current_hash="sha256:v1",
            now="2025-01-01T00:00:00Z",
        )
        store.record_diff(
            harness="codex",
            artifact_id="codex:project:my_tool",
            changed_fields=["args"],
            previous_hash="sha256:v1",
            current_hash="sha256:v2",
            now="2025-06-01T00:00:00Z",
        )

        diff = store.get_latest_diff("codex", "codex:project:my_tool")
        assert diff is not None
        assert diff["current_hash"] == "sha256:v2"
        assert diff["changed_fields"] == ["args"]

    def test_get_latest_diff_returns_none_when_absent(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        assert store.get_latest_diff("codex", "codex:project:unknown") is None

    def test_diff_with_null_previous_hash(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.record_diff(
            harness="codex",
            artifact_id="codex:project:my_tool",
            changed_fields=["command"],
            previous_hash=None,
            current_hash="sha256:first",
            now="2025-01-01T00:00:00Z",
        )

        diff = store.get_latest_diff("codex", "codex:project:my_tool")
        assert diff is not None
        assert diff["previous_hash"] is None


class TestInventoryForExplain:
    def test_record_then_find_inventory_item(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        artifact = _make_artifact("codex:project:my_tool")
        store.record_inventory_artifact(
            artifact=artifact,
            artifact_hash="sha256:abc",
            policy_action="allow",
            changed=False,
            now="2025-01-01T00:00:00Z",
            approved=True,
        )

        item = store.find_inventory_item("codex:project:my_tool")
        assert item is not None
        assert item["artifact_id"] == "codex:project:my_tool"
        assert item["harness"] == "codex"
        assert item["artifact_hash"] == "sha256:abc"
        assert item["last_policy_action"] == "allow"
        assert item["present"] is True

    def test_find_inventory_item_returns_none_for_unknown(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        assert store.find_inventory_item("codex:project:unknown") is None

    def test_explain_payload_includes_latest_receipt_and_diff(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        artifact = _make_artifact("codex:project:my_tool")
        store.record_inventory_artifact(
            artifact=artifact,
            artifact_hash="sha256:abc",
            policy_action="allow",
            changed=False,
            now="2025-01-01T00:00:00Z",
            approved=True,
        )
        store.add_receipt(_make_receipt(
            receipt_id="r-001",
            artifact_id="codex:project:my_tool",
            harness="codex",
            timestamp="2025-01-01T00:00:00Z",
        ))
        store.record_diff(
            harness="codex",
            artifact_id="codex:project:my_tool",
            changed_fields=["args"],
            previous_hash="sha256:old",
            current_hash="sha256:abc",
            now="2025-01-01T00:00:00Z",
        )

        item = store.find_inventory_item("codex:project:my_tool")
        assert item is not None
        latest_receipt = store.get_latest_receipt("codex", "codex:project:my_tool")
        latest_diff = store.get_latest_diff("codex", "codex:project:my_tool")
        assert latest_receipt is not None
        assert latest_receipt["receipt_id"] == "r-001"
        assert latest_diff is not None
        assert latest_diff["changed_fields"] == ["args"]


class TestReceiptAnalytics:
    def test_receipt_analytics_aggregates_across_all_rows(self, tmp_path: Path) -> None:
        from datetime import datetime, timedelta, timezone

        store = _make_store(tmp_path)
        now = datetime.now(tz=timezone.utc)
        t1 = (now - timedelta(days=6)).isoformat().replace("+00:00", "Z")
        t2 = (now - timedelta(days=5)).isoformat().replace("+00:00", "Z")
        t3 = now.isoformat().replace("+00:00", "Z")

        store.add_receipt(_make_receipt(
            receipt_id="r1",
            harness="codex",
            policy_decision="allow",
            timestamp=t1,
            artifact_name="install npm",
        ))
        store.add_receipt(_make_receipt(
            receipt_id="r2",
            harness="codex",
            policy_decision="block",
            timestamp=t2,
            artifact_name="curl outbound",
        ))
        store.add_receipt(_make_receipt(
            receipt_id="r3",
            harness="claude",
            policy_decision="ask",
            timestamp=t3,
            artifact_name="read secrets",
        ))

        analytics = store.receipt_analytics(activity_days=7, trend_days=7, top_limit=5)

        assert analytics["total"] == 3
        assert analytics["allowed"] == 1
        assert analytics["blocked"] == 1
        assert analytics["reviewed"] == 1
        assert len(analytics["trend_buckets"]) == 7
        assert analytics["trend_buckets"][0]["date_key"] == (now - timedelta(days=6)).strftime("%Y-%m-%d")
        assert analytics["trend_buckets"][0]["allowed"] == 1
        assert analytics["trend_buckets"][1]["blocked"] == 1
        assert analytics["trend_buckets"][-1]["reviewed"] == 1
        assert len(analytics["daily_activity"]) == 7
        assert analytics["by_harness"][0]["harness"] == "codex"
        assert analytics["top_artifacts"][0]["total"] >= 1
