"""The native store reads the Cloud Review policy-memory cursor in one snapshot."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_review_policy_memory_rows import (
    ReviewPolicyMemoryRows,
    ReviewPolicyMemoryRowUnreadableError,
)

_NOW = "2026-11-22T00:00:00+00:00"
_REGISTRY_KEY = "guard_review_memory_registry"
_VERSION_KEY = "guard_review_memory_policy_version"


def test_an_empty_store_holds_no_cursor(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).review_policy_memory_rows() == ReviewPolicyMemoryRows(None, None)


def test_stored_rows_come_back_together(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    registry: list[object] = [{"ruleId": "rule-a", "decision": {"action": "allow"}}]
    store.set_sync_payload(_REGISTRY_KEY, registry, _NOW)
    store.set_sync_payload(_VERSION_KEY, {"policyVersion": "  v7 "}, _NOW)

    assert store.review_policy_memory_rows() == ReviewPolicyMemoryRows(registry, "v7")


def test_a_version_without_text_reads_as_absent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(_VERSION_KEY, {"policyVersion": "   "}, _NOW)

    assert store.review_policy_memory_rows().policy_version is None


@pytest.mark.parametrize("key", [_REGISTRY_KEY, _VERSION_KEY])
def test_a_row_that_is_not_json_refuses_the_snapshot(tmp_path: Path, key: str) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(key, {"policyVersion": "v1"}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = 'not-json' where state_key = ?", (key,))

    with pytest.raises(ReviewPolicyMemoryRowUnreadableError, match="review_policy_memory_unreadable"):
        store.review_policy_memory_rows()


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"registry": "rules", "policy_version": None, "unreadable": []},
        {"registry": None, "policy_version": 7, "unreadable": []},
        {"registry": None, "policy_version": "", "unreadable": []},
    ],
)
def test_a_malformed_answer_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="no answer"):
        ReviewPolicyMemoryRows.from_native(answer)
