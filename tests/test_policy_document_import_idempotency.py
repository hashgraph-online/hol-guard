"""HGP-160: deterministic imports do not duplicate grants."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument, policy_document_digest
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_document_import import _document, _rows


def test_identical_retry_is_idempotent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    document = _document()
    compiled = compile_policy_document(document)
    first = store.import_policy_document(
        document, compiled, mode="merge", now="2026-07-16T12:00:00Z", approval_gate_grant=None
    )
    second = store.import_policy_document(
        document, compiled, mode="merge", now="2026-07-16T12:00:01Z", approval_gate_grant=None
    )
    assert first.digest == second.digest == policy_document_digest(document)
    assert len(_rows(store)) == 1


def test_duplicate_rule_ids_conflict() -> None:
    document = _document(rule_ids=("same", "same"))
    with pytest.raises(PolicyCompilationError, match="duplicate_policy_rule_id"):
        compile_policy_document(document)


def test_one_rule_can_import_several_distinct_selectors(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    mapping = _document().to_mapping()
    mapping["spec"]["rules"][0]["match"] = {"artifacts": ["skill:fixture/one", "skill:fixture/two"]}
    document = GuardPolicyDocument.from_mapping(mapping)
    compiled = compile_policy_document(document)
    assert len(compiled) == 2
    result = store.import_policy_document(
        document, compiled, mode="merge", now="2026-07-16T12:00:00Z", approval_gate_grant=None
    )
    assert result.inserted == 2
    assert [row["policy_rule_id"] for row in _rows(store)] == ["rule-1", "rule-1"]


def test_reordered_rules_do_not_change_selectors(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    first = _document(rule_ids=("rule-a", "rule-b"))
    second = _document(rule_ids=("rule-b", "rule-a"))
    store.import_policy_document(
        first,
        compile_policy_document(first),
        mode="replace",
        now="2026-07-16T12:00:00Z",
        approval_gate_grant=None,
    )
    store.import_policy_document(
        second,
        compile_policy_document(second),
        mode="replace",
        now="2026-07-16T12:00:01Z",
        approval_gate_grant=None,
    )
    rule_ids = [row["policy_rule_id"] for row in _rows(store)]
    assert sorted(rule_ids) == ["rule-a", "rule-b"]


def test_crash_before_commit_does_not_persist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard")
    document = _document()
    compiled = compile_policy_document(document)
    original = store._import_policy_rows_on_connection  # pyright: ignore[reportPrivateUsage]

    def write_then_fail(*args: object, **kwargs: object) -> object:
        original(*args, **kwargs)
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "_import_policy_rows_on_connection", write_then_fail)
    with pytest.raises(sqlite3.OperationalError):
        store.import_policy_document(
            document, compiled, mode="merge", now="2026-07-16T12:00:00Z", approval_gate_grant=None
        )
    assert _rows(store) == []
