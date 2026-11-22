"""The workspace fix proposal rows are read and written by the native store."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import workspace_assessment_fix_proposals as fixes
from codex_plugin_scanner.guard import workspace_assessment_store as assessments


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KEYS = assessments.WorktreeKeys(_digest("codebase"), _digest("worktree"))


class _Store:
    """Answers each native store call in order and records it."""

    def __init__(self, answers: list[object]) -> None:
        self.answers = iter(answers)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _native_store_call(self, method: str, args: dict[str, object], **_kwargs: Any) -> object:
        self.calls.append((method, dict(args)))
        return next(self.answers)


def _row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "proposal_id": "p1",
        "codebase_key": KEYS.codebase_key,
        "worktree_key": KEYS.worktree_key,
        "finding_id": "f" * 32,
        "ecosystem": "npm",
        "package_name": "left-pad",
        "fix_version": "1.3.0",
        "advisory_ids_json": '["GHSA-1"]',
        "rule_ids_json": "[]",
        "source_run_id": "r1",
        "snapshot_digest": "d" * 64,
        "manifest_path": "package.json",
        "base_sha256": "b" * 64,
        "new_sha256": "n" * 64,
        "edits_json": '[{"section":"dependencies","start":1,"end":2,"from_spec":"1.0.0","to_spec":"1.3.0"}]',
        "diff_text": "--- a\n+++ b\n",
        "state": "prepared",
        "created_at_ms": 5,
        "updated_at_ms": 5,
        "applied_at_ms": None,
        "verified_at_ms": None,
        "verification_run_id": None,
    }
    row.update(overrides)
    return row


def test_the_worktree_root_comes_from_the_native_store() -> None:
    store = _Store([{"root": "/work/a", "paused": 1}, None])
    assert fixes._worktree(store, KEYS) == (Path("/work/a"), True)
    with pytest.raises(fixes.FixProposalError) as refused:
        fixes._worktree(store, KEYS)
    assert refused.value.code == "worktree_not_found"
    assert store.calls[0] == (
        "workspace_assessment_worktree_root",
        {"codebase_key": KEYS.codebase_key, "worktree_key": KEYS.worktree_key},
    )


@pytest.mark.parametrize(
    "answer",
    [{"root": "/work/a"}, {"root": 3, "paused": 0}, {"root": "/work/a", "paused": True}, []],
)
def test_a_malformed_worktree_answer_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="workspace_assessment_worktree_root"):
        fixes._worktree(_Store([answer]), KEYS)


def test_listing_pages_until_the_limit_and_decodes_each_row(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fixes, "verify_proposals", lambda *_args, **_kwargs: None)
    first = {"items": [_row(proposal_id="p2"), _row(proposal_id="p1")], "next": [5, "p1"]}
    second = {"items": [_row(proposal_id="p0", state="applied", diff_text=None)], "next": None}
    store = _Store([first, second])
    listed = fixes.list_proposals(store, KEYS, limit=3, now_ms=9)
    assert [item["proposal_id"] for item in listed] == ["p2", "p1", "p0"]
    assert listed[0]["advisory_ids"] == ["GHSA-1"]
    assert listed[0]["edits"] == [{"section": "dependencies", "from_spec": "1.0.0", "to_spec": "1.3.0"}]
    assert listed[2]["diff"] is None
    assert store.calls[0][1]["limit"] == 3
    assert "before" not in store.calls[0][1]
    assert store.calls[1][1]["before"] == [5, "p1"]


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"items": []},
        {"items": [], "next": [1, "p"]},
        {"items": [{"proposal_id": "p1"}], "next": None},
        {"items": "x", "next": None},
    ],
)
def test_a_malformed_listing_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    monkeypatch.setattr(fixes, "verify_proposals", lambda *_args, **_kwargs: None)
    with pytest.raises(RuntimeError, match="list_workspace_fix_proposals"):
        fixes.list_proposals(_Store([answer]), KEYS, now_ms=1)


def test_fetch_reads_one_row_or_none() -> None:
    store = _Store([_row(), None, {"proposal_id": "p1"}])
    row = fixes._fetch(store, "p1")
    assert row is not None and row["proposal_id"] == "p1"
    assert fixes._fetch(store, "p9") is None
    with pytest.raises(RuntimeError, match="get_workspace_fix_proposal"):
        fixes._fetch(store, "p1")


def test_setting_state_sends_the_apply_flag() -> None:
    store = _Store([None, False])
    fixes._set_state(store, "p1", "applied", now_ms=7, applied=True)
    assert store.calls[0] == (
        "set_workspace_fix_proposal_state",
        {"proposal_id": "p1", "state": "applied", "now_ms": 7, "applied": True},
    )
    with pytest.raises(RuntimeError, match="set_workspace_fix_proposal_state"):
        fixes._set_state(store, "p1", "stale", now_ms=7)


def test_preparing_sends_each_planned_edit_with_a_fresh_id() -> None:
    planned: list[dict[str, object]] = [
        {
            "manifest_path": "package.json",
            "base_sha256": "b" * 64,
            "new_sha256": "n" * 64,
            "edits": [{"section": "dependencies", "start": 1, "end": 2, "from_spec": "1.0.0", "to_spec": "1.3.0"}],
            "diff": "diff",
        }
    ]
    identity: dict[str, object] = {
        "ecosystem": "npm",
        "package_name": "left-pad",
        "fix_version": "1.3.0",
        "advisory_ids": ["GHSA-1"],
        "rule_ids": [],
    }
    run: dict[str, object] = {"run_id": "r1", "snapshot_digest": "d" * 64}
    store = _Store([["kept"], _row(proposal_id="kept")])
    stored = fixes._store_prepared(store, KEYS, "f" * 32, run, planned, identity, now_ms=11)
    assert [item["proposal_id"] for item in stored] == ["kept"]
    method, args = store.calls[0]
    assert method == "store_prepared_workspace_fix_proposals"
    assert args["advisory_ids_json"] == '["GHSA-1"]'
    assert args["source_run_id"] == "r1"
    items = args["items"]
    assert isinstance(items, list) and len(items) == 1
    item = items[0]
    assert isinstance(item, dict)
    assert len(str(item["proposal_id"])) == 32
    assert item["edits_json"] == (
        '[{"section":"dependencies","start":1,"end":2,"from_spec":"1.0.0","to_spec":"1.3.0"}]'
    )
    with pytest.raises(RuntimeError, match="store_prepared_workspace_fix_proposals"):
        fixes._store_prepared(_Store([[]]), KEYS, "f" * 32, run, planned, identity, now_ms=11)
    broken = [{**planned[0], "edits": "x"}]
    with pytest.raises(fixes.FixProposalError):
        fixes._store_prepared(_Store([]), KEYS, "f" * 32, run, broken, identity, now_ms=11)


def test_verdicts_are_settled_by_the_native_store(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runner_authority as runner_authority

    run = {"run_id": "r2", "snapshot_digest": "e" * 64, "started_at_ms": 1, "coverage": {}, "findings": []}
    monkeypatch.setattr(assessments, "latest_assessed_run", lambda *_args: run)
    seen: list[dict[str, object]] = []

    def verdict(_name: str, payload: dict[str, object]) -> dict[str, object]:
        seen.append(payload)
        return {"updates": [{"proposal_id": "p1", "state": "verified_fixed"}, {"proposal_id": "zz", "state": "x"}]}

    monkeypatch.setattr(runner_authority, "native_runner_authority", verdict)
    pending = {
        "proposal_id": "p1",
        "ecosystem": "npm",
        "package_name": "left-pad",
        "fix_version": "1.3.0",
        "advisory_ids": '["GHSA-1"]',
        "rule_ids": "[]",
        "snapshot_digest": "d" * 64,
        "applied_at_ms": 4,
        "state": "applied",
        "verification_run_id": None,
    }
    store = _Store([{"items": [pending], "next": None}, False, {"items": [pending], "next": None}, True])
    assert fixes._settle_against_newest(store, KEYS, now_ms=30) is False
    assert fixes._settle_against_newest(store, KEYS, now_ms=30) is True
    proposals = seen[0]["proposals"]
    assert isinstance(proposals, list) and proposals[0]["advisory_ids"] == ["GHSA-1"]
    method, args = store.calls[1]
    assert method == "settle_workspace_fix_proposals"
    assert args["run_id"] == "r2"
    assert args["updates"] == [
        {
            "proposal_id": "p1",
            "state": "verified_fixed",
            "prior_state": "applied",
            "prior_verification_run_id": None,
        }
    ]
