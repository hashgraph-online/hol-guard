"""The workspace assessment read models come from the native store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import workspace_assessment_reads as reads
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.store import GuardStore
from tests.workspace_fix_support import admit_worktree

DETECTORS = "d" * 64
T0 = 1_000_000_000


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KEYS = assessments.WorktreeKeys(_digest("codebase"), _digest("worktree"))


def _run_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "run_id": "r1",
        "codebase_key": KEYS.codebase_key,
        "worktree_key": KEYS.worktree_key,
        "snapshot_digest": None,
        "kind": "deterministic",
        "trigger_kind": "manual",
        "state": "queued",
        "dirty_generation": 1,
        "coverage_json": '{"z": 1, "a": 2}',
        "error_code": None,
        "created_at_ms": T0,
        "started_at_ms": None,
        "finished_at_ms": None,
        "finding_count": 0,
    }
    row.update(overrides)
    return row


def _answers(monkeypatch: pytest.MonkeyPatch, store: GuardStore, answers: list[object]) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    pending = iter(answers)

    def native(_method: str, args: dict[str, object], **_kwargs: Any) -> object:
        calls.append(dict(args))
        return next(pending)

    monkeypatch.setattr(store, "_native_store_call", native)
    return calls


def test_the_reads_round_trip_through_the_native_store(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    admit_worktree(store, KEYS, root="/work/0", now_ms=T0)
    run_id = assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=DETECTORS, now_ms=T0)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update workspace_assessment_runs set findings_json = ? where run_id = ?",
            (json.dumps([{"id": 1}, {"id": 2}]), run_id),
        )

    [worktree] = reads.list_worktrees(store)
    assert worktree["root"] == "/work/0"
    assert worktree["paused"] is False
    assert worktree["ended"] is False
    assert worktree["stale"] is True
    [run] = reads.recent_runs(store, KEYS, limit=5)
    assert run["run_id"] == run_id
    assert run["finding_count"] == 2
    assert "findings" not in run
    assert reads.latest_runs(store) == [run]
    assert reads.latest_assessed_run(store, KEYS) is None


def test_stored_coverage_keeps_its_key_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "home")
    _answers(monkeypatch, store, [{"items": [_run_row()], "next": None}])

    [run] = reads.latest_runs(store)

    coverage = run["coverage"]
    assert isinstance(coverage, dict)
    assert list(coverage) == ["z", "a"]


def test_run_history_follows_the_cursor_and_stops_at_its_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "home")
    calls = _answers(
        monkeypatch,
        store,
        [
            {"items": [_run_row(run_id="r3")], "next": [T0, "r3"]},
            {"items": [_run_row(run_id="r2"), _run_row(run_id="r1")], "next": [T0, "r1"]},
        ],
    )

    runs = reads.recent_runs(store, limit=2)

    assert [run["run_id"] for run in runs] == ["r3", "r2"]
    assert calls == [{"mode": "recent", "limit": 2}, {"mode": "recent", "limit": 2, "before": [T0, "r3"]}]


def test_the_newest_assessed_run_carries_its_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "home")
    row = _run_row(state="completed", findings_json='[{"id": 1}]')
    del row["finding_count"]
    _answers(monkeypatch, store, [row])

    run = reads.latest_assessed_run(store, KEYS)

    assert run is not None
    assert run["findings"] == [{"id": 1}]
    assert run["coverage"] == {"z": 1, "a": 2}


@pytest.mark.parametrize(
    "answer",
    [
        None,
        [],
        {"items": []},
        {"items": [], "next": None, "extra": 1},
        {"items": {}, "next": None},
        {"items": [], "next": "r1"},
        {"items": [], "next": [T0, "r1"]},
        {"items": [{"run_id": "r1"}], "next": None},
        {"items": [_run_row(finding_count="2")], "next": None},
        {"items": [_run_row(finding_count=True)], "next": None},
        {"items": [_run_row(coverage_json=None)], "next": None},
    ],
)
def test_a_malformed_run_page_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path / "home")
    _answers(monkeypatch, store, [answer])

    with pytest.raises(RuntimeError, match="returned no answer"):
        reads.latest_runs(store)


@pytest.mark.parametrize("answer", [[], {"run_id": "r1"}, _run_row()])
def test_a_malformed_assessed_run_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    store = GuardStore(tmp_path / "home")
    _answers(monkeypatch, store, [answer])

    with pytest.raises(RuntimeError, match="returned no answer"):
        reads.latest_assessed_run(store, KEYS)


def test_a_malformed_worktree_row_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "home")
    row = {
        "codebase_key": KEYS.codebase_key,
        "worktree_key": KEYS.worktree_key,
        "root": "/work/0",
        "dirty_generation": "1",
        "last_completed_generation": 0,
        "last_scan_at_ms": None,
        "paused": 0,
        "admitted_at_ms": T0,
        "ended": 0,
    }
    _answers(monkeypatch, store, [{"items": [row], "next": None}])

    with pytest.raises(RuntimeError, match="returned no answer"):
        reads.list_worktrees(store)


def test_a_store_that_never_stops_paging_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(reads, "_MAX_PAGES", 3)
    _answers(monkeypatch, store, [{"items": [_run_row()], "next": [T0, "r1"]}] * 3)

    with pytest.raises(RuntimeError, match="kept paging"):
        reads.latest_runs(store)
