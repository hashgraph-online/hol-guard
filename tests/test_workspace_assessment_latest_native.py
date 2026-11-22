from __future__ import annotations

from collections.abc import Mapping

import pytest

from codex_plugin_scanner.guard import workspace_assessment_reads as reads
from codex_plugin_scanner.guard.workspace_assessment_runner import feed_context_digest
from codex_plugin_scanner.guard.workspace_assessment_store import WorktreeKeys


class _Store:
    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> object:
        self.calls.append((method, dict(args)))
        return self.answers.pop(0)


def _run(worktree: str) -> dict[str, object]:
    return {
        "run_id": f"run-{worktree}",
        "codebase_key": "cb",
        "worktree_key": worktree,
        "snapshot_digest": None,
        "kind": "full",
        "trigger_kind": "manual",
        "state": "completed",
        "dirty_generation": 1,
        "coverage_json": '{"secrets": "complete"}',
        "findings_json": '[{"id": "f1"}]',
        "error_code": None,
        "created_at_ms": 1,
        "started_at_ms": 2,
        "finished_at_ms": 3,
    }


def test_feed_digest_comes_from_the_native_store() -> None:
    digest = "a" * 64
    store = _Store(digest)

    assert feed_context_digest(store) == digest
    assert store.calls == [("workspace_assessment_feed_digest", {})]


@pytest.mark.parametrize("answer", [None, 7, "A" * 64, "a" * 63, "a" * 65, "g" * 64])
def test_a_malformed_feed_digest_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="returned no answer"):
        feed_context_digest(_Store(answer))


def test_latest_assessed_runs_pages_and_decodes_findings() -> None:
    store = _Store(
        {"items": [_run("wt-a")], "next": ["cb", "wt-a", 2, 1]},
        {"items": [_run("wt-b")], "next": None},
    )

    runs = reads.latest_assessed_runs(store)

    assert [run["worktree_key"] for run in runs] == ["wt-a", "wt-b"]
    assert runs[0]["findings"] == [{"id": "f1"}]
    assert runs[0]["coverage"] == {"secrets": "complete"}
    assert store.calls == [
        ("list_latest_assessed_workspace_runs", {}),
        ("list_latest_assessed_workspace_runs", {"after": ["cb", "wt-a", 2, 1]}),
    ]


def test_latest_assessed_runs_sends_the_selected_keys() -> None:
    store = _Store({"items": [], "next": None})

    assert reads.latest_assessed_runs(store, [WorktreeKeys("cb", "wt-a"), WorktreeKeys("cb", "wt-b")]) == []
    assert store.calls == [("list_latest_assessed_workspace_runs", {"keys": [["cb", "wt-a"], ["cb", "wt-b"]]})]


def test_no_selected_keys_reads_nothing() -> None:
    store = _Store()

    assert reads.latest_assessed_runs(store, []) == []
    assert store.calls == []


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"items": [{**_run("wt-a"), "findings_json": None}], "next": None},
        {"items": [{key: value for key, value in _run("wt-a").items() if key != "findings_json"}], "next": None},
        {"items": [_run("wt-a")]},
    ],
)
def test_a_malformed_latest_listing_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="returned no answer"):
        reads.latest_assessed_runs(_Store(answer))
