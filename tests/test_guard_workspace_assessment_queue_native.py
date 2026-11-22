"""The workspace assessment queue and admissions are run by the native store."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from codex_plugin_scanner.guard import workspace_assessment_admissions as admissions
from codex_plugin_scanner.guard import workspace_assessment_store as assessments


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KEYS = assessments.WorktreeKeys(_digest("codebase"), _digest("worktree"))
KEY_ARGS = {"codebase_key": KEYS.codebase_key, "worktree_key": KEYS.worktree_key}


class _Store:
    """Answers each native store call in order and records it."""

    def __init__(self, answers: list[object]) -> None:
        self.answers = iter(answers)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _native_store_call(self, method: str, args: dict[str, object], **_kwargs: Any) -> object:
        self.calls.append((method, dict(args)))
        return next(self.answers)


def _claimed(**overrides: object) -> dict[str, object]:
    answer: dict[str, object] = {
        "run_id": "r1",
        "codebase_key": KEYS.codebase_key,
        "worktree_key": KEYS.worktree_key,
        "private_root": "/work/a",
        "trigger_kind": "manual",
        "kind": "deterministic",
        "dirty_generation": 2,
        "lease_generation": 1,
        "detector_set_digest": _digest("detectors"),
    }
    answer.update(overrides)
    return answer


def test_enqueue_sends_a_fresh_run_id_and_reads_the_covering_run() -> None:
    store = _Store(["r1", None])
    covering = assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest="d", now_ms=4)
    assert covering == "r1"
    method, args = store.calls[0]
    assert method == "enqueue_workspace_assessment"
    assert {key: args[key] for key in KEY_ARGS} == KEY_ARGS
    assert args["kind"] == "deterministic" and args["trigger_kind"] == "manual"
    assert len(str(args["run_id"])) == 32
    assert assessments.enqueue(store, KEYS, trigger_kind="file_change", detector_set_digest="d", now_ms=5) is None
    with pytest.raises(ValueError, match="unknown workspace assessment trigger"):
        assessments.enqueue(_Store([]), KEYS, trigger_kind="hook", detector_set_digest="d", now_ms=1)


@pytest.mark.parametrize("answer", [3, "", ["r1"], True])
def test_a_malformed_enqueue_answer_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="enqueue_workspace_assessment"):
        assessments.enqueue(_Store([answer]), KEYS, trigger_kind="manual", detector_set_digest="d", now_ms=1)


def test_a_claim_becomes_a_claimed_run() -> None:
    store = _Store([_claimed(), None])
    claimed = assessments.claim_next(store, owner="w", now_ms=9, detector_set_digest="e", user_only=True)
    assert claimed == assessments.ClaimedRun(
        run_id="r1",
        keys=KEYS,
        private_root="/work/a",
        trigger_kind="manual",
        kind="deterministic",
        dirty_generation=2,
        lease_generation=1,
        detector_set_digest=_digest("detectors"),
    )
    assert store.calls[0] == (
        "claim_workspace_assessment",
        {"owner": "w", "now_ms": 9, "user_only": True, "detector_set_digest": "e"},
    )
    assert assessments.claim_next(store, owner="w", now_ms=9) is None
    assert "detector_set_digest" not in store.calls[1][1]


@pytest.mark.parametrize(
    "answer",
    [
        [],
        _claimed(extra=1),
        {key: value for key, value in _claimed().items() if key != "kind"},
        _claimed(lease_generation=True),
        _claimed(dirty_generation=-1),
        _claimed(run_id=7),
        _claimed(private_root=""),
    ],
)
def test_a_malformed_claim_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="claim_workspace_assessment"):
        assessments.claim_next(_Store([answer]), owner="w", now_ms=1)


def test_finish_sends_the_bounded_outcome_and_the_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assessments, "latest_assessed_run", lambda *_args: None)
    monkeypatch.setattr(assessments, "keep_package_identities", lambda outcome, *_a, **_k: (outcome, set()))
    run = assessments.ClaimedRun("r1", KEYS, "/work/a", "manual", "deterministic", 2, 1, "d")
    outcome = assessments.RunOutcome(state="completed", snapshot_digest="s", coverage={"b": 1, "a": 2})
    store = _Store([True, 1])
    assert assessments.finish(store, run, outcome, now_ms=7) is True
    method, args = store.calls[0]
    assert method == "finish_workspace_assessment"
    assert args["coverage_json"] == '{"a":2,"b":1}' and args["findings_json"] == "[]"
    assert (args["run_id"], args["lease_generation"], args["dirty_generation"]) == ("r1", 1, 2)
    assert (args["trigger_kind"], args["kind"], args["detector_set_digest"]) == ("manual", "deterministic", "d")
    with pytest.raises(RuntimeError, match="finish_workspace_assessment"):
        assessments.finish(store, run, outcome, now_ms=7)
    with pytest.raises(ValueError, match="invalid workspace assessment outcome state"):
        assessments.finish(_Store([]), run, assessments.RunOutcome(state="canceled"), now_ms=7)


def test_renew_cancel_and_pause_answer_with_a_flag() -> None:
    run = assessments.ClaimedRun("r1", KEYS, "/work/a", "manual", "deterministic", 2, 1, "d")
    store = _Store([True, False, True, None])
    assert assessments.renew_lease(store, run, now_ms=3) is True
    assert assessments.cancel(store, "r1", now_ms=4) is False
    assert assessments.set_paused(store, KEYS, paused=False) is True
    assert store.calls[0] == ("renew_workspace_assessment_lease", {"run_id": "r1", "lease_generation": 1, "now_ms": 3})
    assert store.calls[1] == ("cancel_workspace_assessment", {"run_id": "r1", "now_ms": 4})
    assert store.calls[2] == ("set_workspace_assessment_paused", {**KEY_ARGS, "paused": False})
    with pytest.raises(RuntimeError, match="set_workspace_assessment_paused"):
        assessments.set_paused(store, KEYS, paused=True)


def test_an_observation_returns_its_triggers() -> None:
    store = _Store([["file_change", "feed_change"], [], ["file_change", "file_change"], ["cron"]])
    assert assessments.record_observation(store, KEYS, stat_digest="s") == ("file_change", "feed_change")
    assert store.calls[0][1] == {**KEY_ARGS, "stat_digest": "s", "feed_digest": None}
    assert assessments.record_observation(store, KEYS) == ()
    for _ in range(2):
        with pytest.raises(RuntimeError, match="record_workspace_assessment_observation"):
            assessments.record_observation(store, KEYS)


def test_admission_sends_a_fresh_run_id() -> None:
    store = _Store(["r1", None, 5])
    kwargs: dict[str, Any] = {
        "root": "/work/a",
        "now_ms": 3,
        "automatic": True,
        "stat_digest": "s",
        "feed_digest": None,
        "detector_set_digest": "d",
    }
    assert admissions.admit_and_queue(store, KEYS, **kwargs) == "r1"
    assert admissions.admit_and_queue(store, KEYS, **kwargs) is None
    method, args = store.calls[0]
    assert method == "admit_workspace_assessment"
    assert args["automatic"] is True and len(str(args["run_id"])) == 32
    with pytest.raises(RuntimeError, match="admit_workspace_assessment"):
        admissions.admit_and_queue(store, KEYS, **kwargs)


def test_watched_roots_page_into_one_set() -> None:
    store = _Store([{"items": ["/a", "/b"], "next": ["c", "w1"]}, {"items": ["/a"], "next": None}])
    assert admissions.watched_roots(store, unavailable_digest="u") == {"/a", "/b"}
    assert "after" not in store.calls[0][1]
    assert store.calls[1][1] == {"unavailable_digest": "u", "after": ["c", "w1"]}


@pytest.mark.parametrize(
    "pages",
    [
        [None],
        [{"items": ["/a"]}],
        [{"items": [3], "next": None}],
        [{"items": [], "next": ["c", "w"]}],
        [{"items": ["/a"], "next": "c"}],
        [{"items": ["/a"], "next": ["c", "w"]}, {"items": ["/b"], "next": ["c", "w"]}],
    ],
)
def test_malformed_root_pages_are_refused(pages: list[object]) -> None:
    with pytest.raises(RuntimeError, match="workspace_assessment_watched_roots"):
        admissions.watched_roots(_Store(pages), unavailable_digest="u")


def test_manual_and_ended_admissions_answer_strictly() -> None:
    store = _Store([True, "yes", 2, -1, True])
    assert admissions.is_manual_admission(store, KEYS, root="/a") is True
    with pytest.raises(RuntimeError, match="is_manual_workspace_assessment_admission"):
        admissions.is_manual_admission(store, KEYS, root="/a")
    assert admissions.end_unregistered_install_admissions(store, {"/b", "/a"}, now_ms=4) == 2
    assert store.calls[2][1] == {"registered_roots": ["/a", "/b"], "now_ms": 4}
    for _ in range(2):
        with pytest.raises(RuntimeError, match="end_unregistered_workspace_assessment_admissions"):
            admissions.end_unregistered_install_admissions(store, [], now_ms=4)
