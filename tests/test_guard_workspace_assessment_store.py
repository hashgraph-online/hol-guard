from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_connection_schema import _REQUIRED_SCHEMA_MIGRATION_VERSIONS
from codex_plugin_scanner.guard.store_workspace_assessment_schema import WORKSPACE_ASSESSMENT_MIGRATION_VERSION

DETECTORS = "d" * 64
T0 = 1_000_000_000
AFTER_DEBOUNCE = T0 + assessments.DEBOUNCE_MS


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KEYS = assessments.WorktreeKeys(digest("codebase"), digest("worktree"))
OTHER = assessments.WorktreeKeys(digest("codebase"), digest("other-worktree"))


def admitted(tmp_path: Path, *keys: assessments.WorktreeKeys) -> GuardStore:
    store = GuardStore(tmp_path / "home")
    for index, item in enumerate(keys or (KEYS,)):
        assessments.admit_worktree(store, item, root=f"/work/{index}", now_ms=T0)
    return store


def enqueue(store: GuardStore, trigger: str = "file_change", *, at: int = T0, keys=KEYS) -> str | None:
    return assessments.enqueue(store, keys, trigger_kind=trigger, detector_set_digest=DETECTORS, now_ms=at)


def completed(state: str = "completed") -> assessments.RunOutcome:
    return assessments.RunOutcome(state=state, snapshot_digest=digest("snapshot"), coverage={"status": "complete"})


def test_store_applies_assessment_migration(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    with store._connect() as connection:
        versions = {row[0] for row in connection.execute("select version from schema_migrations")}
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type = 'table'")}
    assert WORKSPACE_ASSESSMENT_MIGRATION_VERSION in versions
    assert WORKSPACE_ASSESSMENT_MIGRATION_VERSION in _REQUIRED_SCHEMA_MIGRATION_VERSIONS
    assert {"workspace_assessment_state", "workspace_assessment_runs"} <= tables


def test_triggers_coalesce_into_one_queued_run(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    first = enqueue(store, "workspace_open")
    assert enqueue(store, "file_change") == first
    assert enqueue(store, "feed_change") == first
    [run] = assessments.recent_runs(store)
    assert run["dirty_generation"] == 3
    assert run["trigger_kind"] == "workspace_open"
    assert assessments.list_worktrees(store)[0]["stale"] is True


def test_automatic_run_waits_for_debounce(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store)
    assert assessments.claim_next(store, owner="w", now_ms=AFTER_DEBOUNCE - 1) is None
    claimed = assessments.claim_next(store, owner="w", now_ms=AFTER_DEBOUNCE)
    assert claimed is not None and claimed.private_root == "/work/0"


def test_later_change_restarts_the_debounce_up_to_the_maximum_wait(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store)
    enqueue(store, at=T0 + assessments.DEBOUNCE_MS - 1)
    assert assessments.claim_next(store, owner="w", now_ms=AFTER_DEBOUNCE) is None
    # A worktree that never stops changing is still assessed once the wait caps.
    step = assessments.DEBOUNCE_MS - 1
    for at in range(T0, T0 + assessments.MAX_DEBOUNCE_WAIT_MS, step):
        enqueue(store, at=at)
        assert assessments.claim_next(store, owner="w", now_ms=at) is None
    assert assessments.claim_next(store, owner="w", now_ms=T0 + assessments.MAX_DEBOUNCE_WAIT_MS) is not None


def test_manual_request_skips_debounce_and_upgrades_queued_run(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    run_id = enqueue(store, "file_change")
    assert enqueue(store, "manual") == run_id
    claimed = assessments.claim_next(store, owner="w", now_ms=T0)
    assert claimed is not None and claimed.trigger_kind == "manual"


def test_automatic_runs_respect_minimum_interval(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store)
    claimed = assessments.claim_next(store, owner="w", now_ms=AFTER_DEBOUNCE)
    assert claimed is not None
    assert assessments.finish(store, claimed, completed(), now_ms=AFTER_DEBOUNCE)
    enqueue(store, at=AFTER_DEBOUNCE)
    assert assessments.claim_next(store, owner="w", now_ms=AFTER_DEBOUNCE + assessments.DEBOUNCE_MS) is None
    later = AFTER_DEBOUNCE + assessments.MIN_INTERVAL_MS
    assert assessments.claim_next(store, owner="w", now_ms=later) is not None


def test_change_during_run_queues_a_newer_generation(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store, "manual")
    claimed = assessments.claim_next(store, owner="w", now_ms=T0)
    assert claimed is not None
    successor = enqueue(store, "file_change")
    assert successor is not None and successor != claimed.run_id
    # Only one run per worktree may hold a lease at a time.
    due = T0 + assessments.MIN_INTERVAL_MS + assessments.DEBOUNCE_MS
    assert assessments.claim_next(store, owner="w", now_ms=due) is None
    assert assessments.finish(store, claimed, completed(), now_ms=T0 + 1)
    [worktree] = assessments.list_worktrees(store)
    assert (worktree["last_completed_generation"], worktree["dirty_generation"]) == (1, 2)
    assert worktree["stale"] is True


def test_canceled_run_cannot_record_its_outcome(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store, "manual")
    claimed = assessments.claim_next(store, owner="w", now_ms=T0)
    assert claimed is not None
    assert assessments.cancel(store, claimed.run_id, now_ms=T0 + 1)
    assert not assessments.cancel(store, claimed.run_id, now_ms=T0 + 2)
    assert not assessments.finish(store, claimed, completed(), now_ms=T0 + 3)
    assert assessments.get_run(store, claimed.run_id)["state"] == "canceled"
    assert assessments.list_worktrees(store)[0]["last_completed_generation"] == 0


def test_expired_lease_is_failed_requeued_and_fenced(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store, "manual")
    stale = assessments.claim_next(store, owner="old", now_ms=T0)
    assert stale is not None
    expiry = T0 + assessments.LEASE_MS + 1
    fresh = assessments.claim_next(store, owner="new", now_ms=expiry)
    assert fresh is not None and fresh.run_id != stale.run_id
    assert fresh.trigger_kind == "manual"
    expired = assessments.get_run(store, stale.run_id)
    assert expired is not None
    assert (expired["state"], expired["error_code"]) == ("failed", "lease_expired")
    assert not assessments.finish(store, stale, completed(), now_ms=expiry + 1)
    assert assessments.finish(store, fresh, completed(), now_ms=expiry + 1)


def test_finish_after_the_lease_deadline_is_refused(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store, "manual")
    claimed = assessments.claim_next(store, owner="w", now_ms=T0)
    assert claimed is not None
    # No claim ran in between to expire the lease; the deadline alone fences it.
    assert not assessments.finish(store, claimed, completed(), now_ms=T0 + assessments.LEASE_MS + 1)
    assert assessments.get_run(store, claimed.run_id)["state"] == "running"


@pytest.mark.parametrize(("trigger", "successor"), [("manual", "manual"), ("file_change", "file_change")])
def test_superseded_run_queues_one_successor(tmp_path: Path, trigger: str, successor: str) -> None:
    store = admitted(tmp_path)
    enqueue(store, trigger)
    claimed = assessments.claim_next(store, owner="w", now_ms=T0 + assessments.MAX_DEBOUNCE_WAIT_MS)
    assert claimed is not None
    assert assessments.finish(store, claimed, completed("superseded"), now_ms=T0 + assessments.MAX_DEBOUNCE_WAIT_MS)
    runs = assessments.recent_runs(store)
    assert [run["state"] for run in runs].count("queued") == 1
    queued = next(run for run in runs if run["state"] == "queued")
    # A run the user asked for stays theirs: its successor skips the debounce.
    assert queued["trigger_kind"] == successor
    assert assessments.list_worktrees(store)[0]["last_completed_generation"] == 0


def test_device_worker_limit(tmp_path: Path) -> None:
    third = assessments.WorktreeKeys(digest("codebase"), digest("third"))
    store = admitted(tmp_path, KEYS, OTHER, third)
    for item in (KEYS, OTHER, third):
        enqueue(store, "manual", keys=item)
    assert assessments.claim_next(store, owner="w", now_ms=T0) is not None
    assert assessments.claim_next(store, owner="w", now_ms=T0) is not None
    assert assessments.claim_next(store, owner="w", now_ms=T0) is None


def test_paused_worktree_is_neither_queued_nor_observed(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    assert assessments.set_paused(store, KEYS, paused=True)
    assert enqueue(store, "manual") is None
    assert assessments.record_observation(store, KEYS, stat_digest=digest("a")) == ()
    assert assessments.list_worktrees(store, include_paused=False) == []
    assert not assessments.set_paused(store, assessments.WorktreeKeys(digest("x"), digest("y")), paused=True)


def test_paused_worktree_queued_run_is_not_claimed(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store, "manual")
    assessments.set_paused(store, KEYS, paused=True)
    assert assessments.claim_next(store, owner="w", now_ms=T0) is None


def test_observation_triggers_only_on_a_change(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    assert assessments.record_observation(store, KEYS, stat_digest=digest("a"), feed_digest=digest("f")) == ()
    assert assessments.record_observation(store, KEYS, stat_digest=digest("a"), feed_digest=digest("f")) == ()
    assert assessments.record_observation(store, KEYS, stat_digest=digest("b")) == ("file_change",)
    assert assessments.record_observation(store, KEYS, feed_digest=digest("g")) == ("feed_change",)
    # An unreadable worktree reports nothing rather than a change.
    assert assessments.record_observation(store, KEYS, stat_digest=None) == ()


def test_latest_assessed_runs_skip_failed_runs(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store, "manual")
    first = assessments.claim_next(store, owner="w", now_ms=T0)
    assert first is not None
    findings = [{"finding_id": "a" * 32, "package_name": "left-pad"}]
    outcome = assessments.RunOutcome(state="partial", snapshot_digest=digest("s"), findings=findings)
    assert assessments.finish(store, first, outcome, now_ms=T0 + 1)
    enqueue(store, "manual", at=T0 + 2)
    second = assessments.claim_next(store, owner="w", now_ms=T0 + 2)
    assert second is not None
    failed = assessments.RunOutcome(state="failed", error_code="workspace_snapshot_failed")
    assert assessments.finish(store, second, failed, now_ms=T0 + 3)
    [latest] = assessments.latest_assessed_runs(store)
    assert (latest["run_id"], latest["state"], latest["findings"]) == (first.run_id, "partial", findings)
    history = {run["run_id"]: run for run in assessments.recent_runs(store)}
    assert history[first.run_id]["finding_count"] == 1
    assert "findings" not in history[first.run_id]


def test_latest_runs_keep_every_worktree_when_history_is_capped(tmp_path: Path) -> None:
    store = admitted(tmp_path, KEYS, OTHER)
    enqueue(store, "manual", keys=OTHER)
    busy = assessments.claim_next(store, owner="w", now_ms=T0)
    assert busy is not None and busy.keys == OTHER
    for step in range(3):
        enqueue(store, "manual", at=T0 + 1 + step * 2, keys=KEYS)
        claimed = assessments.claim_next(store, owner="w", now_ms=T0 + 1 + step * 2)
        assert claimed is not None and claimed.keys == KEYS
        assert assessments.finish(store, claimed, completed(), now_ms=T0 + 2 + step * 2)
    capped = assessments.recent_runs(store, limit=1)
    assert {run["worktree_key"] for run in capped} == {KEYS.worktree_key}
    latest = {run["worktree_key"]: run for run in assessments.latest_runs(store)}
    assert set(latest) == {KEYS.worktree_key, OTHER.worktree_key}
    assert latest[OTHER.worktree_key]["state"] == "running"
    assert latest[KEYS.worktree_key]["run_id"] == capped[0]["run_id"]
    assert "findings" not in latest[OTHER.worktree_key]


def test_oversized_result_is_rejected_before_storage(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store, "manual")
    claimed = assessments.claim_next(store, owner="w", now_ms=T0)
    assert claimed is not None
    huge = [{"package_name": "x" * 1024} for _ in range(400)]
    outcome = assessments.RunOutcome(state="completed", snapshot_digest=digest("s"), findings=huge)
    with pytest.raises(ValueError):
        assessments.finish(store, claimed, outcome, now_ms=T0 + 1)
    assert assessments.get_run(store, claimed.run_id)["state"] == "running"


def test_generations_cannot_move_backward(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    enqueue(store)
    connection = sqlite3.connect(store.path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("update workspace_assessment_state set dirty_generation = 0")
    finally:
        connection.close()


def test_unknown_trigger_is_rejected(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    with pytest.raises(ValueError):
        enqueue(store, "hook")
