from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import AUDIT, KEYS, SCANNED, T0, snapshots

MINUTE_MS = 60_000
NO_RUNTIMES = {"status": "ok", "coverage": {"advisories_available": False}, "runtimes": [], "advisories": []}


def manual_run(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "home")
    assessments.admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=runner.DETECTOR_SET_DIGEST, now_ms=T0)
    return store


def runs(store: GuardStore) -> list[tuple[str, str | None]]:
    with store._connect() as connection:
        rows = connection.execute(
            "select state, error_code from workspace_assessment_runs order by created_at_ms, rowid"
        ).fetchall()
    return [(str(row[0]), row[1]) for row in rows]


def test_a_run_that_outlasts_one_lease_still_records_its_result(tmp_path: Path, monkeypatch) -> None:
    store = manual_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    now = [T0]

    def slow(result):
        def stage(store, *args):
            now[0] += 3 * MINUTE_MS
            return result

        return stage

    monkeypatch.setattr(runner, "_local_audit", slow(AUDIT))
    monkeypatch.setattr(runner, "_runtime_posture", slow(NO_RUNTIMES))
    assert runner.run_next(store, None, owner="test", clock=lambda: now[0])
    assert now[0] - T0 > assessments.LEASE_MS
    assert runs(store) == [("completed", None)]


def test_canceling_a_running_assessment_skips_its_later_stages(tmp_path: Path, monkeypatch) -> None:
    store = manual_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    claimed: list[assessments.ClaimedRun] = []
    claim = assessments.claim_next
    monkeypatch.setattr(assessments, "claim_next", lambda *a, **k: claimed.append(claim(*a, **k)) or claimed[-1])
    posture_calls: list[Path] = []

    def audit(store, config, root):
        assert assessments.cancel(store, claimed[0].run_id, now_ms=T0 + 1)
        return AUDIT

    monkeypatch.setattr(runner, "_local_audit", audit)
    monkeypatch.setattr(runner, "_runtime_posture", lambda store, root: posture_calls.append(root))
    assert runner.run_next(store, None, owner="test", clock=lambda: T0)
    assert posture_calls == []
    assert runs(store) == [("canceled", None)]


def test_a_second_lease_expiry_stops_retrying(tmp_path: Path) -> None:
    store = manual_run(tmp_path)
    assert assessments.claim_next(store, owner="test", now_ms=T0) is not None
    retry = assessments.claim_next(store, owner="test", now_ms=T0 + assessments.LEASE_MS + 1)
    assert retry is not None and retry.trigger_kind == "manual"
    assert assessments.claim_next(store, owner="test", now_ms=T0 + 2 * assessments.LEASE_MS + 2) is None
    assert runs(store) == [("failed", "lease_expired"), ("failed", "assessment_timed_out")]


def test_a_run_queued_after_an_unretried_expiry_still_gets_its_retry(tmp_path: Path) -> None:
    # A paused worktree cannot queue the retry; the user's later run is a new
    # run with its own retry, not the second attempt of the expired one.
    store = manual_run(tmp_path)
    assert assessments.claim_next(store, owner="test", now_ms=T0) is not None
    assessments.set_paused(store, KEYS, paused=True)
    later = T0 + assessments.LEASE_MS + 1
    assert assessments.claim_next(store, owner="test", now_ms=later) is None
    assessments.set_paused(store, KEYS, paused=False)
    digest = runner.DETECTOR_SET_DIGEST
    assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=digest, now_ms=later + 2)
    assert assessments.claim_next(store, owner="test", now_ms=later + 2) is not None
    retry = assessments.claim_next(store, owner="test", now_ms=later + assessments.LEASE_MS + 3)
    assert retry is not None and retry.trigger_kind == "manual"
    assert runs(store)[:2] == [("failed", "lease_expired"), ("failed", "lease_expired")]
