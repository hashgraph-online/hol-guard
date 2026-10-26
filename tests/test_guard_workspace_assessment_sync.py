"""The workspace assessment summary sent with receipt sync."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import workspace_assessment_reads as reads
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime import workspace_assessment_sync as sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_runner_sync_payload import _add_receipts, _install_transport, store  # noqa: F401

DETECTORS = "d" * 64
T0 = 1_000_000_000
NOW = "2026-10-24T12:00:00Z"
ROOT = "/Users/someone/private-project"
pytestmark = [pytest.mark.usefixtures("native_hook_force")]


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


KEYS = assessments.WorktreeKeys(digest("codebase"), digest("worktree"))


def finding(index: int) -> dict[str, object]:
    return {
        "finding_id": f"{index:032x}",
        "source_kind": "supply_chain",
        "detector": "package_advisory",
        "severity": "high",
        "decision": "block",
        "ecosystem": "npm",
        "package_name": f"pkg-{index}",
        "package_version": "1.0.0",
        "fix_version": "1.0.1",
        "rule_ids": ["rule-1"],
        "advisory_ids": ["GHSA-aaaa-bbbb-cccc"],
        "validation_state": "confirmed",
        "lifecycle_state": "open",
        "path": f"{ROOT}/package-lock.json",
    }


def assessed(
    guard_store: GuardStore,
    *,
    state: str = "completed",
    findings: list[dict[str, object]] | None = None,
    at: int = T0,
    reasons: list[str] | None = None,
) -> None:
    assessments.admit_worktree(guard_store, KEYS, root=ROOT, now_ms=T0)
    assessments.enqueue(guard_store, KEYS, trigger_kind="workspace_open", detector_set_digest=DETECTORS, now_ms=at)
    claimed = assessments.claim_next(guard_store, owner="test", now_ms=at + assessments.DEBOUNCE_MS)
    assert claimed is not None
    coverage = {
        "status": "complete" if state == "completed" else "partial",
        "reasons": reasons if reasons is not None else [] if state == "completed" else ["lockfile_missing"],
        "detectors": {"supply_chain": "complete"},
        "head_commit": "f" * 40,
    }
    outcome = assessments.RunOutcome(
        state=state,
        snapshot_digest=digest(f"snapshot-{at}"),
        coverage=coverage,
        findings=findings if findings is not None else [finding(1)],
    )
    assert assessments.finish(guard_store, claimed, outcome, now_ms=at + assessments.DEBOUNCE_MS + 10)


def test_nothing_is_sent_without_an_admitted_worktree(tmp_path: Path) -> None:
    assert sync.build_workspace_assessment_sync(GuardStore(tmp_path / "home"), now=NOW) is None


def test_summary_rekeys_identifiers_and_never_carries_paths_or_commits(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store)

    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)

    assert built is not None
    text = json.dumps(built.payload)
    for private in (ROOT, KEYS.codebase_key, KEYS.worktree_key, "f" * 40, f"{1:032x}", "package-lock"):
        assert private not in text
    [entry] = built.payload["worktrees"]
    assert entry["status"] == "fresh"
    assert entry["codebaseKey"].startswith("sha256:") and len(entry["codebaseKey"]) == 71
    assert entry["assessment"]["coverage"] == {
        "status": "complete",
        "reasons": [],
        "detectors": {"supply_chain": "complete"},
    }
    [item] = entry["findings"]
    assert item["packageName"] == "pkg-1"
    assert item["fixVersion"] == "1.0.1"
    assert item["advisoryIds"] == ["GHSA-aaaa-bbbb-cccc"]
    assert "path" not in item


def test_snapshot_digest_is_rekeyed_and_the_stored_digest_never_leaves(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store)
    stored = digest(f"snapshot-{T0}")

    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)

    assert built is not None
    assert stored not in json.dumps(built.payload)
    [entry] = built.payload["worktrees"]
    sent = entry["assessment"]["snapshotDigest"]
    assert re.fullmatch(r"[0-9a-f]{64}", sent) and sent != stored
    assert sync.build_workspace_assessment_sync(guard_store, now=NOW).payload["worktrees"] == built.payload["worktrees"]


def test_partial_runs_report_partial_coverage_never_all_clear(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store, state="partial", findings=[])

    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)

    assert built is not None
    [entry] = built.payload["worktrees"]
    assert entry["status"] == "partial"
    assert entry["assessment"]["coverage"]["status"] == "partial"
    assert entry["assessment"]["coverage"]["reasons"] == ["lockfile_missing"]


def test_status_reflects_paused_and_queued_worktrees(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store)
    assessments.enqueue(guard_store, KEYS, trigger_kind="file_change", detector_set_digest=DETECTORS, now_ms=T0 * 2)

    queued = sync.build_workspace_assessment_sync(guard_store, now=NOW)
    assert queued is not None and queued.payload["worktrees"][0]["status"] == "queued"

    assessments.set_paused(guard_store, KEYS, paused=True)
    paused = sync.build_workspace_assessment_sync(guard_store, now=NOW)
    assert paused is not None and paused.payload["worktrees"][0]["status"] == "paused"


def test_unchanged_summary_is_resent_only_after_a_day(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store)
    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)
    assert built is not None

    sync.commit_workspace_assessment_sent(guard_store, built, now=NOW)

    assert sync.build_workspace_assessment_sync(guard_store, now="2026-10-25T11:59:00Z") is None
    assert sync.build_workspace_assessment_sync(guard_store, now="2026-10-25T12:00:00Z") is not None
    assessed(guard_store, findings=[finding(2)], at=T0 * 3)
    assert sync.build_workspace_assessment_sync(guard_store, now="2026-10-24T12:05:00Z") is not None


def test_findings_are_capped_and_flagged(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store, findings=[finding(index) for index in range(sync.MAX_FINDINGS_PER_WORKTREE + 5)])

    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)

    assert built is not None
    [entry] = built.payload["worktrees"]
    assert len(entry["findings"]) == sync.MAX_FINDINGS_PER_WORKTREE
    assert entry["findingsTruncated"] is True
    assert len(json.dumps(built.payload).encode()) <= sync.MAX_SUMMARY_BYTES + 1024


def test_a_secret_scan_that_hit_its_cap_is_synced_as_truncated(tmp_path: Path) -> None:
    from dataclasses import replace

    from codex_plugin_scanner.guard import workspace_assessment_runner as runner
    from tests.test_guard_workspace_assessment_runner import AUDIT, SECRETS_COMPLETE, SNAPSHOT

    capped = replace(
        SNAPSHOT, secrets={**SECRETS_COMPLETE, "status": "incomplete", "truncation_reasons": ["max_findings"]}
    )
    coverage = runner.coverage_summary(capped, AUDIT, findings_truncated=False)
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store, state="partial", findings=[finding(1)], reasons=list(coverage["reasons"]))

    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)

    assert built is not None
    [entry] = built.payload["worktrees"]
    # The receiver must not close secrets this partial list left off.
    assert entry["findingsTruncated"] is True


def test_summary_rides_on_the_first_batch_and_commits_after_delivery(
    store: GuardStore,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessed(store)
    _add_receipts(store, guard_runner_module._RECEIPT_SYNC_BATCH_SIZE + 1)
    bodies = _install_transport(monkeypatch)

    guard_runner_module.sync_receipts(store)

    assert bodies[0]["syncContext"]["workspaceAssessments"]["schemaVersion"] == sync.SCHEMA_VERSION
    assert all("workspaceAssessments" not in body["syncContext"] for body in bodies[1:])
    assert store.get_sync_payload(sync.DELIVERY_STATE_KEY)

    guard_runner_module.sync_receipts(store)
    assert "workspaceAssessments" not in bodies[-1]["syncContext"]


def test_summary_is_not_committed_when_the_request_fails(
    store: GuardStore,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessed(store)
    _add_receipts(store, 1)
    _install_transport(monkeypatch, fail_after=0)

    with pytest.raises(Exception):  # noqa: B017 - any transport failure surfaces from sync_receipts
        guard_runner_module.sync_receipts(store)

    assert not store.get_sync_payload(sync.DELIVERY_STATE_KEY)


def test_summary_failure_never_blocks_receipt_sync(
    store: GuardStore,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _add_receipts(store, 1)
    bodies = _install_transport(monkeypatch)

    def boom(*_args, **_kwargs):
        raise RuntimeError("builder exploded")

    monkeypatch.setattr(sync, "build_workspace_assessment_sync", boom)

    summary = guard_runner_module.sync_receipts(store)

    assert summary["receipts"] == 1
    assert "workspaceAssessments" not in bodies[0]["syncContext"]


def test_findings_are_read_only_for_the_summarized_worktrees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store)
    other = assessments.WorktreeKeys(digest("other-codebase"), digest("other-worktree"))
    assessments.admit_worktree(guard_store, other, root=f"{ROOT}-other", now_ms=T0 + 1)
    monkeypatch.setattr(sync, "MAX_WORKTREES", 1)
    requested: list[object] = []
    original = reads.latest_assessed_runs

    def spy(guard: GuardStore, keys: object = None) -> list[dict[str, object]]:
        requested.append(keys)
        return original(guard, keys)

    monkeypatch.setattr(reads, "latest_assessed_runs", spy)

    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)

    assert built is not None and len(built.payload["worktrees"]) == 1
    assert requested == [[KEYS]]
    assert reads.latest_assessed_runs(guard_store, [other]) == []
    assert [run["worktree_key"] for run in reads.latest_assessed_runs(guard_store, [KEYS])] == [KEYS.worktree_key]
    assert reads.latest_assessed_runs(guard_store, []) == []


def test_request_fit_trims_findings_and_the_full_summary_is_sent_next_time(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store, findings=[finding(index) for index in range(sync.MAX_FINDINGS_PER_WORKTREE)])
    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)
    assert built is not None
    full = len(json.dumps(built.payload).encode())

    fitted = sync.fit_workspace_assessment_to_request(built, full // 2)

    assert fitted is not None and fitted.digest != built.digest
    sync.commit_workspace_assessment_sent(guard_store, fitted, now=NOW)
    assert sync.build_workspace_assessment_sync(guard_store, now="2026-10-24T12:05:00Z") is not None
    [entry] = fitted.payload["worktrees"]
    assert 0 < len(entry["findings"]) < sync.MAX_FINDINGS_PER_WORKTREE
    assert entry["findingsTruncated"] is True
    assert len(json.dumps(fitted.payload).encode()) <= full // 2
    assert len(built.payload["worktrees"][0]["findings"]) == sync.MAX_FINDINGS_PER_WORKTREE
    assert sync.fit_workspace_assessment_to_request(built, 10) is None


def test_whole_request_stays_within_budget_when_the_summary_shares_it(
    store: GuardStore,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessed(store, findings=[finding(index) for index in range(sync.MAX_FINDINGS_PER_WORKTREE)])
    _add_receipts(store, 10)
    bodies = _install_transport(monkeypatch)
    built = sync.build_workspace_assessment_sync(store, now=NOW)
    assert built is not None
    budget = len(json.dumps(built.payload).encode()) // 2
    monkeypatch.setattr(guard_runner_module, "_WORKSPACE_ASSESSMENT_REQUEST_BYTES", budget)

    guard_runner_module.sync_receipts(store)

    assert len(bodies[0]["receipts"]) == 10
    assert len(json.dumps(bodies[0]).encode()) <= budget
    [entry] = bodies[0]["syncContext"]["workspaceAssessments"]["worktrees"]
    assert entry["findingsTruncated"] is True


def test_built_summary_trims_coverage_when_findings_alone_cannot_fit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store, state="partial", findings=[], reasons=[f"{index:02d}" + "r" * 126 for index in range(32)])
    full = sync.build_workspace_assessment_sync(guard_store, now=NOW)
    assert full is not None
    limit = len(json.dumps(full.payload).encode()) // 2
    monkeypatch.setattr(sync, "MAX_SUMMARY_BYTES", limit)

    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)

    assert built is not None and len(json.dumps(built.payload).encode()) <= limit
    [entry] = built.payload["worktrees"]
    assert 0 < len(entry["assessment"]["coverage"]["reasons"]) < 32
    assert entry["assessment"]["coverage"]["reasons"][0].startswith("00")
    assert entry["findingsTruncated"] is True
    monkeypatch.setattr(sync, "MAX_SUMMARY_BYTES", 50)
    assert sync.build_workspace_assessment_sync(guard_store, now=NOW) is None


def test_summary_waits_for_a_later_batch_when_the_first_cannot_fit_it(
    store: GuardStore,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assessed(store)
    _add_receipts(store, guard_runner_module._RECEIPT_SYNC_BATCH_SIZE + 1)
    bodies = _install_transport(monkeypatch)
    real_fit = sync.fit_workspace_assessment_to_request
    calls: list[int] = []

    def first_batch_too_full(built: sync.WorkspaceAssessmentSyncBuild, max_bytes: int):
        calls.append(max_bytes)
        return None if len(calls) == 1 else real_fit(built, max_bytes)

    monkeypatch.setattr(guard_runner_module, "fit_workspace_assessment_to_request", first_batch_too_full)

    guard_runner_module.sync_receipts(store)

    assert len(calls) == 2
    assert "workspaceAssessments" not in bodies[0]["syncContext"]
    assert bodies[1]["syncContext"]["workspaceAssessments"]["schemaVersion"] == sync.SCHEMA_VERSION
    assert store.get_sync_payload(sync.DELIVERY_STATE_KEY)


def test_worktrees_dropped_from_a_request_are_sent_on_the_next_sync(tmp_path: Path) -> None:
    guard_store = GuardStore(tmp_path / "home")
    assessed(guard_store, findings=[])
    second = assessments.WorktreeKeys(digest("codebase-2"), digest("worktree-2"))
    assessments.admit_worktree(guard_store, second, root=ROOT + "-2", now_ms=T0 + 1)
    built = sync.build_workspace_assessment_sync(guard_store, now=NOW)
    assert built is not None and len(built.payload["worktrees"]) == 2
    one = len(json.dumps({**built.payload, "worktrees": built.payload["worktrees"][:1]}).encode())

    fitted = sync.fit_workspace_assessment_to_request(built, one)

    assert fitted is not None and len(fitted.payload["worktrees"]) == 1
    sync.commit_workspace_assessment_sent(guard_store, fitted, now=NOW)
    resent = sync.build_workspace_assessment_sync(guard_store, now="2026-10-24T12:05:00Z")
    assert resent is not None and len(resent.payload["worktrees"]) == 2
