"""Runtimes a workspace's tools would launch, assessed with the workspace.

A runtime that matches an advisory becomes an observation-only finding of the
agent inventory domain; a runtime that changes on disk queues a reassessment;
and coverage never claims runtimes were checked when advisories were missing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard import workspace_runtime_findings as runtimes
from codex_plugin_scanner.guard.runtime import workspace_assessment_sync as sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import (
    AUDIT,
    KEYS,
    SCANNED,
    SNAPSHOT,
    T0,
    digest,
    queued_run,
    snapshots,
)

NODE = {
    "path": "/home/dev/.nvm/versions/node/v20.11.1/bin/node",
    "location_state": "present",
    "artifact_id": "rt-node",
    "family": "node",
    "version": "20.11.1",
    "executable_sha256": "a" * 64,
    "identity_assurance": "observed",
}


def posture(*, advisories: list[dict[str, object]] | None = None, available: bool = True, **extra) -> dict:
    return {
        "status": "ok",
        "coverage": {"advisories_available": available, "reason": None if available else "not_connected"},
        "runtimes": [NODE],
        "advisories": advisories if advisories is not None else [],
        "unresolved_launches": [],
        "skipped_harnesses": [],
        **extra,
    }


def advisory(verdict: str, advisory_id: str = "GHSA-node-0001", **extra) -> dict[str, object]:
    return {
        "advisory_id": advisory_id,
        "verdict": verdict,
        "reasons": [],
        "affected_artifact_ids": ["rt-node"],
        "severity": "HIGH",
        "known_exploited": True,
        "title": "Path traversal in node",
        **extra,
    }


@pytest.fixture(autouse=True)
def fresh_observations():
    runtimes._observed.clear()
    yield
    runtimes._observed.clear()


@pytest.mark.parametrize("verdict", ["affected", "restart_required", "fix_unverified"])
def test_an_advisory_matching_a_launched_runtime_is_an_observation_finding(verdict: str) -> None:
    findings, truncated = runtimes.project_runtime_findings(KEYS.worktree_key, posture(advisories=[advisory(verdict)]))
    assert truncated is False
    [finding] = findings
    assert finding["source_kind"] == "agent_inventory"
    assert finding["detector"] == "runtime_identity_v1"
    assert (finding["severity"], finding["decision"], finding["known_exploited"]) == ("high", "warn", True)
    assert (finding["runtime_family"], finding["runtime_version"]) == ("node", "20.11.1")
    assert (finding["package_name"], finding["ecosystem"]) == (None, None)
    assert finding["rule_ids"] == [verdict]
    assert finding["advisory_ids"] == ["GHSA-node-0001"]
    again, _ = runtimes.project_runtime_findings(KEYS.worktree_key, posture(advisories=[advisory(verdict)]))
    assert again[0]["finding_id"] == finding["finding_id"], "the same runtime and advisory keep one identity"


@pytest.mark.parametrize("verdict", ["fixed_verified", "not_affected", "not_observed", "unknown"])
def test_settled_or_unknown_verdicts_are_not_findings(verdict: str) -> None:
    assert runtimes.project_runtime_findings(KEYS.worktree_key, posture(advisories=[advisory(verdict)])) == ([], False)


def test_findings_are_capped_and_the_cap_is_reported() -> None:
    many = [advisory("affected", f"GHSA-node-{index:04d}") for index in range(runtimes.MAX_RUNTIME_FINDINGS + 1)]
    findings, truncated = runtimes.project_runtime_findings(KEYS.worktree_key, posture(advisories=many))
    assert (len(findings), truncated) == (runtimes.MAX_RUNTIME_FINDINGS, True)


def test_coverage_never_claims_runtimes_were_checked_without_advisories() -> None:
    base = {"status": "complete", "reasons": [], "detectors": {"supply_chain": "complete", "secrets": "complete"}}
    checked = runtimes.with_runtime_coverage(base, posture())
    assert (checked["status"], checked["reasons"]) == ("complete", [])
    assert checked["detectors"]["runtime_identity_v1"] == "complete"
    assert checked["runtimes"]["runtime_count"] == 1

    unchecked = runtimes.with_runtime_coverage(base, posture(available=False))
    assert unchecked["status"] == "partial"
    assert unchecked["reasons"] == ["runtime_advisories_unavailable"]
    assert unchecked["detectors"]["runtime_identity_v1"] == "incomplete"

    unknown = runtimes.with_runtime_coverage(base, posture(advisories=[advisory("unknown")]))
    assert (unknown["status"], unknown["reasons"]) == ("partial", ["runtimes_incomplete"])

    nothing = runtimes.with_runtime_coverage(base, {**posture(available=False), "runtimes": []})
    assert (nothing["status"], nothing["detectors"]["runtime_identity_v1"]) == ("complete", "no_inputs")

    for missing in (None, {"status": "unavailable"}):
        not_run = runtimes.with_runtime_coverage(base, missing)
        assert not_run["reasons"] == ["detector_not_run:runtime_identity_v1"]
        assert (not_run["status"], not_run["detectors"]["runtime_identity_v1"]) == ("partial", "not_run")


def test_runtime_digest_follows_identity_not_advisories() -> None:
    first = runtimes.runtime_identity_digest(posture())
    assert first == runtimes.runtime_identity_digest(posture(advisories=[advisory("affected")]))
    replaced = {**posture(), "runtimes": [{**NODE, "executable_sha256": "b" * 64}]}
    assert runtimes.runtime_identity_digest(replaced) != first
    assert runtimes.runtime_identity_digest({"status": "unavailable"}) is None


def test_runtime_observation_is_throttled_and_survives_a_failed_probe(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    seen: list[dict] = [posture()]
    calls: list[Path] = []

    def observe(store, root, *, home_dir=None):
        calls.append(root)
        if isinstance(seen[0], Exception):
            raise seen[0]
        return seen[0]

    monkeypatch.setattr(runtimes, "observe_workspace_runtimes", observe)
    first = runtimes.observed_runtime_digest(store, KEYS.worktree_key, tmp_path, now_ms=T0)
    assert runtimes.observed_runtime_digest(store, KEYS.worktree_key, tmp_path, now_ms=T0 + 1) == first
    assert len(calls) == 1, "a second poll inside the interval does not probe again"
    seen[0] = RuntimeError("probe failed")
    later = T0 + runtimes.RUNTIME_OBSERVE_INTERVAL_MS
    assert runtimes.observed_runtime_digest(store, KEYS.worktree_key, tmp_path, now_ms=later) == first
    seen[0] = {**posture(), "runtimes": [{**NODE, "version": "20.12.0"}]}
    changed = runtimes.observed_runtime_digest(store, KEYS.worktree_key, tmp_path, now_ms=later * 2)
    assert changed not in (None, first)


def test_a_replaced_runtime_queues_a_reassessment(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat"))
    current = {"digest": digest("runtime-1")}
    monkeypatch.setattr(worker, "observed_runtime_digest", lambda store, key, root, *, now_ms: current["digest"])
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    worker.observe(store, clock=lambda: T0)
    before = assessments.list_worktrees(store)[0]["dirty_generation"]
    assert worker.observe(store, clock=lambda: T0) == 0, "an unchanged runtime stays quiet"
    current["digest"] = digest("runtime-2")
    worker.observe(store, clock=lambda: T0)
    assert assessments.list_worktrees(store)[0]["dirty_generation"] == before + 1


def test_a_context_recorded_before_the_upgrade_queues_one_reassessment(tmp_path: Path, monkeypatch) -> None:
    # A worktree assessed by the previous release keeps its digests; its stored
    # result predates the unsupported-lockfile coverage reason, so it must rerun.
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat"))
    runtime = digest("runtime-1")
    monkeypatch.setattr(worker, "observed_runtime_digest", lambda store, key, root, *, now_ms: runtime)
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    worker.observe(store, clock=lambda: T0)
    previous = f"guard.workspace-context.v1\0{runner.feed_context_digest(store)}\0{runtime}"
    assessments.record_observation(store, KEYS, feed_digest=hashlib.sha256(previous.encode()).hexdigest())
    before = assessments.list_worktrees(store)[0]["dirty_generation"]
    worker.observe(store, clock=lambda: T0)
    assert assessments.list_worktrees(store)[0]["dirty_generation"] == before + 1
    assert worker.observe(store, clock=lambda: T0) == 0, "only once"


def test_a_run_reports_runtime_findings_and_coverage(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    monkeypatch.setattr(
        runner, "observe_workspace_runtimes", lambda store, root: posture(advisories=[advisory("affected")])
    )
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert outcome.state == "completed"
    assert outcome.coverage is not None
    assert outcome.coverage["detectors"]["runtime_identity_v1"] == "complete"
    assert sorted(str(finding["source_kind"]) for finding in outcome.findings) == ["agent_inventory", "supply_chain"]
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)


def test_a_failed_runtime_probe_leaves_the_run_partial(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)

    def broken(store, root):
        raise RuntimeError(f"cannot read {root}")

    monkeypatch.setattr(runner, "observe_workspace_runtimes", broken)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert outcome.state == "partial"
    assert outcome.coverage is not None
    assert "detector_not_run:runtime_identity_v1" in outcome.coverage["reasons"]
    assert all(finding["source_kind"] != "agent_inventory" for finding in outcome.findings)


def test_runtime_findings_sync_without_paths(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    monkeypatch.setattr(
        runner, "observe_workspace_runtimes", lambda store, root: posture(advisories=[advisory("affected")])
    )
    assert assessments.finish(store, claimed, runner.execute(store, None, claimed, clock=lambda: T0), now_ms=T0 + 1)
    built = sync.build_workspace_assessment_sync(store, now="2026-01-01T00:00:00+00:00")
    assert built is not None
    text = json.dumps(built.payload)
    assert NODE["path"] not in text and "nvm" not in text
    [entry] = built.payload["worktrees"]
    [runtime] = [item for item in entry["findings"] if item["sourceKind"] == "agent_inventory"]
    assert (runtime["detector"], runtime["packageName"], runtime["advisoryIds"]) == (
        "runtime_identity_v1",
        None,
        ["GHSA-node-0001"],
    )
    assert entry["assessment"]["coverage"]["detectors"]["runtime_identity_v1"] == "complete"


def test_a_finished_run_leaves_the_next_observation_quiet(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat"))
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    monkeypatch.setattr(runner, "observe_workspace_runtimes", lambda store, root: posture())
    monkeypatch.setattr(runtimes, "observe_workspace_runtimes", lambda store, root, *, home_dir=None: posture())
    assert assessments.finish(store, claimed, runner.execute(store, None, claimed, clock=lambda: T0), now_ms=T0 + 1)
    # The run stored the context it assessed; observing the same context must
    # not queue another run, or the worker would reassess forever.
    assert worker.observe(store, clock=lambda: T0 + 2) == 0


def test_unresolved_or_unidentified_launches_leave_runtimes_incomplete() -> None:
    base = {"status": "complete", "reasons": [], "detectors": {}}
    launch = {"harness": "codex", "server": "tools", "command": "node", "lookup": "path"}
    unresolved = runtimes.with_runtime_coverage(base, {**posture(), "runtimes": [], "unresolved_launches": [launch]})
    assert (unresolved["reasons"], unresolved["detectors"]["runtime_identity_v1"]) == (
        ["runtimes_incomplete"],
        "incomplete",
    ), "a launch Guard could not resolve is not the same as launching nothing"
    unreadable = {**NODE, "artifact_id": None, "family": None, "location_state": "unreadable"}
    unidentified = runtimes.with_runtime_coverage(base, {**posture(), "runtimes": [unreadable]})
    assert unidentified["reasons"] == ["runtimes_incomplete"]


def test_every_path_of_a_matched_runtime_is_a_finding() -> None:
    copy = {**NODE, "path": "/opt/tools/bin/node"}
    findings, _ = runtimes.project_runtime_findings(
        KEYS.worktree_key, {**posture(advisories=[advisory("affected")]), "runtimes": [NODE, copy]}
    )
    assert sorted(str(finding["path"]) for finding in findings) == sorted([NODE["path"], copy["path"]])
    assert len({finding["finding_id"] for finding in findings}) == 2


def test_the_cap_keeps_known_exploited_and_severe_findings() -> None:
    minor = [
        advisory("affected", f"GHSA-node-{index:04d}", severity="LOW", known_exploited=False)
        for index in range(runtimes.MAX_RUNTIME_FINDINGS)
    ]
    critical = advisory("affected", "GHSA-node-late", severity="CRITICAL", known_exploited=True)
    findings, truncated = runtimes.project_runtime_findings(KEYS.worktree_key, posture(advisories=[*minor, critical]))
    assert truncated is True
    assert findings[0]["advisory_ids"] == ["GHSA-node-late"], "a late critical advisory survives the cap"


def test_a_launch_past_the_candidate_limit_changes_the_runtime_digest() -> None:
    limited = {**posture(), "status": "partial", "candidate_limit_reached": True}
    assert runtimes.runtime_identity_digest(limited) != runtimes.runtime_identity_digest(posture())


def test_a_failed_probe_is_logged_without_its_path(tmp_path: Path, monkeypatch, caplog) -> None:
    store = GuardStore(tmp_path / "home")

    def broken(store, root, *, home_dir=None):
        raise OSError(f"cannot read {root}/secret-config.json")

    monkeypatch.setattr(runtimes, "observe_workspace_runtimes", broken)
    with caplog.at_level("WARNING", logger=runtimes.__name__):
        assert runtimes.observed_runtime_digest(store, KEYS.worktree_key, tmp_path, now_ms=T0) is None
    assert "workspace runtime probe failed: OSError" in caplog.text
    assert str(tmp_path) not in caplog.text


def test_an_observation_pass_probes_a_bounded_number_of_worktrees(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    rows = [
        {"codebase_key": "c" * 64, "worktree_key": f"{index:064d}", "root": str(tmp_path / str(index))}
        for index in range(5)
    ]
    monkeypatch.setattr(worker.assessments, "list_worktrees", lambda store, include_paused=False: rows)
    monkeypatch.setattr(worker.assessments, "record_observation", lambda *args, **kwargs: [])

    def unavailable(root, *, mode):
        raise worker.WorkspaceSnapshotError("workspace_root_missing")

    monkeypatch.setattr(worker, "workspace_snapshot", unavailable)
    probed: list[str] = []

    def observe(store, root, *, home_dir=None):
        probed.append(root.name)
        return posture()

    monkeypatch.setattr(runtimes, "observe_workspace_runtimes", observe)
    worker.observe(store, clock=lambda: T0)
    assert probed == ["0", "1"], "a restart does not hash every worktree's runtimes in one poll"
    worker.observe(store, clock=lambda: T0 + 1)
    assert probed == ["0", "1", "2", "3"], "the rest are probed by later polls"
