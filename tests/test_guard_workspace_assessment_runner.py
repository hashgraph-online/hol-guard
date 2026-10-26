from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_supply_chain_egress as egress
from codex_plugin_scanner.guard import native_workspace_snapshot as native
from codex_plugin_scanner.guard import workspace_assessment_pressure as pressure
from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard import workspace_runtime_findings as runtimes
from codex_plugin_scanner.guard.daemon import workspace_assessment_api as api
from codex_plugin_scanner.guard.store import GuardStore

T0 = 1_000_000_000


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


SNAPSHOT = native.WorkspaceSnapshot(
    mode="content",
    root="/work",
    worktree_key=digest("worktree"),
    codebase_key=digest("codebase"),
    snapshot_digest=digest("content-1"),
    input_manifest_digest=digest("manifests"),
    head_commit="a" * 40,
    coverage="complete",
    partial_reasons=(),
    entry_count=3,
    summary={"entry_count": 3, "hashed_bytes": 120},
)
SECRETS_COMPLETE = {
    "schema": "guard.workspace-secrets.v1",
    "status": "complete",
    "files_scanned": 3,
    "bytes_scanned": 120,
    "skipped": {"credential_store": 0, "not_text": 0, "oversize": 0},
    "truncation_reasons": [],
    "findings": [],
}
SKILLS_COMPLETE = {
    "schema": "guard.workspace-skills.v1",
    "detector_version": "skill-content-v1",
    "status": "complete",
    "files_scanned": 0,
    "bytes_scanned": 0,
    "skipped": {"oversize": 0, "not_text": 0, "unread": 0, "linked": 0},
    "truncation_reasons": [],
    "findings": [],
}
HOOKS_COMPLETE = {
    "schema": "guard.workspace-hooks.v1",
    "detector_version": "hook-config-v1",
    "status": "complete",
    "files_scanned": 0,
    "commands_scanned": 0,
    "skipped": {"oversize": 0, "not_text": 0, "unparsed": 0, "unread": 0, "linked": 0},
    "truncation_reasons": [],
    "findings": [],
}
PLUGINS_COMPLETE = {
    "schema": "guard.workspace-plugins.v1",
    "detector_version": "plugin-manifest-v1",
    "status": "complete",
    "plugins_scanned": 0,
    "files_scanned": 0,
    "commands_scanned": 0,
    "servers_scanned": 0,
    "skipped": {"oversize": 0, "not_text": 0, "unparsed": 0, "unread": 0},
    "truncation_reasons": [],
    "findings": [],
}
SCANNED = replace(
    SNAPSHOT, secrets=SECRETS_COMPLETE, skills=SKILLS_COMPLETE, hooks=HOOKS_COMPLETE, plugins=PLUGINS_COMPLETE
)
KEYS = assessments.WorktreeKeys(SNAPSHOT.codebase_key, SNAPSHOT.worktree_key)

BLOCKED_PACKAGE = {
    "decision": "block",
    "ecosystem": "npm",
    "name": "minimist",
    "requestedVersion": "^1.2.0",
    "resolvedVersion": "1.2.8",
    "recommendedFixVersion": "1.2.9",
    "ruleId": "known-malicious",
    "relatedAdvisoryIds": ["GHSA-xvch-5gv4-984h"],
    "advisoryAliases": ["CVE-2021-44906"],
    "redactedCommand": "npm install minimist",
    "reasons": [
        {"advisoryId": "GHSA-xvch-5gv4-984h", "code": "advisory_match", "message": "m", "severity": "high"},
        {"code": "prototype_pollution", "message": "m", "severity": "critical"},
    ],
}
AUDIT = {
    "audit_status": "complete",
    "manifest_paths": ["package.json"],
    "lockfile_paths": ["package-lock.json"],
    "evaluation": {"packages": [BLOCKED_PACKAGE, {"decision": "allow", "ecosystem": "npm", "name": "react"}]},
}


@pytest.fixture(autouse=True)
def no_launched_runtimes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Runtime observation has its own tests; here the tools launch nothing.
    posture = {"status": "ok", "coverage": {"advisories_available": False}, "runtimes": [], "advisories": []}
    monkeypatch.setattr(runner, "observe_workspace_runtimes", lambda store, root: posture)
    monkeypatch.setattr(runtimes, "observe_workspace_runtimes", lambda store, root, *, home_dir=None: posture)


def queued_run(tmp_path: Path) -> tuple[GuardStore, assessments.ClaimedRun]:
    store = GuardStore(tmp_path / "home")
    assessments.admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=runner.DETECTOR_SET_DIGEST, now_ms=T0)
    claimed = assessments.claim_next(store, owner="test", now_ms=T0)
    assert claimed is not None
    return store, claimed


def snapshots(monkeypatch: pytest.MonkeyPatch, module, *values: native.WorkspaceSnapshot) -> list[str]:
    modes: list[str] = []
    remaining = list(values)

    def fake(
        root: Path,
        *,
        mode: str = "content",
        secrets: bool = False,
        secret_key: str | None = None,
        skills: bool = False,
        hooks: bool = False,
        plugins: bool = False,
    ) -> native.WorkspaceSnapshot:
        modes.append(mode)
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]

    monkeypatch.setattr(module, "workspace_snapshot", fake)
    return modes


def test_unchanged_snapshot_reports_projected_findings(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    modes = snapshots(monkeypatch, runner, SCANNED)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert modes == ["content", "content"]
    # Both detectors covered the whole snapshot, so the run is complete.
    assert outcome.state == "completed"
    assert outcome.snapshot_digest == SNAPSHOT.snapshot_digest
    assert outcome.coverage is not None and outcome.coverage["status"] == "complete"
    assert outcome.coverage["reasons"] == []
    assert outcome.coverage["detectors"] == {
        "supply_chain": "complete",
        "secrets": "complete",
        "runtime_identity_v1": "no_inputs",
        "skill_content_v1": "no_inputs",
        "mcp_config_v1": "no_inputs",
        "hook_config_v1": "no_inputs",
        "plugin_manifest_v1": "no_inputs",
    }
    [finding] = outcome.findings
    assert finding["severity"] == "critical"
    assert finding["package_version"] == "1.2.8"
    assert finding["fix_version"] == "1.2.9"
    assert finding["rule_ids"] == ["advisory_match", "known-malicious", "prototype_pollution"]
    assert finding["advisory_ids"] == ["CVE-2021-44906", "GHSA-xvch-5gv4-984h"]
    assert "npm install" not in repr(outcome.findings)
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)


@pytest.mark.parametrize("code", ["cloud_auth_error", "cloud_http_error", "cloud_timeout", "cloud_validation_error"])
def test_a_package_cloud_could_not_answer_is_a_coverage_gap_not_a_finding(
    tmp_path: Path, monkeypatch, code: str
) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SNAPSHOT)
    unanswered = {
        "decision": "ask",
        "ecosystem": "npm",
        "name": "left-pad",
        "resolvedVersion": "1.3.0",
        "reasons": [{"code": code, "message": "m", "severity": "high"}],
    }
    audit = {**AUDIT, "evaluation": {"packages": [BLOCKED_PACKAGE, unanswered]}}
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: audit)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert [finding["package_name"] for finding in outcome.findings] == ["minimist"]
    assert outcome.coverage is not None
    detectors, reasons = outcome.coverage["detectors"], outcome.coverage["reasons"]
    assert isinstance(detectors, dict) and detectors["supply_chain"] == "incomplete"
    assert isinstance(reasons, list) and "supply_chain_incomplete" in reasons


UNMATCHED = {
    "decision": "monitor",
    "ecosystem": "npm",
    "name": "lodash",
    "resolvedVersion": "4.17.20",
    "reasons": [{"code": "no_cached_match", "message": "m", "severity": "low", "source": "guard-local"}],
}


@pytest.mark.parametrize("extra", [[], ["unidentified_package"], ["lockfile_drift"]])
def test_packages_unchecked_without_an_advisory_bundle_are_a_coverage_gap(extra: list[str]) -> None:
    # Unconnected, nothing cached: the packages were never compared with any
    # intelligence, so the run must not read as a clean, complete check, even
    # when the evaluator also asked for review for another reason.
    package = {
        **UNMATCHED,
        "decision": "ask" if extra else "monitor",
        "reasons": [*UNMATCHED["reasons"], *({"code": code, "message": "m", "severity": "medium"} for code in extra)],
    }
    audit = {**AUDIT, "evaluation": {"bundle_version": None, "cache_status": "miss", "packages": [package]}}
    coverage = runner.coverage_summary(SCANNED, audit, findings_truncated=False)
    assert coverage["status"] == "partial"
    assert coverage["detectors"]["supply_chain"] == "incomplete"
    assert "advisory_data_unavailable" in coverage["reasons"]


def test_no_match_in_a_cached_bundle_is_a_clean_result() -> None:
    audit = {**AUDIT, "evaluation": {"bundle_version": "2026.10.25", "cache_status": "hit", "packages": [UNMATCHED]}}
    coverage = runner.coverage_summary(SCANNED, audit, findings_truncated=False)
    assert coverage["status"] == "complete"
    assert coverage["reasons"] == []


def test_change_during_detectors_supersedes_the_run(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SNAPSHOT, replace(SNAPSHOT, snapshot_digest=digest("content-2")))
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert (outcome.state, outcome.findings) == ("superseded", ())


def test_replaced_worktree_fails_without_running_detectors(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, replace(SNAPSHOT, worktree_key=digest("someone-else")))
    monkeypatch.setattr(runner, "_local_audit", pytest.fail)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert (outcome.state, outcome.error_code) == ("failed", "workspace_identity_changed")


def test_detector_failure_is_reported_without_details(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SNAPSHOT)

    def broken(store, config, root):
        raise RuntimeError(f"cannot read {root}/secret")

    monkeypatch.setattr(runner, "_local_audit", broken)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert (outcome.state, outcome.error_code) == ("failed", "supply_chain_detector_failed")
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)


def test_snapshot_failure_fails_the_run(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)

    def unavailable(
        root: Path,
        *,
        mode: str = "content",
        secrets: bool = False,
        secret_key: str | None = None,
        skills: bool = False,
        hooks: bool = False,
        plugins: bool = False,
    ):
        raise native.WorkspaceSnapshotError("workspace_snapshot_native_unavailable")

    monkeypatch.setattr(runner, "workspace_snapshot", unavailable)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert (outcome.state, outcome.error_code) == ("failed", "workspace_snapshot_native_unavailable")


def test_partial_snapshot_and_missing_lockfile_report_partial_coverage() -> None:
    partial = replace(SNAPSHOT, coverage="partial", partial_reasons=("entry_limit",))
    payload = {"audit_status": "incomplete", "manifest_paths": ["package.json"], "lockfile_warnings": ["x"]}
    coverage = runner.coverage_summary(partial, payload, findings_truncated=True)
    assert coverage["status"] == "partial"
    assert coverage["reasons"] == [
        "snapshot_entry_limit",
        "supply_chain_incomplete",
        "lockfile_warnings",
        "detector_not_run:secrets",
        "finding_cap",
    ]
    assert coverage["detectors"] == {"supply_chain": "incomplete", "secrets": "not_run"}


def test_workspace_without_manifests_reports_no_inputs() -> None:
    coverage = runner.coverage_summary(SNAPSHOT, {"audit_status": "incomplete"}, findings_truncated=False)
    assert coverage["reasons"] == ["detector_not_run:secrets"]
    assert coverage["detectors"]["supply_chain"] == "no_inputs"


def test_a_lockfile_without_packages_is_not_reported_as_no_inputs() -> None:
    payload = {"audit_status": "incomplete", "manifest_paths": [], "lockfile_paths": ["poetry.lock"]}
    coverage = runner.coverage_summary(SNAPSHOT, payload, findings_truncated=False)
    assert coverage["detectors"]["supply_chain"] == "incomplete"
    assert "supply_chain_incomplete" in coverage["reasons"]


def test_refused_offline_lookup_leaves_supply_chain_incomplete() -> None:
    coverage = runner.coverage_summary(SNAPSHOT, AUDIT, findings_truncated=False, egress_refused=1)
    assert coverage["detectors"]["supply_chain"] == "incomplete"
    assert coverage["reasons"] == ["supply_chain_incomplete", "detector_not_run:secrets"]


@pytest.mark.parametrize(("trigger", "offline"), [("file_change", True), ("manual", False)])
def test_only_automatic_runs_are_offline(tmp_path: Path, monkeypatch, trigger: str, offline: bool) -> None:
    store = GuardStore(tmp_path / "home")
    assessments.admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    assessments.enqueue(store, KEYS, trigger_kind=trigger, detector_set_digest=runner.DETECTOR_SET_DIGEST, now_ms=T0)
    claimed = assessments.claim_next(store, owner="test", now_ms=T0 + assessments.MAX_DEBOUNCE_WAIT_MS)
    assert claimed is not None
    snapshots(monkeypatch, runner, SNAPSHOT)
    seen: list[bool] = []

    def audit(store, config, root):
        seen.append(egress._OFFLINE.get() is not None)
        return AUDIT

    monkeypatch.setattr(runner, "_local_audit", audit)
    runner.execute(store, None, claimed, clock=lambda: T0)
    assert seen == [offline]


def test_unreadable_feed_cache_fails_the_run(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)

    def broken(store):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(runner, "feed_context_digest", broken)
    monkeypatch.setattr(runner, "workspace_snapshot", pytest.fail)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert (outcome.state, outcome.error_code) == ("failed", "feed_context_unavailable")


def test_finding_identity_is_stable_and_bounded() -> None:
    first, _ = runner.project_supply_chain_findings(KEYS.worktree_key, AUDIT)
    second, _ = runner.project_supply_chain_findings(KEYS.worktree_key, AUDIT)
    other, _ = runner.project_supply_chain_findings(digest("other"), AUDIT)
    assert first[0]["finding_id"] == second[0]["finding_id"] != other[0]["finding_id"]
    many = {
        "evaluation": {
            "packages": [
                {**BLOCKED_PACKAGE, "name": f"pkg-{index:04d}-{'x' * 200}", "relatedAdvisoryIds": ["A" * 256] * 8}
                for index in range(runner.MAX_FINDINGS + 10)
            ]
        }
    }
    findings, truncated = runner.project_supply_chain_findings(KEYS.worktree_key, many)
    assert truncated is True
    assert 0 < len(findings) <= runner.MAX_FINDINGS


def test_oversized_result_is_recorded_as_failure(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    huge = assessments.RunOutcome(
        state="completed",
        snapshot_digest=SNAPSHOT.snapshot_digest,
        findings=[{"package_name": "x" * 1024}] * 400,
    )
    monkeypatch.setattr(assessments, "claim_next", lambda store, owner, now_ms, **_: claimed)
    monkeypatch.setattr(runner, "execute", lambda store, config, run, **_: huge)
    assert runner.run_next(store, None, owner="test", clock=lambda: T0 + 1)
    run = assessments.get_run(store, claimed.run_id)
    assert run is not None and (run["state"], run["error_code"]) == ("failed", "assessment_result_too_large")


def test_feed_digest_follows_cached_bundles(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    empty = runner.feed_context_digest(store)
    with store._connect() as connection:
        columns = [row[1] for row in connection.execute("pragma table_info(guard_supply_chain_bundle_cache)")]
        values = {name: "x" for name in columns}
        values.update(workspace_id="w", payload_hash="p1", policy_hash="h1")
        placeholders = ", ".join("?" * len(values))
        connection.execute(
            f"insert into guard_supply_chain_bundle_cache ({', '.join(values)}) values ({placeholders})",
            tuple(values.values()),
        )
    changed = runner.feed_context_digest(store)
    assert empty != changed == runner.feed_context_digest(store)


def test_admission_queues_a_workspace_open_run(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat"))
    admitted = worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    assert admitted["worktree_key"] == KEYS.worktree_key
    [run] = assessments.recent_runs(store)
    assert (run["run_id"], run["trigger_kind"]) == (admitted["run_id"], "workspace_open")


@pytest.mark.parametrize(
    ("root", "code"),
    [("relative/path", "workspace_root_not_absolute"), ("/definitely/missing/root", "workspace_root_missing")],
)
def test_admission_rejects_unusable_roots(tmp_path: Path, root: str, code: str) -> None:
    with pytest.raises(worker.WorkspaceAdmissionError) as error:
        worker.admit_workspace(GuardStore(tmp_path / "home"), root)
    assert error.value.code == code


def test_observe_queues_on_file_change_only(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    stat = replace(SNAPSHOT, mode="stat", snapshot_digest=digest("stat-1"))
    snapshots(monkeypatch, worker, stat)
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    before = assessments.list_worktrees(store)[0]["dirty_generation"]
    assert worker.observe(store, clock=lambda: T0) == 0
    assert assessments.list_worktrees(store)[0]["dirty_generation"] == before
    snapshots(monkeypatch, worker, replace(stat, snapshot_digest=digest("stat-2")))
    worker.observe(store, clock=lambda: T0)
    assert assessments.list_worktrees(store)[0]["dirty_generation"] == before + 1


def test_losing_the_root_queues_one_run_and_then_stays_quiet(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat"))
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    before = assessments.list_worktrees(store)[0]["dirty_generation"]
    # The path now names another worktree: record that once, then stay quiet.
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat", worktree_key=digest("moved")))
    assert worker.observe(store, clock=lambda: T0) == 1
    assert worker.observe(store, clock=lambda: T0) == 0
    assert assessments.list_worktrees(store)[0]["dirty_generation"] == before + 1


class FakeHandler:
    def __init__(self, store: GuardStore) -> None:
        self.server = type("Server", (), {"store": store})()
        self.responses: list[tuple[int, dict[str, object]]] = []

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None:
        self.responses.append((status, payload))


def test_routes_admit_list_and_control_worktrees(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat"))
    handler = FakeHandler(store)
    assert api.handle_workspace_assessment_post(handler, api.ASSESSMENTS_PATH, {"root": str(tmp_path)})
    status, admitted = handler.responses[-1]
    assert status == 202
    keys = {"codebase_key": admitted["codebase_key"], "worktree_key": admitted["worktree_key"]}
    assert api.handle_workspace_assessment_get(handler, api.ASSESSMENTS_PATH)
    status, listing = handler.responses[-1]
    assert status == 200 and len(listing["worktrees"]) == 1 and len(listing["runs"]) == 1
    for action, expected in (("pause", 200), ("run", 404), ("resume", 200), ("run", 202)):
        api.handle_workspace_assessment_post(handler, f"{api.ASSESSMENTS_PATH}/{action}", keys)
        assert handler.responses[-1][0] == expected, action
    run_id = handler.responses[-1][1]["run_id"]
    api.handle_workspace_assessment_post(handler, f"{api.ASSESSMENTS_PATH}/cancel", {"run_id": run_id})
    assert handler.responses[-1] == (200, {"canceled": True})
    api.handle_workspace_assessment_post(handler, f"{api.ASSESSMENTS_PATH}/cancel", {"run_id": run_id})
    assert handler.responses[-1][0] == 409
    assert api.handle_workspace_assessment_get(handler, api.FINDINGS_PATH)
    assert handler.responses[-1][1]["assessments"] == []


@pytest.mark.parametrize(
    ("path", "payload", "error"),
    [
        (api.ASSESSMENTS_PATH, {"root": 7}, "invalid_root"),
        (api.ASSESSMENTS_PATH + "/cancel", {"run_id": ""}, "invalid_run_id"),
        (api.ASSESSMENTS_PATH + "/pause", {"codebase_key": "A" * 64, "worktree_key": "b" * 64}, "invalid_worktree"),
    ],
)
def test_routes_reject_malformed_requests(tmp_path: Path, path: str, payload: dict[str, object], error: str) -> None:
    handler = FakeHandler(GuardStore(tmp_path / "home"))
    assert api.handle_workspace_assessment_post(handler, path, payload)
    assert handler.responses == [(400, {"error": error})]


def test_routes_leave_other_paths_alone(tmp_path: Path) -> None:
    handler = FakeHandler(GuardStore(tmp_path / "home"))
    assert not api.handle_workspace_assessment_post(handler, api.ASSESSMENTS_PATH + "/delete", {})
    assert not api.handle_workspace_assessment_get(handler, "/v1/supply-chain/bundle")
    assert handler.responses == []


def test_native_reply_parsing_rejects_malformed_results() -> None:
    reply = {
        "schema": native.WORKSPACE_SNAPSHOT_SCHEMA,
        "mode": "content",
        "coverage": "partial",
        "root": "/work",
        "entry_count": 2,
        "worktree_key": digest("w"),
        "codebase_key": digest("c"),
        "snapshot_digest": digest("s"),
        "input_manifest_digest": digest("m"),
        "partial_reasons": ["unreadable"],
        "git": {"head_commit": "b" * 40},
    }
    parsed = native._parse_result(reply)
    assert (parsed.coverage, parsed.partial_reasons, parsed.head_commit) == ("partial", ("unreadable",), "b" * 40)
    for broken in ({**reply, "schema": "other"}, {**reply, "snapshot_digest": "short"}, {**reply, "mode": "x"}):
        with pytest.raises(native.WorkspaceSnapshotError):
            native._parse_result(broken)


def test_a_run_queued_before_an_upgrade_is_relabelled_when_it_is_claimed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    old = digest("old-detector-set")
    assessments.admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=old, now_ms=T0)
    claimed = assessments.claim_next(store, owner="test", now_ms=T0, detector_set_digest=runner.DETECTOR_SET_DIGEST)
    assert claimed is not None
    assert claimed.detector_set_digest == runner.DETECTOR_SET_DIGEST
    with store._connect() as connection:
        stored = connection.execute("select detector_set_digest from workspace_assessment_runs").fetchone()[0]
    assert stored == runner.DETECTOR_SET_DIGEST


def test_coalescing_into_a_queued_run_records_the_current_detector_set(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    assessments.admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    first = assessments.enqueue(
        store, KEYS, trigger_kind="workspace_open", detector_set_digest=digest("old"), now_ms=T0
    )
    second = assessments.enqueue(
        store, KEYS, trigger_kind="file_change", detector_set_digest=runner.DETECTOR_SET_DIGEST, now_ms=T0 + 1
    )
    assert first == second
    with store._connect() as connection:
        stored = connection.execute("select detector_set_digest from workspace_assessment_runs").fetchone()[0]
    assert stored == runner.DETECTOR_SET_DIGEST


def test_run_next_claims_with_the_running_detector_set(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    assessments.admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    assessments.enqueue(store, KEYS, trigger_kind="manual", detector_set_digest=digest("old"), now_ms=T0)
    seen: list[str] = []
    monkeypatch.setattr(
        runner,
        "execute",
        lambda store, config, run, **_: seen.append(run.detector_set_digest) or assessments.RunOutcome(state="failed"),
    )
    assert runner.run_next(store, None, owner="test", clock=lambda: T0)
    assert seen == [runner.DETECTOR_SET_DIGEST]


def test_automatic_runs_wait_while_the_host_is_busy(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(SNAPSHOT, mode="stat"))
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    ran: list[str] = []

    def fake_execute(_store, _config, run: assessments.ClaimedRun, **_) -> assessments.RunOutcome:
        ran.append(run.trigger_kind)
        return assessments.RunOutcome(state="failed", error_code="test")

    monkeypatch.setattr(runner, "execute", fake_execute)
    monkeypatch.setattr(worker, "host_resource_pressure", lambda: pressure.RESOURCE_PRESSURE)
    observed: list[bool] = []
    monkeypatch.setattr(worker, "observe", lambda _store: observed.append(True))
    assert worker.poll_once(store, owner="test") == 0
    # The workspace_open run stays queued and nothing was observed.
    assert ran == [] and observed == []
    assert [run["state"] for run in assessments.recent_runs(store)] == ["queued"]
    handler = FakeHandler(store)
    api.handle_workspace_assessment_get(handler, api.ASSESSMENTS_PATH)
    assert handler.responses[-1][1]["deferred_reason"] == "resource_pressure"
    # A run the user asked for still starts under pressure.
    keys = assessments.WorktreeKeys(KEYS.codebase_key, KEYS.worktree_key)
    worker.queue_manual_run(store, keys, clock=lambda: T0)
    assert worker.poll_once(store, owner="test") == 1 and ran == ["manual"]
    # Once the host is quiet the deferral clears and observation resumes.
    monkeypatch.setattr(worker, "host_resource_pressure", lambda: None)
    worker.poll_once(store, owner="test")
    assert observed == [True]
    api.handle_workspace_assessment_get(handler, api.ASSESSMENTS_PATH)
    assert handler.responses[-1][1]["deferred_reason"] is None


def test_each_claim_in_a_poll_rechecks_host_pressure(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(worker, "admit_registered_workspaces", lambda store, attempted=None: 0)
    monkeypatch.setattr(worker, "observe", lambda _store: 0)
    samples = iter([None, pressure.RESOURCE_PRESSURE])
    monkeypatch.setattr(worker, "host_resource_pressure", lambda: next(samples))
    claims: list[bool] = []

    def fake_run_next(_store, _config, *, owner: str, user_only: bool = False) -> bool:
        claims.append(user_only)
        return True

    monkeypatch.setattr(worker, "run_next", fake_run_next)
    monkeypatch.setattr(worker, "_MAX_RUNS_PER_POLL", 2)
    assert worker.poll_once(store, owner="test") == 2
    # The host got busy during the first run, so the second claim takes only user runs.
    assert claims == [False, True]
    assert pressure.deferral_reason(store) == pressure.RESOURCE_PRESSURE
    pressure.record_deferral(store, None)


def test_user_only_claim_leaves_automatic_runs_queued(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    assessments.admit_worktree(store, KEYS, root=str(tmp_path), now_ms=T0)
    assessments.enqueue(
        store, KEYS, trigger_kind="file_change", detector_set_digest=runner.DETECTOR_SET_DIGEST, now_ms=T0
    )
    due = T0 + assessments.MAX_DEBOUNCE_WAIT_MS
    assert assessments.claim_next(store, owner="test", now_ms=due, user_only=True) is None
    assert assessments.claim_next(store, owner="test", now_ms=due) is not None


@pytest.mark.parametrize(("load", "expected"), [((7.9, 0, 0), None), ((12.0, 0, 0), "resource_pressure")])
def test_host_pressure_follows_load_per_cpu(monkeypatch, load, expected) -> None:
    monkeypatch.setattr(pressure.os, "getloadavg", lambda: load)
    monkeypatch.setattr(pressure.os, "cpu_count", lambda: 8)
    assert pressure.host_resource_pressure() == expected


def test_host_without_load_average_reports_no_pressure(monkeypatch) -> None:
    def unavailable() -> tuple[float, float, float]:
        raise OSError("no load average")

    monkeypatch.setattr(pressure.os, "getloadavg", unavailable)
    assert pressure.host_resource_pressure() is None
