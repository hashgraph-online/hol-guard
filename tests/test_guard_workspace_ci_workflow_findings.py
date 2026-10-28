"""GitHub Actions workflow findings in background workspace assessments."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_workspace_snapshot as native
from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard import workspace_ci_workflow_findings as workflow_findings
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.runtime import workspace_assessment_sync as sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import (
    AUDIT,
    HOOKS_COMPLETE,
    PLUGINS_COMPLETE,
    SCANNED,
    SECRETS_COMPLETE,
    SKILLS_COMPLETE,
    SNAPSHOT,
    T0,
    WORKFLOWS_COMPLETE,
    queued_run,
)

FINDING_ID = "0123456789abcdef0123456789abcdef"
WORKFLOW_PATH = ".github/workflows/ci.yml"
PWN_REQUEST = """on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
"""
EMPTY_COVERAGE: dict[str, object] = {"status": "complete", "reasons": [], "detectors": {}}


def native_finding(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "finding_id": FINDING_ID,
        "rule_id": "ci.workflow.untrusted-checkout",
        "category": "execution",
        "severity": "high",
        "confidence": "likely",
        "title": "Privileged workflow checks out pull request code",
        "reason": "A privileged workflow checks out the pull request's own code.",
        "false_positive_hint": "Safe only when the checked-out code is read as data.",
        "path": WORKFLOW_PATH,
    }
    return {**base, **overrides}


def workflows_result(*findings: dict[str, object], **overrides: object) -> dict[str, object]:
    return {**WORKFLOWS_COMPLETE, "files_scanned": 1, "findings": list(findings), **overrides}


def run_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workflows: dict[str, object] | None):
    store, claimed = queued_run(tmp_path)
    scanned = replace(SCANNED, workflows=workflows)
    monkeypatch.setattr(runner, "workspace_snapshot", lambda root, **_: scanned)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    return store, claimed, runner.execute(store, None, claimed, clock=lambda: T0)


def test_detector_set_names_the_workflow_detector() -> None:
    assert "ci_workflow_v1" in runner.DETECTOR_SET


def test_a_risky_workflow_is_a_warning_with_its_path(tmp_path: Path, monkeypatch) -> None:
    pinned = native_finding(
        finding_id="f" * 32, rule_id="ci.workflow.unpinned-action", severity="medium", false_positive_hint=None
    )
    store, claimed, outcome = run_with(tmp_path, monkeypatch, workflows_result(native_finding(), pinned))
    assert outcome.state == "completed"
    assert outcome.coverage is not None
    assert outcome.coverage["detectors"]["ci_workflow_v1"] == "complete"
    assert outcome.coverage["ci_workflow"]["files_scanned"] == 1
    found = [item for item in outcome.findings if item["detector"] == "ci_workflow_v1"]
    assert sorted((item["rule_ids"][0], item["severity"]) for item in found) == [
        ("ci.workflow.unpinned-action", "medium"),
        ("ci.workflow.untrusted-checkout", "high"),
    ]
    for finding in found:
        assert (finding["source_kind"], finding["decision"], finding["path"]) == (
            "workspace_source",
            "warn",
            WORKFLOW_PATH,
        )
        assert finding["line"] is None
        assert all(finding[name] is None for name in ("ecosystem", "package_name", "package_version", "fix_version"))
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)


def test_workflow_findings_sync_without_path_or_rule_text(tmp_path: Path, monkeypatch) -> None:
    store, claimed, outcome = run_with(tmp_path, monkeypatch, workflows_result(native_finding()))
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)
    built = sync.build_workspace_assessment_sync(store, now="2026-01-01T00:00:00+00:00")
    assert built is not None
    text = json.dumps(built.payload)
    for private in (".github/workflows", "Privileged workflow", "checked-out code"):
        assert private not in text
    [entry] = built.payload["worktrees"]
    found = [item for item in entry["findings"] if item["detector"] == "ci_workflow_v1"]
    assert [(item["sourceKind"], item["decision"], item["ruleIds"]) for item in found] == [
        ("workspace_source", "warn", ["ci.workflow.untrusted-checkout"])
    ]


def test_a_worktree_without_workflows_has_no_inputs(tmp_path: Path, monkeypatch) -> None:
    _, _, outcome = run_with(tmp_path, monkeypatch, WORKFLOWS_COMPLETE)
    assert outcome.state == "completed"
    assert outcome.coverage is not None
    assert outcome.coverage["detectors"]["ci_workflow_v1"] == "no_inputs"


def test_older_runtime_keeps_earlier_scans_and_reports_workflows_not_run(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    requested: list[tuple[bool, bool, bool]] = []

    def snapshot(root: Path, *, secrets: bool = False, plugins: bool = False, workflows: bool = False, **_):
        requested.append((secrets, plugins, workflows))
        if workflows:
            raise native.WorkspaceSnapshotError("workspace_snapshot_workflows_unavailable")
        if secrets:
            return replace(
                SNAPSHOT,
                secrets=SECRETS_COMPLETE,
                skills=SKILLS_COMPLETE,
                hooks=HOOKS_COMPLETE,
                plugins=PLUGINS_COMPLETE,
            )
        return SNAPSHOT

    monkeypatch.setattr(runner, "workspace_snapshot", snapshot)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    # Detector snapshot with workflows, again without them, then the plain recheck.
    assert requested == [(True, True, True), (True, True, False), (False, False, False)]
    assert outcome.state == "partial"
    assert outcome.coverage is not None
    assert outcome.coverage["reasons"] == [
        "detector_not_run:ci_workflow_v1",
        "detector_not_run:editor_task_v1",
        "detector_not_run:instruction_file_v1",
    ]
    assert outcome.coverage["detectors"]["plugin_manifest_v1"] == "no_inputs"
    assert outcome.coverage["detectors"]["ci_workflow_v1"] == "not_run"


def test_a_runtime_missing_an_earlier_scan_still_runs_the_workflow_scan(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    requested: list[tuple[bool, bool, bool]] = []

    def snapshot(root: Path, *, secrets: bool = False, plugins: bool = False, workflows: bool = False, **_):
        requested.append((secrets, plugins, workflows))
        if plugins:
            raise native.WorkspaceSnapshotError("workspace_snapshot_plugins_unavailable")
        if workflows:
            return replace(
                SNAPSHOT,
                secrets=SECRETS_COMPLETE,
                skills=SKILLS_COMPLETE,
                hooks=HOOKS_COMPLETE,
                workflows=workflows_result(),
            )
        return SNAPSHOT

    monkeypatch.setattr(runner, "workspace_snapshot", snapshot)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert requested[:2] == [(True, True, True), (True, False, True)]
    assert outcome.coverage is not None
    assert outcome.coverage["detectors"]["ci_workflow_v1"] == "complete"
    assert outcome.coverage["detectors"]["plugin_manifest_v1"] == "not_run"


def test_a_runtime_without_the_workflow_scan_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    features = (
        native.WORKSPACE_SNAPSHOT_FEATURE,
        native.WORKSPACE_SECRETS_FEATURE,
        native.WORKSPACE_SKILLS_FEATURE,
        native.WORKSPACE_HOOKS_FEATURE,
        native.WORKSPACE_PLUGINS_FEATURE,
    )
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/runtime/hol-guard-runtime")),
        capabilities=SimpleNamespace(features=features),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    with pytest.raises(native.WorkspaceSnapshotError) as raised:
        native._native_request({}, needs_plugins=True, needs_workflows=True)
    assert raised.value.code == "workspace_snapshot_workflows_unavailable"


@pytest.mark.parametrize(
    "reason",
    [
        "workflow_oversize",
        "workflow_not_text",
        "workflow_unread",
        "workflow_linked",
        "path_too_long",
        "snapshot_entry_limit",
    ],
)
def test_a_workflow_the_scan_could_not_read_leaves_the_run_partial(tmp_path: Path, monkeypatch, reason: str) -> None:
    result = workflows_result(status="incomplete", truncation_reasons=[reason])
    _, _, outcome = run_with(tmp_path, monkeypatch, result)
    assert outcome.state == "partial"
    assert outcome.coverage is not None
    assert outcome.coverage["reasons"] == ["ci_workflow_incomplete"]
    assert outcome.coverage["detectors"]["ci_workflow_v1"] == "incomplete"
    assert outcome.coverage["ci_workflow"]["truncation_reasons"] == [reason]


def test_a_workflow_scan_at_its_cap_marks_findings_truncated() -> None:
    coverage = workflow_findings.with_ci_workflow_coverage(
        EMPTY_COVERAGE, workflows_result(native_finding(), status="incomplete", truncation_reasons=["max_findings"])
    )
    assert coverage["reasons"] == ["ci_workflow_incomplete", "finding_cap"]


@pytest.mark.parametrize(
    "payload",
    [
        {"schema": "other"},
        {**WORKFLOWS_COMPLETE, "schema": "guard.workspace-plugins.v1"},
        {**WORKFLOWS_COMPLETE, "status": "weird"},
        {**WORKFLOWS_COMPLETE, "status": []},
        {},
        {key: value for key, value in WORKFLOWS_COMPLETE.items() if key != "findings"},
        {**WORKFLOWS_COMPLETE, "findings": None},
        {**WORKFLOWS_COMPLETE, "findings": {"0": {}}},
        {key: value for key, value in WORKFLOWS_COMPLETE.items() if key != "files_scanned"},
        {**WORKFLOWS_COMPLETE, "files_scanned": True},
        {**WORKFLOWS_COMPLETE, "files_scanned": -1},
        {key: value for key, value in WORKFLOWS_COMPLETE.items() if key != "skipped"},
        {key: value for key, value in WORKFLOWS_COMPLETE.items() if key != "truncation_reasons"},
        {"schema": WORKFLOWS_COMPLETE["schema"], "status": "complete", "findings": []},
    ],
)
def test_an_unreadable_workflow_result_is_an_error(payload: dict[str, object]) -> None:
    coverage = workflow_findings.with_ci_workflow_coverage(EMPTY_COVERAGE, payload)
    assert (coverage["status"], coverage["reasons"]) == ("partial", ["ci_workflow_incomplete"])
    assert coverage["detectors"]["ci_workflow_v1"] == "error"


@pytest.mark.parametrize(
    "bad",
    [
        {"finding_id": "short"},
        {"rule_id": "hook.config.remote-code"},
        {"rule_id": "ci.workflow.has space"},
        {"rule_id": "ci.workflow.unexpected"},
        {"path": ".github/workflows/" + "w" * 4080 + ".yml"},
        {"rule_id": None},
        {"rule_id": ["ci.workflow.untrusted-checkout"]},
        {"path": "ci.yml"},
        {"path": ".github/workflows/nested/ci.yml"},
        {"path": ".github/workflows/ci.json"},
        {"path": ".github/actions/setup/action.yml"},
        {"path": "/.github/workflows/ci.yml"},
        {"path": ".github\\workflows\\ci.yml"},
        {"path": None},
        {"category": "Execution!"},
        {"severity": "unknown"},
        {"severity": ["high"]},
        {"confidence": "high"},
        {"confidence": {"level": "high"}},
        {"title": ""},
        {"title": "line one\nline two"},
        {"reason": "r" * 2000},
        {"false_positive_hint": "\x1b[31m"},
    ],
)
def test_a_malformed_finding_is_dropped_and_leaves_the_scan_incomplete(bad: dict[str, object]) -> None:
    result = workflows_result(native_finding(**bad))
    assert workflow_findings.project_ci_workflow_findings(result) == []
    coverage = workflow_findings.with_ci_workflow_coverage(EMPTY_COVERAGE, result)
    assert coverage["detectors"]["ci_workflow_v1"] == "incomplete"
    assert coverage["ci_workflow"]["truncation_reasons"] == ["invalid_finding"]


def test_every_workflow_name_the_native_scan_reads_is_accepted() -> None:
    paths = [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yaml",
        ".github/workflows/.yml",
        ".github/workflows/" + "w" * 251 + ".yml",
    ]
    result = workflows_result(
        *(native_finding(finding_id=f"{index:032x}", path=path) for index, path in enumerate(paths))
    )
    assert [item["path"] for item in workflow_findings.project_ci_workflow_findings(result)] == paths
    coverage = workflow_findings.with_ci_workflow_coverage(EMPTY_COVERAGE, result)
    assert coverage["detectors"]["ci_workflow_v1"] == "complete"


@pytest.fixture
def native_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    if not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file():
        pytest.skip("needs HOL_GUARD_NATIVE_BINARY for the compiled runtime")
    empty_audit = {"audit_status": "complete", "manifest_paths": [], "lockfile_paths": [], "evaluation": {}}
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: empty_audit)


def test_compiled_runtime_reports_a_risky_workflow_without_quoting_it(tmp_path: Path, native_binary: None) -> None:
    workspace = tmp_path / "workspace"
    workflows = workspace / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(PWN_REQUEST, encoding="utf-8")
    store = GuardStore(tmp_path / "guard-home")
    admitted = worker.admit_workspace(store, str(workspace))
    keys = assessments.WorktreeKeys(str(admitted["codebase_key"]), str(admitted["worktree_key"]))
    assert worker.queue_manual_run(store, keys) == admitted["run_id"]
    assert runner.run_next(store, load_guard_config(store.guard_home), owner="test")
    [latest] = assessments.latest_assessed_runs(store)
    assert latest["coverage"]["detectors"]["ci_workflow_v1"] == "complete"
    assert latest["coverage"]["ci_workflow"]["files_scanned"] == 1
    found = [item for item in latest["findings"] if item["detector"] == "ci_workflow_v1"]
    assert sorted(item["rule_ids"][0] for item in found) == [
        "ci.workflow.unpinned-action",
        "ci.workflow.untrusted-checkout",
        "ci.workflow.write-all-permissions",
    ]
    assert {item["path"] for item in found} == {WORKFLOW_PATH}
    stored = json.dumps(latest)
    for quoted in ("actions/checkout", "head.sha", "npm ci", "@v4"):
        assert quoted not in stored
