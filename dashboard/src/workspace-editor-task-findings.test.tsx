import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";
import { WorktreeRow } from "./workspace-findings-workspace";

const ids = { codebase_key: "c".repeat(64), worktree_key: "w".repeat(64) };
const editorFinding = {
  source_kind: "workspace_source",
  detector: "editor_task_v1",
  rule_ids: ["editor.task.folder-open"],
  path: ".vscode/tasks.json",
  title: "t",
  reason: "r",
};

function stateWith(findings: Record<string, unknown>[], coverage: Record<string, unknown>) {
  return normalizeWorkspaceFindingsState(
    { worktrees: [], runs: [{ ...ids, run_id: "run-editor", state: "completed", trigger_kind: "manual" }] },
    {
      worktrees: [{ ...ids, root: "/Users/dev/app", stale: false, paused: false }],
      assessments: [{ ...ids, run_id: "run-editor", state: "completed", coverage, findings }],
    },
  );
}

function render(state: ReturnType<typeof stateWith>) {
  const [worktree] = state.worktrees;
  const [run] = state.runs;
  return renderToStaticMarkup(
    createElement(WorktreeRow, { worktree, newestRun: run, assessment: state.assessments[0], busyKey: null, onAction: () => {} }),
  );
}

const state = stateWith(
  [
    {
      ...editorFinding,
      finding_id: "folder-open",
      severity: "high",
      decision: "warn",
      confidence: "likely",
      title: "Editor task runs when the folder is opened",
      reason: "A VS Code task in this project is set to run when the folder is opened.",
      false_positive_hint: "Expected when the maintainers start a watcher this way.",
    },
    {
      ...editorFinding,
      finding_id: "initialize",
      severity: "medium",
      decision: "warn",
      rule_ids: ["devcontainer.initialize-command"],
      path: ".devcontainer/devcontainer.json",
      confidence: "likely",
      title: "Dev container runs a command on the host",
      reason: "The dev container's initializeCommand runs on this machine before the container starts.",
    },
    { ...editorFinding, finding_id: "no-path", path: undefined },
    { ...editorFinding, finding_id: "no-reason", reason: undefined },
    { ...editorFinding, finding_id: "no-rule", rule_ids: [] },
  ],
  { status: "complete", reasons: [], detectors: { supply_chain: "complete", editor_task_v1: "complete" } },
);
const findings = state.assessments[0].findings;
assert.equal(findings.length, 2, "an editor task finding without its path, wording or rule is dropped");
const [folderOpen, initialize] = findings;
assert.deepEqual(
  [folderOpen.kind, folderOpen.path, folderOpen.editorTask?.falsePositiveHint, folderOpen.workflow, folderOpen.packageName],
  ["editor_task", ".vscode/tasks.json", "Expected when the maintainers start a watcher this way.", null, null],
  "an editor task finding carries its file and the editor task check",
);
assert.deepEqual([initialize.kind, initialize.ruleIds], ["editor_task", ["devcontainer.initialize-command"]]);

const markup = render(state);
assert.ok(markup.includes("Editor tasks and dev containers that run commands on their own"), "editor task findings get their own table");
assert.ok(markup.includes(".vscode/tasks.json") && markup.includes(".devcontainer/devcontainer.json"));
assert.ok(markup.includes("Editor task runs when the folder is opened") && markup.includes("Dev container runs a command on the host"));
assert.ok(markup.includes("Expected when the maintainers start a watcher this way."), "the false positive hint is shown");
assert.ok(!markup.includes("GitHub Actions workflows with risky settings"), "editor task findings are not shown as workflows");
assert.ok(!markup.includes("No dependency or secret findings"), "a run with only editor task findings is not shown as clean");
assert.ok(!markup.includes("Prepare fix"), "an editor task finding is a warning with no fix");

const gapMarkup = render(
  stateWith([], {
    status: "partial",
    reasons: ["editor_task_incomplete", "detector_not_run:editor_task_v1"],
    detectors: { supply_chain: "complete", editor_task_v1: "not_run" },
  }),
);
assert.ok(gapMarkup.includes("Some editor task or dev container files could not be fully read"), "an incomplete scan is named");
assert.ok(gapMarkup.includes("Editor task checking is not part of this check yet."), "a scan that did not run is named");
